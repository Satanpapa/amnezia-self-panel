use std::{collections::HashSet, net::Ipv4Addr, str::FromStr};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    security::session::{hash_session_token, new_session_token},
    state::AppState,
};
use super::auth::authenticated_admin;

#[derive(Debug, Serialize, FromRow)]
pub struct ClientRecord {
    pub id: String,
    pub container_id: String,
    pub name: String,
    pub note: String,
    pub assigned_ip: String,
    pub enabled: bool,
    pub traffic_limit_bytes: i64,
    pub traffic_used_bytes: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateClientRequest {
    name: String,
    note: Option<String>,
    traffic_limit_bytes: Option<i64>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
pub struct ListClientsQuery {
    container_id: Option<String>,
}

#[derive(Serialize)]
pub struct ClientList {
    items: Vec<ClientRecord>,
}

#[derive(Serialize)]
pub struct CreateClientResponse {
    item: ClientRecord,
    subscription_token: String,
    notice: &'static str,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ListClientsQuery>,
) -> Result<Json<ClientList>, StatusCode> {
    authenticated_admin(&state, &jar).await?;
    let items = if let Some(container_id) = query.container_id {
        sqlx::query_as::<_, ClientRecord>(
            "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at FROM clients WHERE container_id = ? ORDER BY created_at DESC"
        ).bind(container_id).fetch_all(&state.pool).await
    } else {
        sqlx::query_as::<_, ClientRecord>(
            "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at FROM clients ORDER BY created_at DESC"
        ).fetch_all(&state.pool).await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ClientList { items }))
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
    Json(input): Json<CreateClientRequest>,
) -> Result<Json<CreateClientResponse>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let name = input.name.trim();
    if !(1..=48).contains(&name.len()) {
        return Err((StatusCode::BAD_REQUEST, "Client name must be 1-48 characters"));
    }
    let note = input.note.unwrap_or_default();
    if note.len() > 200 {
        return Err((StatusCode::BAD_REQUEST, "Note must be at most 200 characters"));
    }
    let traffic_limit = input.traffic_limit_bytes.unwrap_or(0);
    if traffic_limit < 0 {
        return Err((StatusCode::BAD_REQUEST, "Traffic limit cannot be negative"));
    }
    if let Some(expires_at) = &input.expires_at {
        if chrono::DateTime::parse_from_rfc3339(expires_at).is_err() {
            return Err((StatusCode::BAD_REQUEST, "Expiration must be an RFC3339 timestamp"));
        }
    }

    let row = sqlx::query("SELECT subnet FROM protocol_containers WHERE id = ?")
        .bind(&container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "Container not found"))?;
    let subnet_text: String = sqlx::Row::try_get(&row, "subnet")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let subnet = Ipv4Net::from_str(&subnet_text)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored subnet is invalid"))?;

    let used_rows = sqlx::query("SELECT assigned_ip FROM clients WHERE container_id = ?")
        .bind(&container_id).fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let mut used = HashSet::new();
    for row in used_rows {
        let address: String = sqlx::Row::try_get(&row, "assigned_ip")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        if let Ok(ip) = Ipv4Addr::from_str(&address) {
            used.insert(ip);
        }
    }
    let assigned_ip = subnet.hosts().find(|address| !used.contains(address))
        .ok_or((StatusCode::CONFLICT, "No free IP addresses remain in this subnet"))?;

    let id = Uuid::new_v4().to_string();
    let subscription_token = new_session_token();
    let token_hash = hash_session_token(&subscription_token);
    sqlx::query(
        "INSERT INTO clients (id, container_id, name, note, assigned_ip, enabled, subscription_token_hash, traffic_limit_bytes, expires_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)"
    )
    .bind(&id).bind(&container_id).bind(name).bind(note.trim())
    .bind(assigned_ip.to_string()).bind(token_hash).bind(traffic_limit)
    .bind(input.expires_at).execute(&state.pool).await
    .map_err(|error| {
        tracing::error!("Failed to create client: {error}");
        (StatusCode::INTERNAL_SERVER_ERROR, "Could not save client")
    })?;

    let item = sqlx::query_as::<_, ClientRecord>(
        "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at FROM clients WHERE id = ?"
    ).bind(&id).fetch_one(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read saved client"))?;

    let details = serde_json::json!({"client_id": id, "container_id": container_id, "assigned_ip": assigned_ip.to_string()}).to_string();
    let _ = sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.created', ?)")
        .bind(admin_id).bind(details).execute(&state.pool).await;

    Ok(Json(CreateClientResponse {
        item,
        subscription_token,
        notice: "Token is shown once. VPN keys and a working subscription endpoint will be added in a later step.",
    }))
}

pub async fn disable(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let result = sqlx::query("UPDATE clients SET enabled = 0 WHERE id = ?")
        .bind(&client_id).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Client not found"));
    }
    let details = serde_json::json!({"client_id": client_id}).to_string();
    let _ = sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.disabled', ?)")
        .bind(admin_id).bind(details).execute(&state.pool).await;
    Ok(StatusCode::NO_CONTENT)
}
