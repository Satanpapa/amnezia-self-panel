use axum::{
    extract::{Path, State},
    http::{header::CACHE_CONTROL, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::{
    routes::configs::build_server_config,
    runtime::{interface_name_for_profile, PeerRuntimeStat, RuntimeStatus},
    state::AppState,
};

use super::auth::authenticated_admin;

#[derive(Serialize)]
pub struct InterfaceOperationResponse {
    container_id: String,
    interface_name: String,
    status: &'static str,
    runtime: &'static str,
    revision: i64,
    peer_count: usize,
}

async fn audit(
    state: &AppState,
    admin_id: &i64,
    action: &'static str,
    details: serde_json::Value,
) -> Result<(), (StatusCode, &'static str)> {
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, ?, ?)")
        .bind(*admin_id)
        .bind(action)
        .bind(details.to_string())
        .execute(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not write runtime audit event"))?;
    Ok(())
}

fn ensure_host_runtime(status: &RuntimeStatus) -> Result<(), (StatusCode, &'static str)> {
    if status.mode != "host" || !status.can_manage_vpn {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Host interface management is unavailable. Use RUNTIME_MODE=host and explicitly enable HOST_RUNTIME_ALLOW_MUTATIONS=true",
        ));
    }
    Ok(())
}

/// Activate the real Linux interface using the persisted server profile and active client peers.
/// The generated configuration is stored in the host's protected runtime directory.
pub async fn start(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
) -> Result<Json<InterfaceOperationResponse>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let runtime_status = state.runtime.status().await;
    ensure_host_runtime(&runtime_status)?;

    let row = sqlx::query("SELECT protocol, status, runtime_operation FROM protocol_containers WHERE id = ?")
        .bind(&container_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let current_status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    let runtime_operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if current_status == "running" || current_status == "starting" || runtime_operation.is_some() {
        return Err((StatusCode::CONFLICT, "VPN profile is already active or an operation is in progress"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }

    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    // Claim the profile before building its peer snapshot. Client mutations use
    // the same runtime_operation lock and therefore cannot race interface start.
    let claimed = sqlx::query(
        "UPDATE protocol_containers SET runtime_operation = 'start' WHERE id = ? AND status = ? AND runtime_operation IS NULL"
    )
    .bind(&container_id)
    .bind(&current_status)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim VPN profile start"))?;
    if claimed.rows_affected() != 1 {
        return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
    }

    let draft = match build_server_config(&state, &container_id).await {
        Ok(draft) => draft,
        Err(error) => {
            let _ = sqlx::query("UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
                .bind(&container_id).execute(&state.pool).await;
            return Err(error);
        }
    };

    if let Err(message) = state.runtime.start_interface(&protocol, &interface_name, draft.config).await {
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.start_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'running', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
        .bind(&container_id).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Interface started but database status update failed"))?;
    if updated.rows_affected() != 1 {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Interface started but profile status requires reconciliation"));
    }

    let details = serde_json::json!({
        "container_id": container_id,
        "interface_name": interface_name,
        "revision": draft.revision,
        "peer_count": draft.peer_count,
        "runtime": "linux-host"
    });
    audit(&state, &admin_id, "runtime.interface.started", details).await?;

    Ok(Json(InterfaceOperationResponse {
        container_id,
        interface_name,
        status: "running",
        runtime: "linux-host",
        revision: draft.revision,
        peer_count: draft.peer_count,
    }))
}

/// Stop an interface previously managed by this panel.
pub async fn stop(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
) -> Result<Json<InterfaceOperationResponse>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let runtime_status = state.runtime.status().await;
    ensure_host_runtime(&runtime_status)?;

    let row = sqlx::query("SELECT protocol, status, revision, runtime_operation FROM protocol_containers WHERE id = ?")
        .bind(&container_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let current_status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    let revision: i64 = sqlx::Row::try_get(&row, "revision")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid profile revision"))?;
    let runtime_operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if runtime_operation.is_some() {
        return Err((StatusCode::CONFLICT, "Another VPN runtime operation is already in progress"));
    }
    if current_status != "running" && current_status != "error" {
        return Err((StatusCode::CONFLICT, "VPN profile is not marked as running or requiring cleanup"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    let claimed = sqlx::query(
        "UPDATE protocol_containers SET runtime_operation = 'stop' WHERE id = ? AND status = ? AND runtime_operation IS NULL"
    )
    .bind(&container_id)
    .bind(&current_status)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim VPN profile stop"))?;
    if claimed.rows_affected() != 1 {
        return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
    }

    if let Err(message) = state.runtime.stop_interface(&protocol, &interface_name).await {
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'stop'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.stop_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'stopped', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'stop'")
        .bind(&container_id).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Interface stopped but database status update failed"))?;
    if updated.rows_affected() != 1 {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Interface stopped but profile status requires reconciliation"));
    }

    let details = serde_json::json!({
        "container_id": container_id,
        "interface_name": interface_name,
        "revision": revision,
        "runtime": "linux-host"
    });
    audit(&state, &admin_id, "runtime.interface.stopped", details).await?;

    Ok(Json(InterfaceOperationResponse {
        container_id,
        interface_name,
        status: "stopped",
        runtime: "linux-host",
        revision,
        peer_count: 0,
    }))
}


#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn runtime_operation_migration_provides_an_exclusive_start_stop_lock() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE protocol_containers (id TEXT PRIMARY KEY, status TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!("../../migrations/0008_runtime_operation_lock.sql"))
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO protocol_containers (id, status) VALUES ('profile-a', 'preview')")
            .execute(&pool).await.unwrap();

        let start = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'start' WHERE id = 'profile-a' AND runtime_operation IS NULL"
        ).execute(&pool).await.unwrap();
        assert_eq!(start.rows_affected(), 1);

        let competing_stop = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'stop' WHERE id = 'profile-a' AND runtime_operation IS NULL"
        ).execute(&pool).await.unwrap();
        assert_eq!(competing_stop.rows_affected(), 0);

        let invalid_operation = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'delete' WHERE id = 'profile-a'"
        ).execute(&pool).await.unwrap_err();
        assert!(invalid_operation.to_string().contains("CHECK constraint failed"));

        let release = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = 'profile-a' AND runtime_operation = 'start'"
        ).execute(&pool).await.unwrap();
        assert_eq!(release.rows_affected(), 1);
    }
}


#[derive(Serialize)]
pub struct PeerStatsItem {
    client_id: String,
    name: String,
    assigned_ip: String,
    enabled: bool,
    expired: bool,
    active_on_server: bool,
    latest_handshake_unix: Option<u64>,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
}

#[derive(Serialize)]
pub struct PeerStatsResponse {
    container_id: String,
    interface_name: String,
    peer_count: usize,
    unmatched_peer_count: usize,
    items: Vec<PeerStatsItem>,
}

fn client_is_expired(expires_at: Option<&str>) -> Result<bool, StatusCode> {
    let Some(value) = expires_at else { return Ok(false) };
    let expiry = DateTime::parse_from_rfc3339(value)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(expiry.with_timezone(&Utc) <= Utc::now())
}

/// Read live peer handshake and traffic counters without exposing endpoint or preshared-key data.
pub async fn peer_stats(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;

    let row = sqlx::query(
        "SELECT protocol, status, runtime_operation FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    let operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if status != "running" || operation.is_some() {
        return Err((StatusCode::CONFLICT, "VPN interface must be running and idle to read live peer statistics"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Peer statistics are available only for WireGuard and AmneziaWG"));
    }
    let runtime_status = state.runtime.status().await;
    if runtime_status.mode != "host" {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Live peer statistics require RUNTIME_MODE=host"));
    }
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;
    let stats = state.runtime.peer_stats(&protocol, &interface_name).await
        .map_err(|message| (StatusCode::BAD_GATEWAY, message))?;
    let by_key: HashMap<String, PeerRuntimeStat> = stats.into_iter()
        .map(|item| (item.public_key.clone(), item))
        .collect();

    let rows = sqlx::query(
        "SELECT id, name, assigned_ip, enabled, expires_at, wireguard_public_key FROM clients WHERE container_id = ? ORDER BY created_at ASC"
    ).bind(&container_id).fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read VPN clients"))?;
    let mut items = Vec::with_capacity(rows.len());
    let mut tracked_count = 0usize;
    for row in rows {
        let id: String = sqlx::Row::try_get(&row, "id")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client id"))?;
        let name: String = sqlx::Row::try_get(&row, "name")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client name"))?;
        let assigned_ip: String = sqlx::Row::try_get(&row, "assigned_ip")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client IP"))?;
        let enabled: bool = sqlx::Row::try_get(&row, "enabled")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client enabled state"))?;
        let expires_at: Option<String> = sqlx::Row::try_get(&row, "expires_at")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client expiry"))?;
        let expired = client_is_expired(expires_at.as_deref())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "A client has an invalid expiry timestamp"))?;
        let public_key: Option<String> = sqlx::Row::try_get(&row, "wireguard_public_key")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client public key"))?;
        let live = public_key.as_ref().and_then(|key| by_key.get(key));
        if live.is_some() {
            tracked_count += 1;
        }
        items.push(PeerStatsItem {
            client_id: id,
            name,
            assigned_ip,
            enabled,
            expired,
            active_on_server: live.is_some(),
            latest_handshake_unix: live.and_then(|peer| peer.latest_handshake_unix),
            rx_bytes: live.map(|peer| peer.rx_bytes),
            tx_bytes: live.map(|peer| peer.tx_bytes),
        });
    }

    let mut response = Json(PeerStatsResponse {
        container_id,
        interface_name,
        peer_count: tracked_count,
        unmatched_peer_count: by_key.len().saturating_sub(tracked_count),
        items,
    }).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    Ok(response)
}
