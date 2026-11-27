use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::{security::{password::hash_password, session::{hash_session_token, new_session_token}}, state::AppState};

#[derive(Serialize)]
pub struct SetupStatus {
    setup_required: bool,
}

#[derive(Deserialize)]
pub struct InitializeRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct InitializeResponse {
    ok: bool,
    username: String,
}

pub async fn status(State(state): State<AppState>) -> Result<Json<SetupStatus>, StatusCode> {
    let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM admins WHERE id = 1) AS configured")
        .fetch_one(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let configured: i64 = row.try_get("configured").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(SetupStatus { setup_required: configured == 0 }))
}

pub async fn initialize(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<InitializeRequest>,
) -> Result<(CookieJar, Json<InitializeResponse>), (StatusCode, &'static str)> {
    let username = input.username.trim();
    if !(3..=32).contains(&username.len()) || !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err((StatusCode::BAD_REQUEST, "Username must be 3-32 characters: a-z, A-Z, 0-9, _ or -"));
    }
    if input.password.chars().count() < 12 || input.password.len() > 256 {
        return Err((StatusCode::BAD_REQUEST, "Password must be 12-256 characters"));
    }

    let password_hash = hash_password(&input.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not hash password"))?;
    let mut tx = state.pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let insert = sqlx::query("INSERT INTO admins (id, username, password_hash) VALUES (1, ?, ?)")
        .bind(username).bind(password_hash).execute(&mut *tx).await;
    if insert.is_err() {
        let _ = tx.rollback().await;
        return Err((StatusCode::CONFLICT, "Initial administrator has already been created"));
    }

    let token = new_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (Utc::now() + Duration::days(7)).to_rfc3339();
    sqlx::query("INSERT INTO sessions (id, admin_id, token_hash, expires_at) VALUES (?, 1, ?, ?)")
        .bind(Uuid::new_v4().to_string()).bind(token_hash).bind(expires_at)
        .execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not create session"))?;
    tx.commit().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not save administrator"))?;

    let cookie = Cookie::build(("amnezia_panel_session", token))
        .http_only().secure(state.cookie_secure).same_site(SameSite::Strict).path("/").build();
    let jar = jar.add(cookie);
    Ok((jar, Json(InitializeResponse { ok: true, username: username.to_string() })))
}

use uuid::Uuid;
