use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{security::{password::verify_password, session::{hash_session_token, new_session_token}}, state::AppState};

const COOKIE_NAME: &str = "amnezia_panel_session";

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    authenticated: bool,
    username: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<LoginRequest>,
) -> Result<(CookieJar, Json<AuthResponse>), StatusCode> {
    let row = sqlx::query("SELECT id, username, password_hash FROM admins WHERE id = 1 AND username = ?")
        .bind(input.username.trim()).fetch_optional(&state.pool).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let admin_id: i64 = row.try_get("id").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username: String = row.try_get("username").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let password_hash: String = row.try_get("password_hash").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !verify_password(&input.password, &password_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = new_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (Utc::now() + Duration::days(7)).to_rfc3339();
    sqlx::query("INSERT INTO sessions (id, admin_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(admin_id).bind(token_hash).bind(expires_at)
        .execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie = Cookie::build((COOKIE_NAME, token))
        .http_only().secure(state.cookie_secure).same_site(SameSite::Strict).path("/").build();
    Ok((jar.add(cookie), Json(AuthResponse { authenticated: true, username: Some(username) })))
}

pub async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<AuthResponse>, StatusCode> {
    let token = jar.get(COOKIE_NAME).map(|cookie| cookie.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token_hash = hash_session_token(token);
    let now = Utc::now().to_rfc3339();
    let row = sqlx::query(
        "SELECT admins.username FROM sessions JOIN admins ON admins.id = sessions.admin_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
    ).bind(token_hash).bind(now).fetch_optional(&state.pool).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let username: String = row.try_get("username").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AuthResponse { authenticated: true, username: Some(username) }))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<AuthResponse>), StatusCode> {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        let token_hash = hash_session_token(cookie.value());
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash).execute(&state.pool).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    let removal = Cookie::build((COOKIE_NAME, "")).path("/").http_only().secure(state.cookie_secure).same_site(SameSite::Strict).build();
    Ok((jar.remove(removal), Json(AuthResponse { authenticated: false, username: None })))
}
