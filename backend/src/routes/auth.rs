use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{security::{password::verify_password, session::{hash_session_token, new_session_token}}, state::AppState};

const COOKIE_NAME: &str = "amnezia_panel_session";
const LOGIN_FAILURE_WINDOW_SECONDS: i64 = 5 * 60;
const LOGIN_FAILURE_LIMIT: i64 = 8;
const LOGIN_LOCK_SECONDS: i64 = 60;

fn login_throttle_key(username: &str) -> String {
    let normalized = username.trim().to_ascii_lowercase();
    hash_session_token(&format!("login:{normalized}"))
}

async fn login_is_locked(
    pool: &sqlx::SqlitePool,
    username_hash: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let blocked_until: Option<i64> = sqlx::query_scalar(
        "SELECT blocked_until FROM auth_login_attempts WHERE username_hash = ?"
    ).bind(username_hash).fetch_optional(pool).await?.flatten();
    Ok(blocked_until.is_some_and(|until| until > now))
}

/// Atomically records one failed login. The counter is reset after its rolling
/// window; once the threshold is reached, subsequent attempts wait 60 seconds.
async fn record_failed_login(
    pool: &sqlx::SqlitePool,
    username_hash: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let window_cutoff = now - LOGIN_FAILURE_WINDOW_SECONDS;
    let blocked_until = now + LOGIN_LOCK_SECONDS;
    let locked_until: Option<i64> = sqlx::query_scalar(
        "INSERT INTO auth_login_attempts (username_hash, window_started_at, failure_count, blocked_until)
         VALUES (?, ?, 1, NULL)
         ON CONFLICT(username_hash) DO UPDATE SET
            failure_count = CASE
                WHEN auth_login_attempts.window_started_at <= ? THEN 1
                ELSE auth_login_attempts.failure_count + 1
            END,
            window_started_at = CASE
                WHEN auth_login_attempts.window_started_at <= ? THEN excluded.window_started_at
                ELSE auth_login_attempts.window_started_at
            END,
            blocked_until = CASE
                WHEN (
                    CASE
                        WHEN auth_login_attempts.window_started_at <= ? THEN 1
                        ELSE auth_login_attempts.failure_count + 1
                    END
                ) >= ? THEN ? ELSE NULL
            END
         RETURNING blocked_until"
    )
    .bind(username_hash)
    .bind(now)
    .bind(window_cutoff)
    .bind(window_cutoff)
    .bind(window_cutoff)
    .bind(LOGIN_FAILURE_LIMIT)
    .bind(blocked_until)
    .fetch_one(pool)
    .await?;
    Ok(locked_until.is_some_and(|until| until > now))
}

async fn clear_login_throttle(
    pool: &sqlx::SqlitePool,
    username_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM auth_login_attempts WHERE username_hash = ?")
        .bind(username_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn authenticated_admin(
    state: &AppState,
    jar: &CookieJar,
) -> Result<(i64, String), StatusCode> {
    let token = jar.get(COOKIE_NAME).map(|cookie| cookie.value())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token_hash = hash_session_token(token);
    let now = Utc::now().to_rfc3339();
    let row = sqlx::query(
        "SELECT admins.id, admins.username FROM sessions JOIN admins ON admins.id = sessions.admin_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    let admin_id: i64 = row.try_get("id").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username: String = row.try_get("username").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((admin_id, username))
}


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
    let username = input.username.trim();
    let throttle_key = login_throttle_key(username);
    let now = Utc::now().timestamp();
    if login_is_locked(&state.pool, &throttle_key, now).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let row = sqlx::query("SELECT id, username, password_hash FROM admins WHERE id = 1 AND username = ?")
        .bind(username).fetch_optional(&state.pool).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(row) = row else {
        let locked = record_failed_login(&state.pool, &throttle_key, now).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(if locked { StatusCode::TOO_MANY_REQUESTS } else { StatusCode::UNAUTHORIZED });
    };

    let admin_id: i64 = row.try_get("id").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username: String = row.try_get("username").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let password_hash: String = row.try_get("password_hash").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !verify_password(&input.password, &password_hash) {
        let locked = record_failed_login(&state.pool, &throttle_key, now).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(if locked { StatusCode::TOO_MANY_REQUESTS } else { StatusCode::UNAUTHORIZED });
    }

    clear_login_throttle(&state.pool, &throttle_key).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = new_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (Utc::now() + Duration::days(7)).to_rfc3339();
    sqlx::query("INSERT INTO sessions (id, admin_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(admin_id).bind(token_hash).bind(expires_at)
        .execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie = Cookie::build((COOKIE_NAME, token))
        .http_only(true).secure(state.cookie_secure).same_site(SameSite::Strict).path("/").build();
    Ok((jar.add(cookie), Json(AuthResponse { authenticated: true, username: Some(username) })))
}

#[cfg(test)]
mod login_throttle_tests {
    use super::{
        clear_login_throttle, login_is_locked, login_throttle_key, record_failed_login,
    };
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE auth_login_attempts (
                username_hash TEXT PRIMARY KEY NOT NULL,
                window_started_at INTEGER NOT NULL,
                failure_count INTEGER NOT NULL,
                blocked_until INTEGER
            )"
        ).execute(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn locks_after_eight_failures_and_automatically_expires() {
        let pool = test_pool().await;
        let key = login_throttle_key("Admin");
        for attempt in 1..8 {
            assert!(!record_failed_login(&pool, &key, 1_000).await.unwrap(), "attempt {attempt}");
        }
        assert!(record_failed_login(&pool, &key, 1_000).await.unwrap());
        assert!(login_is_locked(&pool, &key, 1_059).await.unwrap());
        assert!(!login_is_locked(&pool, &key, 1_060).await.unwrap());

        // A failed login immediately after the cooldown is subject to the same
        // rolling window and starts another short cooldown.
        assert!(record_failed_login(&pool, &key, 1_060).await.unwrap());
        assert!(login_is_locked(&pool, &key, 1_119).await.unwrap());
        assert!(!login_is_locked(&pool, &key, 1_120).await.unwrap());

        // Once the rolling window expires, the next bad attempt starts at one.
        assert!(!record_failed_login(&pool, &key, 1_301).await.unwrap());
        let failures: i64 = sqlx::query_scalar(
            "SELECT failure_count FROM auth_login_attempts WHERE username_hash = ?"
        ).bind(&key).fetch_one(&pool).await.unwrap();
        assert_eq!(failures, 1);
    }

    #[tokio::test]
    async fn login_keys_are_case_normalized_and_success_clears_throttle_state() {
        let pool = test_pool().await;
        let first = login_throttle_key("Admin");
        let second = login_throttle_key("  admin  ");
        assert_eq!(first, second);
        assert!(!record_failed_login(&pool, &first, 10).await.unwrap());
        clear_login_throttle(&pool, &first).await.unwrap();
        assert!(!login_is_locked(&pool, &first, 10).await.unwrap());
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM auth_login_attempts WHERE username_hash = ?"
        ).bind(&first).fetch_one(&pool).await.unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn independent_usernames_do_not_share_throttle_counters() {
        let pool = test_pool().await;
        let admin = login_throttle_key("admin");
        let other = login_throttle_key("another-user");
        for _ in 0..8 {
            let _ = record_failed_login(&pool, &admin, 50).await.unwrap();
        }
        assert!(login_is_locked(&pool, &admin, 50).await.unwrap());
        assert!(!login_is_locked(&pool, &other, 50).await.unwrap());
    }
}

pub async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<AuthResponse>, StatusCode> {
    let (_, username) = authenticated_admin(&state, &jar).await?;
    Ok(Json(AuthResponse {
        authenticated: true,
        username: Some(username),
    }))
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
    let removal = Cookie::build((COOKIE_NAME, "")).path("/").http_only(true).secure(state.cookie_secure).same_site(SameSite::Strict).build();
    Ok((jar.remove(removal), Json(AuthResponse { authenticated: false, username: None })))
}
