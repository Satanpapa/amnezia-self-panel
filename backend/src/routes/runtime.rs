use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::CookieJar;

use crate::{runtime::RuntimeStatus, state::AppState};
use super::auth::authenticated_admin;

pub async fn status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<RuntimeStatus>, StatusCode> {
    authenticated_admin(&state, &jar).await?;
    Ok(Json(state.runtime.status()))
}
