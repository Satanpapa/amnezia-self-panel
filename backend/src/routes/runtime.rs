use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use axum_extra::extract::cookie::CookieJar;

use crate::{runtime::RuntimeStatus, state::AppState};

#[derive(Serialize)]
pub struct RuntimeStatusResponse {
    #[serde(flatten)]
    runtime: RuntimeStatus,
    wireguard_master_key_configured: bool,
}
use super::auth::authenticated_admin;

pub async fn status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<RuntimeStatus>, StatusCode> {
    authenticated_admin(&state, &jar).await?;
    Ok(Json(RuntimeStatusResponse {
        runtime: state.runtime.status().await,
        wireguard_master_key_configured: state.wireguard_master_key.is_some(),
    }))
}
