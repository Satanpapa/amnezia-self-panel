use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    ok: bool,
    service: &'static str,
    version: &'static str,
    runtime: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "amnezia-panel-api",
        version: env!("CARGO_PKG_VERSION"),
        runtime: "rust",
    })
}
