mod state;
mod routes;
mod security;
mod runtime;

use std::{env, net::SocketAddr, path::Path, str::FromStr, sync::Arc};
use zeroize::Zeroizing;
use axum::{routing::get, Router};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::{cors::{Any, CorsLayer}, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use crate::{
    routes::{auth, clients, configs, containers, interfaces, runtime as runtime_routes, setup, system},
    runtime::{DockerRuntime, HostRuntime, PreviewRuntime, RuntimeAdapter},
    state::AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data/amnezia-panel.db".into());
    if let Some(path) = database_url.strip_prefix("sqlite://") {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(5).connect_with(options).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let runtime: Arc<dyn RuntimeAdapter> = match env::var("RUNTIME_MODE").as_deref() {
        Ok("docker") => Arc::new(DockerRuntime::new()),
        Ok("host") => Arc::new(HostRuntime::new()),
        Ok("preview") | Err(_) => Arc::new(PreviewRuntime),
        Ok(other) => return Err(format!("Unsupported RUNTIME_MODE '{other}'. Use 'preview', 'host' or 'docker'.").into()),
    };

    let wireguard_master_key = match env::var("WIREGUARD_MASTER_KEY") {
        Ok(value) => {
            // Keep the environment-value copy, decoded bytes, and long-lived key in zeroizing containers.
            let value = Zeroizing::new(value);
            let decoded = Zeroizing::new(hex::decode(value.trim())?);
            let key: [u8; 32] = decoded.as_slice().try_into()
                .map_err(|_| "WIREGUARD_MASTER_KEY must be exactly 64 hexadecimal characters")?;
            Some(Arc::new(Zeroizing::new(key)))
        }
        Err(_) => None,
    };

    let state = AppState {
        pool,
        cookie_secure: env::var("COOKIE_SECURE").map(|v| v == "true").unwrap_or(false),
        runtime,
        wireguard_master_key,
    };

    let app = Router::new()
        .route("/api/health", get(system::health))
        .route("/api/setup/status", get(setup::status))
        .route("/api/setup/initialize", axum::routing::post(setup::initialize))
        .route("/api/auth/login", axum::routing::post(auth::login))
        .route("/api/auth/logout", axum::routing::post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        .route("/api/runtime/status", get(runtime_routes::status))
        .route("/api/containers", get(containers::list).post(containers::create))
        .route("/api/containers/{container_id}/awg-profile", axum::routing::put(containers::update_awg_profile))
        .route("/api/containers/{container_id}/wireguard-server-key", axum::routing::post(containers::provision_wireguard_server_key))
        .route("/api/containers/{container_id}/awg-header-protection-key", axum::routing::post(containers::provision_awg_header_protection_key))
        .route("/api/containers/{container_id}/clients", axum::routing::post(clients::create))
        .route("/api/containers/{container_id}/server-config", get(configs::server_config))
        .route("/api/containers/{container_id}/start", axum::routing::post(interfaces::start))
        .route("/api/containers/{container_id}/stop", axum::routing::post(interfaces::stop))
        .route("/api/clients", get(clients::list))
        .route("/api/clients/{client_id}/disable", axum::routing::post(clients::disable))
        .route("/api/clients/{client_id}/config", get(configs::client_config))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(CorsLayer::new().allow_origin([
            "http://127.0.0.1:5173".parse::<axum::http::HeaderValue>().unwrap(),
            "http://localhost:5173".parse::<axum::http::HeaderValue>().unwrap(),
        ]).allow_credentials(true).allow_methods(Any).allow_headers(Any))
        .layer(TraceLayer::new_for_http());

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env::var("PORT").unwrap_or_else(|_| "4000".into()).parse()?;
    let address: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!("Amnezia Panel Rust API listening on http://{address}");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
