mod state;
mod routes;
mod security;

use std::{env, net::SocketAddr, path::Path};
use axum::{routing::get, Router};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::{cors::{Any, CorsLayer}, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use crate::{routes::{auth, setup, system}, state::AppState};

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

    let options = SqliteConnectOptions::from_str(&database_url)
        .map_err(|e| format!("Invalid DATABASE_URL: {e}"))?
        .create_if_missing(true)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState {
        pool,
        cookie_secure: env::var("COOKIE_SECURE").map(|v| v == "true").unwrap_or(false),
    };

    let app = Router::new()
        .route("/api/health", get(system::health))
        .route("/api/setup/status", get(setup::status))
        .route("/api/setup/initialize", axum::routing::post(setup::initialize))
        .route("/api/auth/login", axum::routing::post(auth::login))
        .route("/api/auth/logout", axum::routing::post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(CorsLayer::new().allow_origin([
            "http://127.0.0.1:5173".parse().unwrap(),
            "http://localhost:5173".parse().unwrap(),
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
