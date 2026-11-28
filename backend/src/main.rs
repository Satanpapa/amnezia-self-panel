mod state;
mod routes;
mod security;
mod runtime;

#[cfg(test)]
mod migration_tests;

use std::{env, net::SocketAddr, path::Path, str::FromStr, sync::Arc, time::Duration};
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
    let recovered_operations = runtime::recover_interrupted_operations(&pool).await?;
    if recovered_operations > 0 {
        tracing::warn!(
            recovered_operations,
            "Recovered interrupted VPN runtime operation(s); affected profiles require explicit cleanup"
        );
    }

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
    reconcile_running_host_interfaces(&state).await?;

    // Expired peers are revoked without requiring an administrator browser session.
    // The reaper runs only in explicitly enabled Linux host-runtime mode.
    let expiry_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let revoked = interfaces::reap_expired_peers_once(&expiry_state).await;
            if revoked > 0 {
                tracing::info!(revoked, "Automatically revoked expired WireGuard/AmneziaWG client(s)");
            }
        }
    });

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
        .route("/api/containers/{container_id}/peer-stats", get(interfaces::peer_stats))
        .route("/api/clients", get(clients::list))
        .route("/api/clients/{client_id}/disable", axum::routing::post(clients::disable))
        .route("/api/clients/{client_id}/subscription-token", axum::routing::post(clients::rotate_subscription_token))
        .route("/api/clients/{client_id}/preshared-key", axum::routing::post(clients::provision_client_preshared_key))
        .route("/api/clients/{client_id}/preshared-key/rotate", axum::routing::post(clients::rotate_client_preshared_key))
        .route("/api/clients/{client_id}/config", get(configs::client_config))
        .route("/api/subscriptions/config", get(configs::subscription_config))
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

/// Compare persisted "running" profiles with actual Linux interface state at startup.
async fn reconcile_running_host_interfaces(
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    if state.runtime.status().await.mode != "host" {
        return Ok(());
    }

    let rows = sqlx::query(
        "SELECT id, protocol FROM protocol_containers WHERE status = 'running' AND runtime_operation IS NULL"
    )
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let profile_id: String = sqlx::Row::try_get(&row, "id")?;
        let protocol: String = sqlx::Row::try_get(&row, "protocol")?;
        let interface_name = match runtime::interface_name_for_profile(&protocol, &profile_id) {
            Ok(name) => name,
            Err(_) => continue,
        };
        match state.runtime.interface_is_up(&protocol, &interface_name).await {
            Ok(true) => {}
            Ok(false) => {
                let changed = sqlx::query(
                    "UPDATE protocol_containers SET status = 'error' WHERE id = ? AND status = 'running' AND runtime_operation IS NULL"
                )
                .bind(&profile_id)
                .execute(&state.pool)
                .await?;
                if changed.rows_affected() == 1 {
                    tracing::warn!(
                        container_id = %profile_id,
                        interface_name = %interface_name,
                        "Persisted VPN status was running, but the Linux interface is absent; profile marked for recovery"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    container_id = %profile_id,
                    interface_name = %interface_name,
                    error,
                    "Could not verify Linux interface state during startup; persisted status was left unchanged"
                );
            }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
#[cfg(test)]
mod startup_reconciliation_tests {
    use std::{collections::HashSet, sync::Arc};

    use async_trait::async_trait;
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{
        runtime::{interface_name_for_profile, PeerRuntimeStat, RuntimeAdapter, RuntimeStatus},
        state::AppState,
    };

    struct FakeHostRuntime {
        existing_interfaces: HashSet<String>,
    }

    #[async_trait]
    impl RuntimeAdapter for FakeHostRuntime {
        async fn status(&self) -> RuntimeStatus {
            RuntimeStatus {
                mode: "host",
                available: true,
                engine: "linux-host",
                message: "test runtime".into(),
                can_manage_vpn: false,
            }
        }

        async fn interface_is_up(
            &self,
            _protocol: &str,
            interface_name: &str,
        ) -> Result<bool, &'static str> {
            Ok(self.existing_interfaces.contains(interface_name))
        }

        async fn peer_stats(
            &self,
            _protocol: &str,
            _interface_name: &str,
        ) -> Result<Vec<PeerRuntimeStat>, &'static str> {
            Ok(Vec::new())
        }
    }

    async fn state_with_profiles() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE protocol_containers (id TEXT PRIMARY KEY, protocol TEXT NOT NULL, status TEXT NOT NULL, runtime_operation TEXT)"
        ).execute(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO protocol_containers (id, protocol, status, runtime_operation) VALUES
             ('abcdef1234', 'wireguard', 'running', NULL),
             ('123456789a', 'amnezia-awg', 'running', NULL),
             ('9876543210', 'wireguard', 'stopped', NULL),
             ('abcdefabcd', 'openvpn', 'running', NULL)"
        ).execute(&pool).await.unwrap();

        let still_up = interface_name_for_profile("wireguard", "abcdef1234").unwrap();
        let runtime = FakeHostRuntime {
            existing_interfaces: HashSet::from([still_up]),
        };

        AppState {
            pool,
            cookie_secure: false,
            runtime: Arc::new(runtime),
            wireguard_master_key: None,
        }
    }

    #[tokio::test]
    async fn marks_missing_linux_interfaces_as_error_but_preserves_existing_and_unmanaged_profiles() {
        let state = state_with_profiles().await;
        super::reconcile_running_host_interfaces(&state).await.unwrap();

        let statuses = sqlx::query_as::<_, (String, String)>(
            "SELECT id, status FROM protocol_containers ORDER BY id"
        ).fetch_all(&state.pool).await.unwrap();
        let status_by_id: std::collections::HashMap<_, _> = statuses.into_iter().collect();

        assert_eq!(status_by_id["abcdef1234"], "running");
        assert_eq!(status_by_id["123456789a"], "error");
        assert_eq!(status_by_id["9876543210"], "stopped");
        // Unsupported protocols are intentionally left for their own runtime adapter.
        assert_eq!(status_by_id["abcdefabcd"], "running");
    }

    #[tokio::test]
    async fn does_not_reconcile_profiles_in_preview_mode() {
        let state = state_with_profiles().await;
        let runtime = crate::runtime::PreviewRuntime;
        let state = AppState {
            pool: state.pool.clone(),
            cookie_secure: state.cookie_secure,
            runtime: Arc::new(runtime),
            wireguard_master_key: None,
        };
        super::reconcile_running_host_interfaces(&state).await.unwrap();
        let status: String = sqlx::query_scalar(
            "SELECT status FROM protocol_containers WHERE id = '123456789a'"
        ).fetch_one(&state.pool).await.unwrap();
        assert_eq!(status, "running");
    }
}
