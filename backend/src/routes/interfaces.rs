use axum::{extract::{Path, State}, http::StatusCode, Json};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

use crate::{
    routes::configs::build_server_config,
    runtime::{interface_name_for_profile, RuntimeStatus},
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
    admin_id: &str,
    action: &'static str,
    details: serde_json::Value,
) -> Result<(), (StatusCode, &'static str)> {
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, ?, ?)")
        .bind(admin_id)
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

    let row = sqlx::query("SELECT protocol, status FROM protocol_containers WHERE id = ?")
        .bind(&container_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let current_status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    if current_status == "running" || current_status == "starting" || current_status == "stopping" {
        return Err((StatusCode::CONFLICT, "VPN profile is already active or changing state"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }

    let draft = build_server_config(&state, &container_id).await?;
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    let claimed = sqlx::query(
        "UPDATE protocol_containers SET status = 'starting' WHERE id = ? AND status = ?"
    )
    .bind(&container_id)
    .bind(&current_status)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim VPN profile start"))?;
    if claimed.rows_affected() != 1 {
        return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
    }

    if let Err(message) = state.runtime.start_interface(&protocol, &interface_name, draft.config).await {
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error' WHERE id = ? AND status = 'starting'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.start_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'running' WHERE id = ? AND status = 'starting'")
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

    let row = sqlx::query("SELECT protocol, status, revision FROM protocol_containers WHERE id = ?")
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
    if current_status != "running" && current_status != "error" {
        return Err((StatusCode::CONFLICT, "VPN profile is not marked as running or requiring cleanup"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    let claimed = sqlx::query(
        "UPDATE protocol_containers SET status = 'stopping' WHERE id = ? AND status = ?"
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
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error' WHERE id = ? AND status = 'stopping'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.stop_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'stopped' WHERE id = ? AND status = 'stopping'")
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
