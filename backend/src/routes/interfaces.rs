use axum::{
    extract::{Path, State},
    http::{header::CACHE_CONTROL, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::{
    routes::configs::build_server_config,
    runtime::{interface_name_for_profile, PeerRuntimeStat, RuntimeStatus},
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
    admin_id: &i64,
    action: &'static str,
    details: serde_json::Value,
) -> Result<(), (StatusCode, &'static str)> {
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, ?, ?)")
        .bind(*admin_id)
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

    let row = sqlx::query("SELECT protocol, status, runtime_operation FROM protocol_containers WHERE id = ?")
        .bind(&container_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let current_status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    let runtime_operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if current_status == "running" || current_status == "starting" || runtime_operation.is_some() {
        return Err((StatusCode::CONFLICT, "VPN profile is already active or an operation is in progress"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }

    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    // Claim the profile before building its peer snapshot. Client mutations use
    // the same runtime_operation lock and therefore cannot race interface start.
    let claimed = sqlx::query(
        "UPDATE protocol_containers SET runtime_operation = 'start' WHERE id = ? AND status = ? AND runtime_operation IS NULL"
    )
    .bind(&container_id)
    .bind(&current_status)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim VPN profile start"))?;
    if claimed.rows_affected() != 1 {
        return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
    }

    let draft = match build_server_config(&state, &container_id).await {
        Ok(draft) => draft,
        Err(error) => {
            let _ = sqlx::query("UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
                .bind(&container_id).execute(&state.pool).await;
            return Err(error);
        }
    };

    if let Err(message) = state.runtime.start_interface(&protocol, &interface_name, draft.config).await {
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.start_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'running', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'start'")
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

    let row = sqlx::query("SELECT protocol, status, revision, runtime_operation FROM protocol_containers WHERE id = ?")
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
    let runtime_operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if runtime_operation.is_some() {
        return Err((StatusCode::CONFLICT, "Another VPN runtime operation is already in progress"));
    }
    if current_status != "running" && current_status != "error" {
        return Err((StatusCode::CONFLICT, "VPN profile is not marked as running or requiring cleanup"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Host runtime currently supports only WireGuard and AmneziaWG"));
    }
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;

    let claimed = sqlx::query(
        "UPDATE protocol_containers SET runtime_operation = 'stop' WHERE id = ? AND status = ? AND runtime_operation IS NULL"
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
        let _ = sqlx::query("UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'stop'")
            .bind(&container_id).execute(&state.pool).await;
        let details = serde_json::json!({
            "container_id": container_id,
            "interface_name": interface_name,
            "error": message
        });
        let _ = audit(&state, &admin_id, "runtime.interface.stop_failed", details).await;
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let updated = sqlx::query("UPDATE protocol_containers SET status = 'stopped', runtime_operation = NULL WHERE id = ? AND runtime_operation = 'stop'")
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


#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn runtime_operation_migration_provides_an_exclusive_start_stop_lock() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE protocol_containers (id TEXT PRIMARY KEY, status TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!("../../migrations/0008_runtime_operation_lock.sql"))
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO protocol_containers (id, status) VALUES ('profile-a', 'preview')")
            .execute(&pool).await.unwrap();

        let start = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'start' WHERE id = 'profile-a' AND runtime_operation IS NULL"
        ).execute(&pool).await.unwrap();
        assert_eq!(start.rows_affected(), 1);

        let competing_stop = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'stop' WHERE id = 'profile-a' AND runtime_operation IS NULL"
        ).execute(&pool).await.unwrap();
        assert_eq!(competing_stop.rows_affected(), 0);

        let invalid_operation = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'delete' WHERE id = 'profile-a'"
        ).execute(&pool).await.unwrap_err();
        assert!(invalid_operation.to_string().contains("CHECK constraint failed"));

        let release = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = 'profile-a' AND runtime_operation = 'start'"
        ).execute(&pool).await.unwrap();
        assert_eq!(release.rows_affected(), 1);
    }
}


#[derive(Serialize)]
pub struct PeerStatsItem {
    client_id: String,
    name: String,
    assigned_ip: String,
    enabled: bool,
    expired: bool,
    active_on_server: bool,
    latest_handshake_unix: Option<u64>,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
    traffic_used_bytes: i64,
    traffic_limit_bytes: i64,
}

#[derive(Serialize)]
pub struct PeerStatsResponse {
    container_id: String,
    interface_name: String,
    peer_count: usize,
    unmatched_peer_count: usize,
    items: Vec<PeerStatsItem>,
}

fn client_is_expired(expires_at: Option<&str>) -> Result<bool, StatusCode> {
    let Some(value) = expires_at else { return Ok(false) };
    let expiry = DateTime::parse_from_rfc3339(value)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(expiry.with_timezone(&Utc) <= Utc::now())
}

/// Read live peer handshake and traffic counters without exposing endpoint or preshared-key data.
pub async fn peer_stats(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;

    let row = sqlx::query(
        "SELECT protocol, status, runtime_operation FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol profile"))?;
    let status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid protocol status"))?;
    let operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid runtime operation state"))?;
    if status != "running" || operation.is_some() {
        return Err((StatusCode::CONFLICT, "VPN interface must be running and idle to read live peer statistics"));
    }
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Peer statistics are available only for WireGuard and AmneziaWG"));
    }
    let runtime_status = state.runtime.status().await;
    if runtime_status.mode != "host" {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Live peer statistics require RUNTIME_MODE=host"));
    }
    let interface_name = interface_name_for_profile(&protocol, &container_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?;
    let stats = state.runtime.peer_stats(&protocol, &interface_name).await
        .map_err(|message| (StatusCode::BAD_GATEWAY, message))?;
    let by_key: HashMap<String, PeerRuntimeStat> = stats.into_iter()
        .map(|item| (item.public_key.clone(), item))
        .collect();

    let rows = sqlx::query(
        "SELECT id, name, assigned_ip, enabled, expires_at, wireguard_public_key, traffic_used_bytes, traffic_limit_bytes FROM clients WHERE container_id = ? ORDER BY created_at ASC"
    ).bind(&container_id).fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read VPN clients"))?;
    let mut items = Vec::with_capacity(rows.len());
    let mut tracked_count = 0usize;
    for row in rows {
        let id: String = sqlx::Row::try_get(&row, "id")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client id"))?;
        let name: String = sqlx::Row::try_get(&row, "name")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client name"))?;
        let assigned_ip: String = sqlx::Row::try_get(&row, "assigned_ip")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client IP"))?;
        let enabled: bool = sqlx::Row::try_get(&row, "enabled")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client enabled state"))?;
        let expires_at: Option<String> = sqlx::Row::try_get(&row, "expires_at")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client expiry"))?;
        let expired = client_is_expired(expires_at.as_deref())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "A client has an invalid expiry timestamp"))?;
        let public_key: Option<String> = sqlx::Row::try_get(&row, "wireguard_public_key")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client public key"))?;
        let traffic_used_bytes: i64 = sqlx::Row::try_get(&row, "traffic_used_bytes")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client traffic usage"))?;
        let traffic_limit_bytes: i64 = sqlx::Row::try_get(&row, "traffic_limit_bytes")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client traffic limit"))?;
        let live = public_key.as_ref().and_then(|key| by_key.get(key));
        if live.is_some() {
            tracked_count += 1;
        }
        items.push(PeerStatsItem {
            client_id: id,
            name,
            assigned_ip,
            enabled,
            expired,
            active_on_server: live.is_some(),
            latest_handshake_unix: live.and_then(|peer| peer.latest_handshake_unix),
            rx_bytes: live.map(|peer| peer.rx_bytes),
            tx_bytes: live.map(|peer| peer.tx_bytes),
            traffic_used_bytes,
            traffic_limit_bytes,
        });
    }

    let mut response = Json(PeerStatsResponse {
        container_id,
        interface_name,
        peer_count: tracked_count,
        unmatched_peer_count: by_key.len().saturating_sub(tracked_count),
        items,
    }).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    Ok(response)
}

/// Revoke peers whose access deadline has passed on a running Linux host interface.
/// This is independent of the browser UI and runs from the backend scheduler.
pub async fn reap_expired_peers_once(state: &AppState) -> usize {
    let runtime_status = state.runtime.status().await;
    if runtime_status.mode != "host" || !runtime_status.can_manage_vpn {
        return 0;
    }

    let rows = match sqlx::query(
        "SELECT id, protocol FROM protocol_containers WHERE status = 'running' AND runtime_operation IS NULL AND protocol IN ('wireguard', 'amnezia-awg') ORDER BY created_at ASC"
    ).fetch_all(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("Could not list running profiles for expiry cleanup: {error}");
            return 0;
        }
    };

    let mut total_revoked = 0usize;
    for row in rows {
        let profile_id: String = match sqlx::Row::try_get(&row, "id") {
            Ok(id) => id,
            Err(error) => {
                tracing::error!("Invalid profile id in expiry cleanup query: {error}");
                continue;
            }
        };
        let protocol: String = match sqlx::Row::try_get(&row, "protocol") {
            Ok(protocol) => protocol,
            Err(error) => {
                tracing::error!(container_id = %profile_id, "Invalid protocol in expiry cleanup query: {error}");
                continue;
            }
        };
        let interface_name = match interface_name_for_profile(&protocol, &profile_id) {
            Ok(name) => name,
            Err(error) => {
                tracing::warn!(container_id = %profile_id, error, "Could not derive interface name for expiry cleanup");
                continue;
            }
        };

        // Reuse the profile-operation lock to serialize expiry cleanup with start,
        // stop, AWG edits, and client changes. While the profile remains running,
        // UI renders this lock as SYNCING rather than STARTING.
        let claimed = match sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'start' WHERE id = ? AND status = 'running' AND runtime_operation IS NULL"
        ).bind(&profile_id).execute(&state.pool).await {
            Ok(result) => result.rows_affected() == 1,
            Err(error) => {
                tracing::error!(container_id = %profile_id, "Could not claim expiry cleanup lock: {error}");
                false
            }
        };
        if !claimed {
            continue;
        }

        match reap_profile_expired_peers(state, &profile_id, &protocol, &interface_name).await {
            Ok(revoked) => total_revoked += revoked,
            Err(error) => {
                let _ = sqlx::query(
                    "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'start'"
                ).bind(&profile_id).execute(&state.pool).await;
                tracing::error!(
                    container_id = %profile_id,
                    interface_name = %interface_name,
                    error,
                    "Automatic expired-peer cleanup failed; expired client records were not marked revoked"
                );
            }
        }
    }
    total_revoked
}

fn bounded_counter(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn traffic_counter_delta(previous: i64, current: u64) -> u64 {
    let current = bounded_counter(current);
    let previous = previous.max(0);
    if current >= previous {
        (current - previous) as u64
    } else {
        // A lower runtime counter indicates that the interface or peer was
        // recreated. Count the new counter from zero instead of underflowing.
        current as u64
    }
}

fn accumulated_traffic(current: i64, rx_delta: u64, tx_delta: u64) -> i64 {
    let delta = rx_delta.saturating_add(tx_delta);
    current.max(0).saturating_add(bounded_counter(delta))
}

async fn reap_profile_expired_peers(
    state: &AppState,
    profile_id: &str,
    protocol: &str,
    interface_name: &str,
) -> Result<usize, &'static str> {
    let now = Utc::now();
    let rows = sqlx::query(
        "SELECT id, expires_at, wireguard_public_key, traffic_limit_bytes, traffic_used_bytes, last_rx_bytes, last_tx_bytes FROM clients WHERE container_id = ? AND enabled = 1 ORDER BY created_at ASC"
    ).bind(profile_id).fetch_all(&state.pool).await
        .map_err(|_| "Could not query enabled VPN clients")?;

    match state.runtime.interface_is_up(protocol, interface_name).await {
        Ok(true) => {}
        Ok(false) => {
            sqlx::query(
                "UPDATE protocol_containers SET status = 'error', runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'start'"
            ).bind(profile_id).execute(&state.pool).await
                .map_err(|_| "Could not mark a missing interface for recovery")?;
            return Ok(0);
        }
        Err(_) => return Err("Could not verify live VPN interface before policy enforcement"),
    }

    let live_peers = state.runtime.peer_stats(protocol, interface_name).await
        .map_err(|_| "Could not read live peer counters before policy enforcement")?;
    let by_key: HashMap<String, PeerRuntimeStat> = live_peers.into_iter()
        .map(|peer| (peer.public_key.clone(), peer))
        .collect();

    // (client id, cumulative usage, last RX, last TX, revoke reason, public key)
    let mut snapshots: Vec<(String, i64, i64, i64, Option<&'static str>, Option<String>)> = Vec::new();
    for row in rows {
        let client_id: String = sqlx::Row::try_get(&row, "id")
            .map_err(|_| "Invalid client id during traffic accounting")?;
        let expires_at: Option<String> = sqlx::Row::try_get(&row, "expires_at")
            .map_err(|_| "Invalid client expiry during traffic accounting")?;
        let public_key: Option<String> = sqlx::Row::try_get(&row, "wireguard_public_key")
            .map_err(|_| "Invalid client public key during traffic accounting")?;
        let traffic_limit: i64 = sqlx::Row::try_get(&row, "traffic_limit_bytes")
            .map_err(|_| "Invalid client traffic limit")?;
        let traffic_used: i64 = sqlx::Row::try_get(&row, "traffic_used_bytes")
            .map_err(|_| "Invalid client cumulative traffic")?;
        let last_rx: i64 = sqlx::Row::try_get(&row, "last_rx_bytes")
            .map_err(|_| "Invalid client RX snapshot")?;
        let last_tx: i64 = sqlx::Row::try_get(&row, "last_tx_bytes")
            .map_err(|_| "Invalid client TX snapshot")?;

        let expired = match expires_at.as_deref() {
            Some(value) => match DateTime::parse_from_rfc3339(value) {
                Ok(expiry) => expiry.with_timezone(&Utc) <= now,
                Err(_) => {
                    tracing::warn!(container_id = %profile_id, client_id = %client_id, "Skipping invalid client expiry timestamp");
                    false
                }
            },
            None => false,
        };

        let peer = public_key.as_ref().and_then(|key| by_key.get(key));
        let (new_used, new_rx, new_tx) = if let Some(peer) = peer {
            let rx_delta = traffic_counter_delta(last_rx, peer.rx_bytes);
            let tx_delta = traffic_counter_delta(last_tx, peer.tx_bytes);
            (
                accumulated_traffic(traffic_used, rx_delta, tx_delta),
                bounded_counter(peer.rx_bytes),
                bounded_counter(peer.tx_bytes),
            )
        } else {
            (traffic_used.max(0), last_rx.max(0), last_tx.max(0))
        };

        let quota_reached = traffic_limit > 0 && new_used >= traffic_limit;
        let reason = if expired {
            Some("expired")
        } else if quota_reached {
            Some("traffic_limit")
        } else {
            None
        };
        if reason.is_some() && public_key.is_none() {
            return Err("An enabled client reached an access limit but has no public key");
        }

        // Save snapshots only when there was a matched peer or a policy action.
        if peer.is_some() || reason.is_some() {
            snapshots.push((client_id, new_used, new_rx, new_tx, reason, public_key));
        }
    }

    // Remove only keys still present on the actual interface. If a runtime
    // operation partially succeeds and the DB commit later fails, the next
    // pass safely retries the DB side after observing the peer is already gone.
    for (_, _, _, _, reason, public_key) in &snapshots {
        if reason.is_none() {
            continue;
        }
        let public_key = public_key.as_deref()
            .ok_or("An enabled client reached an access limit but has no public key")?;
        if by_key.contains_key(public_key) {
            state.runtime.remove_peer(protocol, interface_name, public_key).await
                .map_err(|_| "Could not remove a policy-revoked peer from the live VPN interface")?;
        }
    }

    let mut tx = state.pool.begin().await
        .map_err(|_| "Could not begin client traffic accounting transaction")?;
    let mut revoked_clients = Vec::new();
    for (client_id, used, rx, tx_bytes, reason, _) in &snapshots {
        let enabled = if reason.is_some() { 0 } else { 1 };
        let result = sqlx::query(
            "UPDATE clients SET traffic_used_bytes = ?, last_rx_bytes = ?, last_tx_bytes = ?, enabled = ? WHERE id = ? AND container_id = ? AND enabled = 1"
        ).bind(used).bind(rx).bind(tx_bytes).bind(enabled).bind(client_id).bind(profile_id)
            .execute(&mut *tx).await
            .map_err(|_| "Could not persist client traffic snapshot")?;
        if result.rows_affected() == 1 {
            if let Some(reason) = reason {
                revoked_clients.push(serde_json::json!({
                    "client_id": client_id,
                    "reason": reason
                }));
            }
        }
    }

    let revoked_count = revoked_clients.len();
    let revision_increment = if revoked_count > 0 { 1_i64 } else { 0_i64 };
    let updated = sqlx::query(
        "UPDATE protocol_containers SET revision = revision + ?, runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'start'"
    ).bind(revision_increment).bind(profile_id).execute(&mut *tx).await
        .map_err(|_| "Could not release profile lock after traffic accounting")?;
    if updated.rows_affected() != 1 {
        return Err("Profile state changed during traffic accounting");
    }

    if revoked_count > 0 {
        let details = serde_json::json!({
            "container_id": profile_id,
            "revoked_clients": revoked_clients,
            "revoked_count": revoked_count,
            "accounting": "rx_plus_tx",
            "automatic": true
        }).to_string();
        sqlx::query(
            "INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (NULL, 'client.policy_enforced', ?)"
        ).bind(details).execute(&mut *tx).await
            .map_err(|_| "Could not audit automatic VPN client policy enforcement")?;
    }

    tx.commit().await
        .map_err(|_| "Could not commit client traffic accounting transaction")?;
    Ok(revoked_count)
}

#[cfg(test)]
mod expiry_reaper_tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{Duration as ChronoDuration, Utc};
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{
        runtime::{PeerRuntimeStat, RuntimeAdapter, RuntimeStatus},
        state::AppState,
    };

    use super::reap_expired_peers_once;

    struct FakeHostRuntime {
        peers: Arc<Mutex<HashSet<String>>>,
        counters: Arc<Mutex<HashMap<String, (u64, u64)>>>,
        fail_remove: bool,
    }

    #[async_trait]
    impl RuntimeAdapter for FakeHostRuntime {
        async fn status(&self) -> RuntimeStatus {
            RuntimeStatus {
                mode: "host",
                available: true,
                engine: "linux-host",
                message: "test host runtime".into(),
                can_manage_vpn: true,
            }
        }

        async fn interface_is_up(
            &self,
            _protocol: &str,
            _interface_name: &str,
        ) -> Result<bool, &'static str> {
            Ok(true)
        }

        async fn peer_stats(
            &self,
            _protocol: &str,
            _interface_name: &str,
        ) -> Result<Vec<PeerRuntimeStat>, &'static str> {
            let peers = self.peers.lock().unwrap().clone();
            let counters = self.counters.lock().unwrap().clone();
            Ok(peers.into_iter().map(|public_key| {
                let (rx_bytes, tx_bytes) = counters.get(&public_key).copied().unwrap_or((0, 0));
                PeerRuntimeStat {
                    public_key,
                    allowed_ips: "10.66.0.2/32".into(),
                    latest_handshake_unix: None,
                    rx_bytes,
                    tx_bytes,
                }
            }).collect())
        }

        async fn remove_peer(
            &self,
            _protocol: &str,
            _interface_name: &str,
            public_key: &str,
        ) -> Result<(), &'static str> {
            if self.fail_remove {
                return Err("simulated peer removal failure");
            }
            self.peers.lock().unwrap().remove(public_key);
            Ok(())
        }
    }

    async fn test_state(fail_remove: bool) -> (AppState, Arc<Mutex<HashSet<String>>>, String, String) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE protocol_containers (
                id TEXT PRIMARY KEY,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                runtime_operation TEXT,
                revision INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "CREATE TABLE clients (
                id TEXT PRIMARY KEY,
                container_id TEXT NOT NULL,
                name TEXT NOT NULL,
                assigned_ip TEXT NOT NULL,
                enabled BOOLEAN NOT NULL,
                expires_at TEXT,
                wireguard_public_key TEXT,
                traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
                traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
                last_rx_bytes INTEGER NOT NULL DEFAULT 0,
                last_tx_bytes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_admin_id INTEGER,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL
            )"
        ).execute(&pool).await.unwrap();

        let profile_id = "abcdef1234".to_string();
        sqlx::query(
            "INSERT INTO protocol_containers (id, protocol, status, runtime_operation, revision)
             VALUES (?, 'wireguard', 'running', NULL, 1)"
        ).bind(&profile_id).execute(&pool).await.unwrap();

        let expired_key = STANDARD.encode([21u8; 32]);
        let future_key = STANDARD.encode([22u8; 32]);
        let expired_at = (Utc::now() - ChronoDuration::minutes(1)).to_rfc3339();
        let future_at = (Utc::now() + ChronoDuration::days(1)).to_rfc3339();

        sqlx::query(
            "INSERT INTO clients (id, container_id, name, assigned_ip, enabled, expires_at, wireguard_public_key)
             VALUES ('expired-client', ?, 'Expired', '10.66.0.2', 1, ?, ?),
                    ('future-client', ?, 'Future', '10.66.0.3', 1, ?, ?)"
        )
            .bind(&profile_id).bind(expired_at).bind(&expired_key)
            .bind(&profile_id).bind(future_at).bind(&future_key)
            .execute(&pool).await.unwrap();

        let peers = Arc::new(Mutex::new(HashSet::from([
            expired_key.clone(),
            future_key.clone(),
        ])));
        let counters = Arc::new(Mutex::new(HashMap::from([
            (expired_key.clone(), (1_000_u64, 250_u64)),
            (future_key.clone(), (100_u64, 50_u64)),
        ])));
        let runtime = FakeHostRuntime {
            peers: peers.clone(),
            counters,
            fail_remove,
        };
        let state = AppState {
            pool,
            cookie_secure: false,
            runtime: Arc::new(runtime),
            wireguard_master_key: None,
        };
        (state, peers, expired_key, future_key)
    }

    #[tokio::test]
    async fn automatically_removes_expired_peer_and_audits_database_revocation() {
        let (state, peers, expired_key, future_key) = test_state(false).await;
        assert_eq!(reap_expired_peers_once(&state).await, 1);

        let expired_enabled: bool = sqlx::query_scalar(
            "SELECT enabled FROM clients WHERE id = 'expired-client'"
        ).fetch_one(&state.pool).await.unwrap();
        let future_enabled: bool = sqlx::query_scalar(
            "SELECT enabled FROM clients WHERE id = 'future-client'"
        ).fetch_one(&state.pool).await.unwrap();
        let (status, operation, revision): (String, Option<String>, i64) = sqlx::query_as(
            "SELECT status, runtime_operation, revision FROM protocol_containers WHERE id = 'abcdef1234'"
        ).fetch_one(&state.pool).await.unwrap();
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'client.policy_enforced'"
        ).fetch_one(&state.pool).await.unwrap();
        let (expired_usage, expired_rx, expired_tx): (i64, i64, i64) = sqlx::query_as(
            "SELECT traffic_used_bytes, last_rx_bytes, last_tx_bytes FROM clients WHERE id = 'expired-client'"
        ).fetch_one(&state.pool).await.unwrap();
        let (future_usage, future_rx, future_tx): (i64, i64, i64) = sqlx::query_as(
            "SELECT traffic_used_bytes, last_rx_bytes, last_tx_bytes FROM clients WHERE id = 'future-client'"
        ).fetch_one(&state.pool).await.unwrap();

        assert!(!expired_enabled);
        assert!(future_enabled);
        assert_eq!(status, "running");
        assert!(operation.is_none());
        assert_eq!(revision, 2);
        assert_eq!(audit_count, 1);
        assert_eq!((expired_usage, expired_rx, expired_tx), (1_250, 1_000, 250));
        assert_eq!((future_usage, future_rx, future_tx), (150, 100, 50));
        let remaining = peers.lock().unwrap();
        assert!(!remaining.contains(&expired_key));
        assert!(remaining.contains(&future_key));
    }


    #[tokio::test]
    async fn revokes_client_when_cumulative_rx_plus_tx_reaches_traffic_limit() {
        let (state, peers, _expired_key, future_key) = test_state(false).await;
        let future_expiry = (Utc::now() + ChronoDuration::days(1)).to_rfc3339();
        sqlx::query(
            "UPDATE clients SET expires_at = ?, traffic_limit_bytes = 1_250 WHERE id = 'expired-client'"
        ).bind(&future_expiry).execute(&state.pool).await.unwrap();
        sqlx::query(
            "UPDATE clients SET traffic_limit_bytes = 150 WHERE id = 'future-client'"
        ).execute(&state.pool).await.unwrap();

        assert_eq!(reap_expired_peers_once(&state).await, 2);
        let (expired_enabled, future_enabled): (bool, bool) = sqlx::query_as(
            "SELECT
                (SELECT enabled FROM clients WHERE id = 'expired-client'),
                (SELECT enabled FROM clients WHERE id = 'future-client')"
        ).fetch_one(&state.pool).await.unwrap();
        let future_usage: i64 = sqlx::query_scalar(
            "SELECT traffic_used_bytes FROM clients WHERE id = 'future-client'"
        ).fetch_one(&state.pool).await.unwrap();
        let revoked_reasons: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_events WHERE action = 'client.policy_enforced'"
        ).fetch_one(&state.pool).await.unwrap();

        assert!(!expired_enabled);
        assert!(!future_enabled);
        assert_eq!(future_usage, 150);
        assert!(revoked_reasons.contains("traffic_limit"));
        assert!(!peers.lock().unwrap().contains(&future_key));
    }

    #[test]
    fn traffic_counter_resets_do_not_underflow_and_usage_saturates() {
        assert_eq!(super::traffic_counter_delta(900, 100), 100);
        assert_eq!(super::traffic_counter_delta(50, 100), 50);
        assert_eq!(super::accumulated_traffic(i64::MAX - 1, 1, 1), i64::MAX);
    }

    #[tokio::test]
    async fn keeps_client_enabled_and_releases_lock_when_runtime_peer_removal_fails() {
        let (state, peers, expired_key, _future_key) = test_state(true).await;
        assert_eq!(reap_expired_peers_once(&state).await, 0);

        let expired_enabled: bool = sqlx::query_scalar(
            "SELECT enabled FROM clients WHERE id = 'expired-client'"
        ).fetch_one(&state.pool).await.unwrap();
        let (operation, revision): (Option<String>, i64) = sqlx::query_as(
            "SELECT runtime_operation, revision FROM protocol_containers WHERE id = 'abcdef1234'"
        ).fetch_one(&state.pool).await.unwrap();

        assert!(expired_enabled);
        assert!(operation.is_none());
        assert_eq!(revision, 1);
        assert!(peers.lock().unwrap().contains(&expired_key));
    }
}
