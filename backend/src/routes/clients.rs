use std::{collections::HashSet, net::Ipv4Addr, str::FromStr};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    routes::containers::profile_is_stopped,
    security::session::{hash_session_token, new_session_token},
    state::AppState,
};
use super::auth::authenticated_admin;

#[derive(Debug, Serialize, FromRow)]
pub struct ClientRecord {
    pub id: String,
    pub container_id: String,
    pub name: String,
    pub note: String,
    pub assigned_ip: String,
    pub enabled: bool,
    pub traffic_limit_bytes: i64,
    pub traffic_used_bytes: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub wireguard_public_key: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateClientRequest {
    name: String,
    note: Option<String>,
    traffic_limit_bytes: Option<i64>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
pub struct ListClientsQuery {
    container_id: Option<String>,
}

#[derive(Serialize)]
pub struct ClientList {
    items: Vec<ClientRecord>,
}

#[derive(Serialize)]
pub struct CreateClientResponse {
    item: ClientRecord,
    subscription_token: String,
    notice: &'static str,
}

/// Reserve the first usable address for the VPN server interface.
fn first_available_client_ip(subnet: Ipv4Net, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    subnet.hosts().skip(1).find(|address| !used.contains(address))
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ListClientsQuery>,
) -> Result<Json<ClientList>, StatusCode> {
    authenticated_admin(&state, &jar).await?;
    let items = if let Some(container_id) = query.container_id {
        sqlx::query_as::<_, ClientRecord>(
            "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at, wireguard_public_key FROM clients WHERE container_id = ? ORDER BY created_at DESC"
        ).bind(container_id).fetch_all(&state.pool).await
    } else {
        sqlx::query_as::<_, ClientRecord>(
            "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at, wireguard_public_key FROM clients ORDER BY created_at DESC"
        ).fetch_all(&state.pool).await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ClientList { items }))
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
    Json(input): Json<CreateClientRequest>,
) -> Result<Json<CreateClientResponse>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let name = input.name.trim();
    if !(1..=48).contains(&name.len()) {
        return Err((StatusCode::BAD_REQUEST, "Client name must be 1-48 characters"));
    }
    let note = input.note.unwrap_or_default();
    if note.len() > 200 {
        return Err((StatusCode::BAD_REQUEST, "Note must be at most 200 characters"));
    }
    let traffic_limit = input.traffic_limit_bytes.unwrap_or(0);
    if traffic_limit < 0 {
        return Err((StatusCode::BAD_REQUEST, "Traffic limit cannot be negative"));
    }
    if let Some(expires_at) = &input.expires_at {
        let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Expiration must be an RFC3339 timestamp"))?;
        if expiry.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            return Err((StatusCode::BAD_REQUEST, "Expiration must be in the future"));
        }
    }

    let row = sqlx::query("SELECT subnet, protocol, wireguard_server_public_key, status, runtime_operation FROM protocol_containers WHERE id = ?")
        .bind(&container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "Container not found"))?;
    let subnet_text: String = sqlx::Row::try_get(&row, "subnet")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let protocol: String = sqlx::Row::try_get(&row, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let container_status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let runtime_operation: Option<String> = sqlx::Row::try_get(&row, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let live_apply = container_status == "running";
    let runtime_status = state.runtime.status().await;

    if live_apply {
        if protocol != "wireguard" && protocol != "amnezia-awg" {
            return Err((StatusCode::CONFLICT, "Live peer addition supports only WireGuard and AmneziaWG"));
        }
        if runtime_status.mode != "host" || !runtime_status.can_manage_vpn {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Live peer changes require an explicitly enabled Linux host runtime"));
        }
        if runtime_operation.is_some() {
            return Err((StatusCode::CONFLICT, "Another VPN runtime operation is in progress; retry after it finishes"));
        }
    } else if !profile_is_stopped(&container_status, runtime_operation.as_deref()) {
        return Err((StatusCode::CONFLICT, "VPN profile must be stopped before adding a client"));
    }

    if protocol == "amnezia-awg" || protocol == "wireguard" {
        let server_public_key: Option<String> = sqlx::Row::try_get(&row, "wireguard_server_public_key")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        if server_public_key.is_none() {
            return Err((StatusCode::CONFLICT, "Provision the server WireGuard key before creating clients"));
        }
    }
    let keypair = if protocol == "amnezia-awg" || protocol == "wireguard" {
        let master_key = state.wireguard_master_key.as_ref()
            .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Set WIREGUARD_MASTER_KEY before creating WireGuard or AmneziaWG clients"))?;
        let (private_key, public_key) = crate::security::wireguard_keys::generate_keypair();
        let encrypted = crate::security::wireguard_keys::encrypt_private_key(master_key, &private_key)
            .map_err(|message| (StatusCode::INTERNAL_SERVER_ERROR, message))?;
        Some((public_key, encrypted))
    } else {
        None
    };
    let subnet = Ipv4Net::from_str(&subnet_text)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored subnet is invalid"))?;

    let used_rows = sqlx::query("SELECT assigned_ip FROM clients WHERE container_id = ?")
        .bind(&container_id).fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let mut used = HashSet::new();
    for row in used_rows {
        let address: String = sqlx::Row::try_get(&row, "assigned_ip")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        if let Ok(ip) = Ipv4Addr::from_str(&address) {
            used.insert(ip);
        }
    }
    let assigned_ip = first_available_client_ip(subnet, &used)
        .ok_or((StatusCode::CONFLICT, "No free IP addresses remain in this subnet"))?;

    let interface_name = if live_apply {
        Some(crate::runtime::interface_name_for_profile(&protocol, &container_id)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not derive interface name"))?)
    } else {
        None
    };

    // The same per-profile lock serializes live peer installation with stop,
    // revocation and the background expiry worker.
    if live_apply {
        let claimed = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'sync' WHERE id = ? AND status = 'running' AND runtime_operation IS NULL"
        ).bind(&container_id).execute(&state.pool).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim live peer installation"))?;
        if claimed.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
        }
    }

    let id = Uuid::new_v4().to_string();
    let subscription_token = new_session_token();
    let token_hash = hash_session_token(&subscription_token);
    let (public_key, encrypted_private_key) = match keypair {
        Some((public_key, encrypted)) => (Some(public_key), Some(encrypted)),
        None => (None, None),
    };
    let expected_status = container_status.clone();
    let expires_at = input.expires_at.clone();

    let creation_result: Result<(ClientRecord, i64), (StatusCode, &'static str)> = async {
        let mut tx = state.pool.begin().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not begin client creation"))?;
        let insert_sql = if live_apply {
            "INSERT INTO clients (id, container_id, name, note, assigned_ip, enabled, subscription_token_hash, traffic_limit_bytes, expires_at, wireguard_public_key, wireguard_private_key_encrypted) SELECT ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM protocol_containers WHERE id = ? AND status = 'running' AND runtime_operation = 'sync')"
        } else {
            "INSERT INTO clients (id, container_id, name, note, assigned_ip, enabled, subscription_token_hash, traffic_limit_bytes, expires_at, wireguard_public_key, wireguard_private_key_encrypted) SELECT ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM protocol_containers WHERE id = ? AND status = ? AND runtime_operation IS NULL)"
        };
        let mut insert = sqlx::query(insert_sql)
            .bind(&id).bind(&container_id).bind(name).bind(note.trim())
            .bind(assigned_ip.to_string()).bind(&token_hash).bind(traffic_limit)
            .bind(expires_at).bind(&public_key).bind(&encrypted_private_key).bind(&container_id);
        if !live_apply {
            insert = insert.bind(&expected_status);
        }
        let insert_result = insert.execute(&mut *tx).await
            .map_err(|error| {
                if let sqlx::Error::Database(db_error) = &error {
                    if db_error.is_unique_violation() || db_error.message().contains("duplicate_client_ip") {
                        return (StatusCode::CONFLICT, "The selected client IP is already allocated; refresh and retry");
                    }
                }
                tracing::error!("Failed to create client: {error}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Could not save client")
            })?;
        if insert_result.rows_affected() == 0 {
            return Err((StatusCode::CONFLICT, "VPN profile state changed while the client was being created; refresh and retry"));
        }

        let revision_sql = if live_apply {
            "UPDATE protocol_containers SET revision = revision + 1 WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
        } else {
            "UPDATE protocol_containers SET revision = revision + 1 WHERE id = ? AND status = ? AND runtime_operation IS NULL"
        };
        let mut revision_update = sqlx::query(revision_sql).bind(&container_id);
        if !live_apply {
            revision_update = revision_update.bind(&expected_status);
        }
        let revision_update = revision_update.execute(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not advance VPN profile revision"))?;
        if revision_update.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "VPN profile state changed while the client was being created; refresh and retry"));
        }
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM protocol_containers WHERE id = ?")
            .bind(&container_id).fetch_one(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read VPN profile revision"))?;
        let item = sqlx::query_as::<_, ClientRecord>(
            "SELECT id, container_id, name, note, assigned_ip, enabled, traffic_limit_bytes, traffic_used_bytes, expires_at, created_at, wireguard_public_key FROM clients WHERE id = ?"
        ).bind(&id).fetch_one(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read saved client"))?;

        if !live_apply {
            let details = serde_json::json!({
                "client_id": id,
                "container_id": container_id,
                "assigned_ip": assigned_ip.to_string(),
                "revision": revision,
                "runtime_applied": false
            }).to_string();
            sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.created', ?)")
                .bind(admin_id).bind(details).execute(&mut *tx).await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not record client creation"))?;
        }
        tx.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not commit client creation"))?;
        Ok((item, revision))
    }.await;

    let (item, revision) = match creation_result {
        Ok(value) => value,
        Err(error) => {
            if live_apply {
                let release = sqlx::query(
                    "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
                ).bind(&container_id).execute(&state.pool).await;
                if let Err(release_error) = release {
                    tracing::error!(container_id = %container_id, "Could not release live peer installation lock: {release_error}");
                }
            }
            return Err(error);
        }
    };

    if live_apply {
        let public_key = item.wireguard_public_key.as_deref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "New live client has no WireGuard public key"))?;
        let allowed_ip = format!("{}/32", item.assigned_ip);
        let interface_name = interface_name.as_deref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Live VPN interface name is missing"))?;

        if let Err(add_error) = state.runtime.add_peer(&protocol, interface_name, public_key, &allowed_ip).await {
            // A failed command can still leave uncertain runtime state. Attempt a
            // targeted rollback, then force explicit cleanup if either probe fails.
            let cleanup_ok = state.runtime.remove_peer(&protocol, interface_name, public_key).await.is_ok();
            let interface_up = state.runtime.interface_is_up(&protocol, interface_name).await.unwrap_or(false);
            let needs_recovery = !cleanup_ok || !interface_up;

            match state.pool.begin().await {
                Ok(mut tx) => {
                    let _ = sqlx::query("UPDATE clients SET enabled = 0 WHERE id = ? AND container_id = ?")
                        .bind(&id).bind(&container_id).execute(&mut *tx).await;
                    let profile_status = if needs_recovery { "error" } else { "running" };
                    let update = sqlx::query(
                        "UPDATE protocol_containers SET status = ?, revision = revision + 1, runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
                    ).bind(profile_status).bind(&container_id).execute(&mut *tx).await;
                    let details = serde_json::json!({
                        "client_id": id,
                        "container_id": container_id,
                        "runtime_error": add_error,
                        "rollback_succeeded": cleanup_ok,
                        "interface_verified_running": interface_up
                    }).to_string();
                    let audit = sqlx::query(
                        "INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.live_create_failed', ?)"
                    ).bind(admin_id).bind(details).execute(&mut *tx).await;
                    if update.is_ok() && audit.is_ok() {
                        if let Err(error) = tx.commit().await {
                            tracing::error!(container_id = %container_id, "Could not commit failed live peer installation recovery: {error}");
                        }
                    } else {
                        tracing::error!(container_id = %container_id, "Could not persist failed live peer installation recovery state");
                    }
                }
                Err(error) => tracing::error!(container_id = %container_id, "Could not begin failed live peer installation recovery: {error}"),
            }
            return Err((StatusCode::BAD_GATEWAY, "Could not install the new peer on the live VPN interface; inspect the profile state and retry"));
        }

        let mut tx = state.pool.begin().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Peer installed, but could not finalize the profile update"))?;
        let released = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
        ).bind(&container_id).execute(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Peer installed, but could not release the profile lock"))?;
        if released.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "Peer installed, but profile state requires reconciliation"));
        }
        let details = serde_json::json!({
            "client_id": id,
            "container_id": container_id,
            "assigned_ip": assigned_ip.to_string(),
            "revision": revision,
            "runtime_applied": true
        }).to_string();
        sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.created', ?)")
            .bind(admin_id).bind(details).execute(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Peer installed, but could not record client creation"))?;
        tx.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Peer installed, but could not commit client creation audit"))?;
    }

    Ok(Json(CreateClientResponse {
        item,
        subscription_token,
        notice: if live_apply {
            "Peer was installed on the running VPN interface immediately. The subscription token is shown once; download the client .conf separately."
        } else {
            "Subscription token is shown once. This peer will be installed the next time the stopped VPN profile starts; a client .conf export is available separately."
        },
    }))
}

pub async fn disable(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;

    let existing = sqlx::query(
        "SELECT c.container_id, c.enabled, c.wireguard_public_key, p.protocol, p.status, p.runtime_operation FROM clients c JOIN protocol_containers p ON p.id = c.container_id WHERE c.id = ?"
    )
        .bind(&client_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "Client not found"))?;
    let container_id: String = sqlx::Row::try_get(&existing, "container_id")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let enabled: bool = sqlx::Row::try_get(&existing, "enabled")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if !enabled {
        return Ok(StatusCode::NO_CONTENT);
    }
    let protocol: String = sqlx::Row::try_get(&existing, "protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let profile_status: String = sqlx::Row::try_get(&existing, "status")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let runtime_operation: Option<String> = sqlx::Row::try_get(&existing, "runtime_operation")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if runtime_operation.is_some() {
        return Err((StatusCode::CONFLICT, "A VPN runtime operation is in progress; retry after it finishes"));
    }

    let runtime_applied = if profile_status == "running" {
        if protocol != "wireguard" && protocol != "amnezia-awg" {
            return Err((StatusCode::CONFLICT, "Live revocation supports only WireGuard and AmneziaWG"));
        }
        let runtime_status = state.runtime.status().await;
        if runtime_status.mode != "host" || !runtime_status.can_manage_vpn {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Live peer changes require an explicitly enabled Linux host runtime"));
        }
        let public_key: Option<String> = sqlx::Row::try_get(&existing, "wireguard_public_key")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        let public_key = public_key
            .ok_or((StatusCode::CONFLICT, "This running client has no WireGuard public key"))?;
        let interface_name = crate::runtime::interface_name_for_profile(&protocol, &container_id)
            .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
        let claimed = sqlx::query(
            "UPDATE protocol_containers SET runtime_operation = 'sync' WHERE id = ? AND status = 'running' AND runtime_operation IS NULL"
        ).bind(&container_id).execute(&state.pool).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not claim live peer revocation"))?;
        if claimed.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "VPN profile state changed; refresh and retry"));
        }
        if let Err(message) = state.runtime.remove_peer(&protocol, &interface_name, &public_key).await {
            let _ = sqlx::query(
                "UPDATE protocol_containers SET runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
            ).bind(&container_id).execute(&state.pool).await;
            return Err((StatusCode::CONFLICT, message));
        }
        true
    } else if profile_status == "preview" || profile_status == "stopped" {
        false
    } else {
        return Err((StatusCode::CONFLICT, "VPN profile is in an error state; reconcile or stop the interface before revoking this client"));
    };

    let transaction_result: Result<(), (StatusCode, &'static str)> = async {
        let mut tx = state.pool.begin().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not begin client revocation"))?;
        let result = if runtime_applied {
            sqlx::query(
                "UPDATE clients SET enabled = 0 WHERE id = ? AND enabled = 1 AND EXISTS (SELECT 1 FROM protocol_containers WHERE id = ? AND status = 'running' AND runtime_operation = 'sync')"
            ).bind(&client_id).bind(&container_id).execute(&mut *tx).await
        } else {
            sqlx::query(
                "UPDATE clients SET enabled = 0 WHERE id = ? AND enabled = 1 AND EXISTS (SELECT 1 FROM protocol_containers WHERE id = ? AND status IN ('preview', 'stopped') AND runtime_operation IS NULL)"
            ).bind(&client_id).bind(&container_id).execute(&mut *tx).await
        }.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not disable client"))?;
        if result.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "Client or VPN profile changed concurrently; refresh and reconcile runtime state"));
        }

        let profile_update = if runtime_applied {
            sqlx::query(
                "UPDATE protocol_containers SET revision = revision + 1, runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
            ).bind(&container_id).execute(&mut *tx).await
        } else {
            sqlx::query(
                "UPDATE protocol_containers SET revision = revision + 1 WHERE id = ? AND status IN ('preview', 'stopped') AND runtime_operation IS NULL"
            ).bind(&container_id).execute(&mut *tx).await
        }.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not advance profile revision"))?;
        if profile_update.rows_affected() != 1 {
            return Err((StatusCode::CONFLICT, "VPN profile state changed while revoking the client"));
        }

        let details = serde_json::json!({
            "client_id": client_id,
            "container_id": container_id,
            "runtime_applied": runtime_applied
        }).to_string();
        sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'client.disabled', ?)")
            .bind(admin_id).bind(details).execute(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not record client revocation"))?;
        tx.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not commit client revocation"))?;
        Ok(())
    }.await;

    if let Err(error) = transaction_result {
        if runtime_applied {
            // Runtime removal already happened. Keep the client revoked in the
            // database where possible, and mark the profile for explicit cleanup.
            let _ = sqlx::query("UPDATE clients SET enabled = 0 WHERE id = ? AND container_id = ?")
                .bind(&client_id).bind(&container_id).execute(&state.pool).await;
            let _ = sqlx::query(
                "UPDATE protocol_containers SET status = 'error', revision = revision + 1, runtime_operation = NULL WHERE id = ? AND status = 'running' AND runtime_operation = 'sync'"
            ).bind(&container_id).execute(&state.pool).await;
        }
        return Err(error);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::first_available_client_ip;
    use ipnet::Ipv4Net;
    use std::{collections::HashSet, net::Ipv4Addr, str::FromStr};
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn database_guard_rejects_duplicate_client_ip_for_same_container() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE clients (id TEXT PRIMARY KEY, container_id TEXT NOT NULL, assigned_ip TEXT NOT NULL)"
        ).execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!("../../migrations/0006_client_ip_allocation_guard.sql"))
            .execute(&pool).await.unwrap();

        sqlx::query("INSERT INTO clients (id, container_id, assigned_ip) VALUES ('a', 'vpn-a', '10.66.0.2')")
            .execute(&pool).await.unwrap();
        let duplicate = sqlx::query(
            "INSERT INTO clients (id, container_id, assigned_ip) VALUES ('b', 'vpn-a', '10.66.0.2')"
        ).execute(&pool).await.unwrap_err();
        assert!(duplicate.to_string().contains("duplicate_client_ip"));

        // The same address is valid in a different isolated VPN container.
        sqlx::query("INSERT INTO clients (id, container_id, assigned_ip) VALUES ('c', 'vpn-b', '10.66.0.2')")
            .execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn database_guard_rejects_duplicate_ip_updates() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE clients (id TEXT PRIMARY KEY, container_id TEXT NOT NULL, assigned_ip TEXT NOT NULL)"
        ).execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!("../../migrations/0006_client_ip_allocation_guard.sql"))
            .execute(&pool).await.unwrap();

        sqlx::query("INSERT INTO clients (id, container_id, assigned_ip) VALUES ('a', 'vpn-a', '10.66.0.2'), ('b', 'vpn-a', '10.66.0.3')")
            .execute(&pool).await.unwrap();
        let duplicate = sqlx::query("UPDATE clients SET assigned_ip = '10.66.0.2' WHERE id = 'b'")
            .execute(&pool).await.unwrap_err();
        assert!(duplicate.to_string().contains("duplicate_client_ip"));
    }

    #[test]
    fn reserves_first_usable_address_for_server() {
        let subnet = Ipv4Net::from_str("10.66.0.0/24").unwrap();
        let used = HashSet::new();
        assert_eq!(
            first_available_client_ip(subnet, &used),
            Some(Ipv4Addr::new(10, 66, 0, 2))
        );
    }

    #[test]
    fn skips_allocated_addresses_and_detects_exhaustion() {
        let subnet = Ipv4Net::from_str("10.66.0.0/30").unwrap();
        let mut used = HashSet::new();
        used.insert(Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(first_available_client_ip(subnet, &used), None);
    }
}
