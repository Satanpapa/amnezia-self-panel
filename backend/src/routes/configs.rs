use std::{mem, net::Ipv4Addr, str::FromStr};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, PRAGMA},
        HeaderMap, HeaderValue, Response, StatusCode,
    },
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use sqlx::Row;
use zeroize::Zeroizing;

use crate::{
    routes::containers::AwgSettings,
    runtime::awg_config::{
        render_client_config, render_server_config, ClientConfigInput, ConfigPeer,
        ServerConfigInput,
    },
    security::{
        session::hash_session_token,
        wireguard_keys::{
            decrypt_header_protection_key, decrypt_private_key, public_key_from_private,
        },
    },
    state::AppState,
};

use super::auth::authenticated_admin;

fn active_at_now(enabled: bool, expires_at: Option<String>) -> Result<bool, StatusCode> {
    if !enabled {
        return Ok(false);
    }
    let Some(expires_at) = expires_at else {
        return Ok(true);
    };
    let expires = DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(expires.with_timezone(&Utc) > Utc::now())
}

fn config_response(filename: &'static str, mut config: Zeroizing<String>) -> Response<Body> {
    // Move the one-use plaintext buffer into the response without making an extra
    // application-level String copy. The HTTP body necessarily exists until sent.
    let body = Body::from(mem::take(&mut *config));
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static(filename),
    );
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Amnezia-Config-Status", HeaderValue::from_static("draft"));
    response
}

/// Server configuration prepared for either download or runtime activation.
pub struct ServerConfigDraft {
    pub revision: i64,
    pub peer_count: usize,
    pub config: Zeroizing<String>,
}

/// Build a server configuration from the persisted profile and currently active clients.
/// Caller must authenticate before invoking this helper.
pub async fn build_server_config(
    state: &AppState,
    container_id: &str,
) -> Result<ServerConfigDraft, (StatusCode, &'static str)> {
    let row = sqlx::query(
        "SELECT protocol, listen_port, subnet, mtu, revision, awg_settings_json, wireguard_server_public_key, wireguard_server_private_key_encrypted, awg_header_protection_key_encrypted FROM protocol_containers WHERE id = ?"
    ).bind(container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;

    let protocol: String = row.try_get("protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Server config is only available for WireGuard and AmneziaWG"));
    }
    let listen_port: u16 = u16::try_from(row.try_get::<i64, _>("listen_port")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored listen port is invalid"))?;
    let subnet_text: String = row.try_get("subnet")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let subnet = Ipv4Net::from_str(&subnet_text)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored subnet is invalid"))?;
    let mtu: u16 = u16::try_from(row.try_get::<i64, _>("mtu")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored MTU is invalid"))?;
    let revision: i64 = row.try_get("revision")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let settings_json: String = row.try_get("awg_settings_json")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let server_public_key: Option<String> = row.try_get("wireguard_server_public_key")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let server_private_encrypted: Option<Vec<u8>> = row.try_get("wireguard_server_private_key_encrypted")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    let header_encrypted: Option<Vec<u8>> = row.try_get("awg_header_protection_key_encrypted")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let master_key = state.wireguard_master_key.as_deref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "WIREGUARD_MASTER_KEY is not configured"))?;
    let server_public_key = server_public_key
        .ok_or((StatusCode::CONFLICT, "Server identity has not been provisioned"))?;
    let server_private_encrypted = server_private_encrypted
        .ok_or((StatusCode::CONFLICT, "Encrypted server private key is missing"))?;
    let server_private = decrypt_private_key(master_key, &server_private_encrypted)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not decrypt server private key"))?;
    if public_key_from_private(&server_private) != server_public_key {
        return Err((StatusCode::CONFLICT, "Stored server public/private keys do not match"));
    }

    let awg_settings = if protocol == "amnezia-awg" {
        Some(serde_json::from_str::<AwgSettings>(&settings_json)
            .map_err(|_| (StatusCode::CONFLICT, "Stored AmneziaWG settings are invalid"))?)
    } else {
        None
    };
    let header_key: Option<Zeroizing<[u8; 32]>> = match header_encrypted {
        Some(encrypted) => Some(
            decrypt_header_protection_key(master_key, &encrypted)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not decrypt AWG HeaderProtectionKey"))?
        ),
        None => None,
    };

    let client_rows = sqlx::query(
        "SELECT assigned_ip, enabled, expires_at, wireguard_public_key FROM clients WHERE container_id = ? ORDER BY created_at ASC"
    ).bind(container_id).fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read client peers"))?;
    let mut peers_owned: Vec<(String, Ipv4Addr)> = Vec::new();
    for client in client_rows {
        let enabled: bool = client.try_get("enabled")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client state"))?;
        let expires_at: Option<String> = client.try_get("expires_at")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client expiry"))?;
        if !active_at_now(enabled, expires_at)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "A client has an invalid expiry timestamp"))? {
            continue;
        }
        let public_key: Option<String> = client.try_get("wireguard_public_key")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client public key"))?;
        let public_key = public_key
            .ok_or((StatusCode::CONFLICT, "An active client has no WireGuard public key; disable it before exporting"))?;
        let assigned_ip_text: String = client.try_get("assigned_ip")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client IP"))?;
        let assigned_ip = Ipv4Addr::from_str(&assigned_ip_text)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "An active client has an invalid IP address"))?;
        peers_owned.push((public_key, assigned_ip));
    }
    let peer_refs: Vec<ConfigPeer<'_>> = peers_owned.iter()
        .map(|(public_key, assigned_ip)| ConfigPeer { public_key, assigned_ip: *assigned_ip })
        .collect();

    let config = render_server_config(&ServerConfigInput {
        protocol: &protocol,
        private_key: &server_private,
        subnet,
        listen_port,
        mtu,
        peers: &peer_refs,
        awg_settings: awg_settings.as_ref(),
        header_protection_key: header_key.as_deref(),
    }).map_err(|_| (StatusCode::CONFLICT, "Server config cannot be rendered from the stored profile"))?;

    Ok(ServerConfigDraft {
        revision,
        peer_count: peer_refs.len(),
        config,
    })
}

/// Download an admin-only server configuration draft.
pub async fn server_config(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container_id): Path<String>,
) -> Result<Response<Body>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let draft = build_server_config(&state, &container_id).await?;

    let details = serde_json::json!({
        "container_id": container_id,
        "revision": draft.revision,
        "peer_count": draft.peer_count,
        "format": "conf",
        "kind": "server",
        "runtime_applied": false
    }).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'config.server.exported', ?)")
        .bind(admin_id).bind(details).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not audit server config export"))?;

    Ok(config_response("attachment; filename=\"server.conf\"", draft.config))
}

/// Download an active client's one-use configuration draft.
async fn build_client_config(
    state: &AppState,
    client_id: &str,
) -> Result<(Zeroizing<String>, String), (StatusCode, &'static str)> {
    let row = sqlx::query(
        "SELECT c.container_id, c.assigned_ip, c.enabled, c.expires_at, c.wireguard_public_key, c.wireguard_private_key_encrypted, p.protocol, p.endpoint, p.listen_port, p.dns, p.mtu, p.subnet, p.awg_settings_json, p.wireguard_server_public_key, p.wireguard_server_private_key_encrypted, p.awg_header_protection_key_encrypted FROM clients c JOIN protocol_containers p ON p.id = c.container_id WHERE c.id = ?"
    ).bind(client_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "Client not found"))?;

    let enabled: bool = row.try_get("enabled")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client state"))?;
    let expires_at: Option<String> = row.try_get("expires_at")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client expiry"))?;
    if !enabled {
        return Err((StatusCode::FORBIDDEN, "Client access has been revoked"));
    }
    if !active_at_now(enabled, expires_at)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Client expiry timestamp is invalid"))? {
        return Err((StatusCode::GONE, "Client access has expired"));
    }

    let protocol: String = row.try_get("protocol")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Client config export is only available for WireGuard and AmneziaWG"));
    }
    let master_key = state.wireguard_master_key.as_deref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "WIREGUARD_MASTER_KEY is not configured"))?;
    let private_encrypted: Option<Vec<u8>> = row.try_get("wireguard_private_key_encrypted")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid encrypted client key"))?;
    let private_encrypted = private_encrypted
        .ok_or((StatusCode::CONFLICT, "Encrypted client private key is missing"))?;
    let private_key = decrypt_private_key(master_key, &private_encrypted)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not decrypt client private key"))?;
    let client_public_key: Option<String> = row.try_get("wireguard_public_key")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client public key"))?;
    let client_public_key = client_public_key
        .ok_or((StatusCode::CONFLICT, "Client public key is missing"))?;
    if public_key_from_private(&private_key) != client_public_key {
        return Err((StatusCode::CONFLICT, "Stored client public/private keys do not match"));
    }

    let server_public_key: Option<String> = row.try_get("wireguard_server_public_key")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid server public key"))?;
    let server_public_key = server_public_key
        .ok_or((StatusCode::CONFLICT, "Server identity has not been provisioned"))?;
    let server_private_encrypted: Option<Vec<u8>> = row.try_get("wireguard_server_private_key_encrypted")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid encrypted server private key"))?;
    let server_private_encrypted = server_private_encrypted
        .ok_or((StatusCode::CONFLICT, "Encrypted server private key is missing"))?;
    let server_private = decrypt_private_key(master_key, &server_private_encrypted)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not decrypt server private key"))?;
    if public_key_from_private(&server_private) != server_public_key {
        return Err((StatusCode::CONFLICT, "Stored server public/private keys do not match"));
    }
    let endpoint: String = row.try_get("endpoint")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid server endpoint"))?;
    let listen_port: i64 = row.try_get("listen_port")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid server port"))?;
    let listen_port = u16::try_from(listen_port)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored server port is invalid"))?;
    let dns: String = row.try_get("dns")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid DNS"))?;
    let mtu: i64 = row.try_get("mtu")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid MTU"))?;
    let mtu = u16::try_from(mtu)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored MTU is invalid"))?;
    let subnet_text: String = row.try_get("subnet")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid VPN subnet"))?;
    let vpn_subnet = Ipv4Net::from_str(&subnet_text)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored VPN subnet is invalid"))?;
    let assigned_ip_text: String = row.try_get("assigned_ip")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid client IP"))?;
    let assigned_ip = Ipv4Addr::from_str(&assigned_ip_text)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored client IP is invalid"))?;
    let settings_json: String = row.try_get("awg_settings_json")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid AWG profile"))?;
    let awg_settings = if protocol == "amnezia-awg" {
        Some(serde_json::from_str::<AwgSettings>(&settings_json)
            .map_err(|_| (StatusCode::CONFLICT, "Stored AmneziaWG settings are invalid"))?)
    } else {
        None
    };
    let header_encrypted: Option<Vec<u8>> = row.try_get("awg_header_protection_key_encrypted")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid encrypted HeaderProtectionKey"))?;
    let header_key: Option<Zeroizing<[u8; 32]>> = match header_encrypted {
        Some(encrypted) => Some(
            decrypt_header_protection_key(master_key, &encrypted)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not decrypt AWG HeaderProtectionKey"))?
        ),
        None => None,
    };

    let config = render_client_config(&ClientConfigInput {
        protocol: &protocol,
        private_key: &private_key,
        assigned_ip,
        vpn_subnet,
        dns: &dns,
        endpoint: &endpoint,
        listen_port,
        mtu,
        server_public_key: &server_public_key,
        awg_settings: awg_settings.as_ref(),
        header_protection_key: header_key.as_deref(),
        persistent_keepalive: 25,
    }).map_err(|_| (StatusCode::CONFLICT, "Client config cannot be rendered from the stored profile"))?;


    let container_id: String = row.try_get("container_id")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid container reference"))?;
    Ok((config, container_id))
}

/// Admin-only client config export. The browser session is used for authentication
/// and the export is recorded against the administrator.
pub async fn client_config(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> Result<Response<Body>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let (config, container_id) = build_client_config(&state, &client_id).await?;

    let details = serde_json::json!({
        "client_id": client_id,
        "container_id": container_id,
        "format": "conf",
        "kind": "client",
        "runtime_applied": false
    }).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'config.client.exported', ?)")
        .bind(admin_id).bind(details).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not audit client config export"))?;

    Ok(config_response("attachment; filename=\"client.conf\"", config))
}

fn subscription_bearer_token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    let authorization = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (scheme, token) = authorization.split_once(' ')
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.len() != 32
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(token)
}

/// Token-authenticated client config endpoint. The one-time token is accepted only
/// in the Authorization header, never in the URL or query string.
pub async fn subscription_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, (StatusCode, &'static str)> {
    let token = subscription_bearer_token(&headers)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "A valid subscription bearer token is required"))?;
    let token_hash = hash_session_token(token);
    let client_id: String = sqlx::query_scalar(
        "SELECT id FROM clients WHERE subscription_token_hash = ?"
    ).bind(token_hash).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::UNAUTHORIZED, "Subscription token is invalid"))?;

    let (config, container_id) = build_client_config(&state, &client_id).await?;
    let details = serde_json::json!({
        "client_id": client_id,
        "container_id": container_id,
        "format": "conf",
        "kind": "subscription",
        "runtime_applied": false
    }).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (NULL, 'config.client.subscription_exported', ?)")
        .bind(details).execute(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not audit subscription config export"))?;

    Ok(config_response("attachment; filename=\"client.conf\"", config))
}

#[cfg(test)]
mod tests {
    use super::{active_at_now, config_response, subscription_bearer_token};
    use axum::http::{
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, PRAGMA, AUTHORIZATION},
        HeaderMap, StatusCode,
    };
    use zeroize::Zeroizing;

    #[test]
    fn client_activity_requires_enabled_and_unexpired_access() {
        assert_eq!(active_at_now(false, None).unwrap(), false);
        assert_eq!(active_at_now(false, Some("not-a-date".into())).unwrap(), false);
        assert_eq!(active_at_now(true, None).unwrap(), true);
        assert_eq!(
            active_at_now(true, Some("2000-01-01T00:00:00Z".into())).unwrap(),
            false
        );
        assert_eq!(
            active_at_now(true, Some("2999-01-01T00:00:00Z".into())).unwrap(),
            true
        );
        assert_eq!(
            active_at_now(true, Some("not-a-date".into())).unwrap_err(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn subscription_tokens_are_bearer_only_and_have_fixed_opaque_format() {
        let mut headers = HeaderMap::new();
        assert_eq!(subscription_bearer_token(&headers), Err(StatusCode::UNAUTHORIZED));

        headers.insert(AUTHORIZATION, "Bearer 0123456789abcdef0123456789abcdef".parse().unwrap());
        assert_eq!(
            subscription_bearer_token(&headers).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );

        headers.insert(AUTHORIZATION, "bearer 0123456789abcdef0123456789abcdef".parse().unwrap());
        assert!(subscription_bearer_token(&headers).is_ok());

        for invalid in [
            "Bearer short",
            "Basic 0123456789abcdef0123456789abcdef",
            "Bearer 0123456789abcdef0123456789abcg",
            "Bearer 0123456789abcdef0123456789abcdef extra",
        ] {
            headers.insert(AUTHORIZATION, invalid.parse().unwrap());
            assert_eq!(subscription_bearer_token(&headers), Err(StatusCode::UNAUTHORIZED));
        }
    }

    #[test]
    fn config_responses_are_attachments_and_never_cacheable() {
        let response = config_response(
            "attachment; filename=\"client.conf\"",
            Zeroizing::new("[Interface]\\n".to_string()),
        );
        let headers = response.headers();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "text/plain; charset=utf-8");
        assert_eq!(
            headers.get(CACHE_CONTROL).unwrap(),
            "no-store, no-cache, must-revalidate, max-age=0"
        );
        assert_eq!(headers.get(PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            headers.get(CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"client.conf\""
        );
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
        assert_eq!(headers.get("X-Amnezia-Config-Status").unwrap(), "draft");
    }
}
