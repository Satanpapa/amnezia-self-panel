use std::{collections::HashSet, net::IpAddr, str::FromStr};

use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::CookieJar;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::state::AppState;
use super::auth::authenticated_admin;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AwgUint32Range {
    Number(u32),
    Range(String),
}

impl AwgUint32Range {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        let Self::Range(value) = self else { return Ok(()) };
        if value.len() > 21 || value.trim() != value {
            return Err("ContentPaddingAddition must be a uint32 value or a range such as 16-32");
        }
        if value == "(off)" {
            return Ok(());
        }
        let parts: Vec<&str> = value.split('-').collect();
        match parts.as_slice() {
            [single] => {
                single.parse::<u32>()
                    .map(|_| ())
                    .map_err(|_| "ContentPaddingAddition values must fit uint32")
            }
            [start, end] => {
                let start = start.parse::<u32>()
                    .map_err(|_| "ContentPaddingAddition ranges must contain uint32 values")?;
                let end = end.parse::<u32>()
                    .map_err(|_| "ContentPaddingAddition ranges must contain uint32 values")?;
                if start > end {
                    return Err("ContentPaddingAddition range start must not exceed range end");
                }
                Ok(())
            }
            _ => Err("ContentPaddingAddition must be a uint32 value or a range such as 16-32"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AwgSettings {
    pub version: String,
    pub jc: Option<u16>,
    pub jmin: Option<u16>,
    pub jmax: Option<u16>,
    pub s1: Option<u16>,
    pub s2: Option<u16>,
    pub s3: Option<u16>,
    pub s4: Option<u16>,
    pub h1: Option<String>,
    pub h2: Option<String>,
    pub h3: Option<String>,
    pub h4: Option<String>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub content_padding_addition: Option<AwgUint32Range>,
    pub random_trailers: bool,
    pub disable_cookies: bool,
}

impl AwgSettings {
    fn validate(&self) -> Result<(), &'static str> {
        if !["1.5", "2.0", "3.1"].contains(&self.version.as_str()) {
            return Err("AWG version must be 1.5, 2.0 or 3.1");
        }
        if self.jc.is_some_and(|v| !(1..=128).contains(&v)) {
            return Err("Jc must be between 1 and 128");
        }
        if let (Some(min), Some(max)) = (self.jmin, self.jmax) {
            if min >= max || max > 1280 {
                return Err("Jmin must be less than Jmax, and Jmax must not exceed 1280");
            }
        } else if self.jmin.is_some() != self.jmax.is_some() {
            return Err("Set both Jmin and Jmax, or leave both empty");
        }
        if self.s1.is_some_and(|v| v > 1132) {
            return Err("S1 must not exceed 1132 for the documented MTU 1280 profile");
        }
        if self.s2.is_some_and(|v| v > 1188) {
            return Err("S2 must not exceed 1188 for the documented MTU 1280 profile");
        }
        if let (Some(s1), Some(s2)) = (self.s1, self.s2) {
            if s1 + 56 == s2 {
                return Err("S1 + 56 must not equal S2");
            }
        }
        if self.version == "1.5" && (self.s3.is_some() || self.s4.is_some()) {
            return Err("S3 and S4 require AWG 2.0 or newer");
        }
        if self.version != "3.1" && (self.content_padding_addition.is_some() || self.random_trailers || self.disable_cookies) {
            return Err("ContentPaddingAddition, RandomTrailers and DisableCookies require AWG 3.1");
        }
        if let Some(value) = &self.content_padding_addition {
            value.validate()?;
        }

        let headers = [&self.h1, &self.h2, &self.h3, &self.h4];
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for header in headers.into_iter().flatten() {
            let parts: Vec<&str> = header.split('-').collect();
            let (start, end) = match parts.as_slice() {
                [one] => {
                    let value = one.parse::<u64>().map_err(|_| "H1-H4 must be integers or numeric ranges")?;
                    (value, value)
                }
                [start, end] => {
                    let start = start.parse::<u64>().map_err(|_| "H1-H4 ranges must contain integers")?;
                    let end = end.parse::<u64>().map_err(|_| "H1-H4 ranges must contain integers")?;
                    if start > end { return Err("H1-H4 range start must not exceed range end"); }
                    (start, end)
                }
                _ => return Err("H1-H4 must be a number or a range like 1000-2000"),
            };
            if start < 5 || end > 2_147_483_647 {
                return Err("H1-H4 values must be between 5 and 2147483647");
            }
            if ranges.iter().any(|(a, b)| start <= *b && *a <= end) {
                return Err("H1-H4 values and ranges must not overlap");
            }
            ranges.push((start, end));
        }
        for signature in [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5].into_iter().flatten() {
            validate_cps_signature(signature)?;
        }
        Ok(())
    }

    pub(crate) fn validate_header_protection(&self) -> Result<(), &'static str> {
        if self.version != "3.1" {
            return Err("HeaderProtectionKey requires AmneziaWG 3.1");
        }
        for value in [self.s1, self.s2, self.s3, self.s4] {
            if value.unwrap_or(0) < 12 {
                return Err("HeaderProtectionKey requires S1, S2, S3 and S4 to be at least 12");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, FromRow)]
pub struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub status: String,
    pub endpoint: String,
    pub listen_port: i64,
    pub transport: String,
    pub subnet: String,
    pub dns: String,
    pub mtu: i64,
    pub revision: i64,
    pub created_at: String,
    pub awg_settings_json: String,
    pub wireguard_server_public_key: Option<String>,
    pub awg_header_protection_key_configured: bool,
}

#[derive(Deserialize)]
pub struct CreateContainerRequest {
    name: String,
    protocol: String,
    endpoint: String,
    listen_port: u16,
    transport: String,
    subnet: String,
    dns: String,
    mtu: u16,
    awg_settings: Option<AwgSettings>,
}

#[derive(Serialize)]
pub struct ContainerList {
    items: Vec<ContainerRecord>,
}

#[derive(Serialize)]
pub struct CreateContainerResponse {
    item: ContainerRecord,
    runtime_mode: &'static str,
    notice: &'static str,
}

fn validate_cps_signature(signature: &str) -> Result<(), &'static str> {
    if signature.is_empty() || signature.len() > 1024 || signature.contains('\r') || signature.contains('\n') {
        return Err("I1-I5 signatures must be 1-1024 characters without line breaks");
    }
    let mut remaining = signature;
    while !remaining.is_empty() {
        let Some(after_open) = remaining.strip_prefix('<') else {
            return Err("I1-I5 must be a sequence of Amnezia tags");
        };
        let Some(close) = after_open.find('>') else {
            return Err("I1-I5 contains an unterminated tag");
        };
        let tag = &after_open[..close];
        let parts: Vec<&str> = tag.split_ascii_whitespace().collect();
        match parts.as_slice() {
            ["t"] => {}
            ["r" | "rd" | "rc", size] => {
                let size = size.parse::<u16>()
                    .map_err(|_| "I1-I5 random tag size must be an integer from 1 to 1024")?;
                if size == 0 || size > 1024 {
                    return Err("I1-I5 random tag size must be from 1 to 1024");
                }
            }
            ["b", bytes] => {
                let hex = bytes.strip_prefix("0x")
                    .ok_or("I1-I5 byte tags must use <b 0x...> syntax")?;
                if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 1024
                    || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err("I1-I5 byte tags must contain an even-sized hexadecimal byte sequence");
                }
            }
            _ => return Err("I1-I5 contains an unsupported Amnezia CPS tag"),
        }
        remaining = &after_open[close + 1..];
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.len() > 253 || endpoint.chars().any(char::is_whitespace) {
        return false;
    }
    let host = if endpoint.starts_with('[') && endpoint.ends_with(']') {
        &endpoint[1..endpoint.len() - 1]
    } else {
        endpoint
    };
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if host.contains(':') || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn validate_dns_servers(dns: &str) -> bool {
    let servers: Vec<&str> = dns.split(',').map(str::trim).collect();
    !servers.is_empty()
        && servers.iter().all(|server| !server.is_empty() && server.parse::<IpAddr>().is_ok())
}

fn validate_transport(protocol: &str, transport: &str) -> Result<(), &'static str> {
    match protocol {
        "amnezia-awg" | "wireguard" if transport != "udp" => {
            Err("AmneziaWG and WireGuard require UDP transport")
        }
        "openvpn-cloak" if transport != "tcp" => {
            Err("OpenVPN over Cloak requires TCP transport")
        }
        _ => Ok(()),
    }
}

fn subnets_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    let left_start = u32::from(left.network());
    let left_end = u32::from(left.broadcast());
    let right_start = u32::from(right.network());
    let right_end = u32::from(right.broadcast());
    left_start <= right_end && right_start <= left_end
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<ContainerList>, StatusCode> {
    authenticated_admin(&state, &jar).await?;
    let items = sqlx::query_as::<_, ContainerRecord>(
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json, wireguard_server_public_key, (awg_header_protection_key_encrypted IS NOT NULL) AS awg_header_protection_key_configured FROM protocol_containers ORDER BY created_at DESC"
    )
    .fetch_all(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ContainerList { items }))
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<CreateContainerRequest>,
) -> Result<Json<CreateContainerResponse>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;

    let name = input.name.trim();
    if !(2..=48).contains(&name.len()) {
        return Err((StatusCode::BAD_REQUEST, "Name must be 2-48 characters"));
    }
    if !["amnezia-awg", "wireguard", "openvpn", "openvpn-cloak"].contains(&input.protocol.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "Unsupported VPN protocol"));
    }
    let endpoint = input.endpoint.trim();
    if !validate_endpoint(endpoint) {
        return Err((StatusCode::BAD_REQUEST, "Endpoint must be a valid hostname or IP address"));
    }
    if !["udp", "tcp"].contains(&input.transport.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "Transport must be udp or tcp"));
    }
    validate_transport(&input.protocol, &input.transport)
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    if !(576..=9000).contains(&input.mtu) {
        return Err((StatusCode::BAD_REQUEST, "MTU must be between 576 and 9000"));
    }
    if input.dns.len() > 128 || !validate_dns_servers(&input.dns) {
        return Err((StatusCode::BAD_REQUEST, "DNS must be a comma-separated list of IPv4 or IPv6 addresses"));
    }
    let awg_settings = match (input.protocol.as_str(), input.awg_settings) {
        ("amnezia-awg", Some(settings)) => {
            settings.validate().map_err(|message| (StatusCode::BAD_REQUEST, message))?;
            serde_json::to_string(&settings).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not serialize AWG settings"))?
        }
        ("amnezia-awg", None) => "{}".to_string(),
        (_, Some(_)) => return Err((StatusCode::BAD_REQUEST, "AWG settings are only valid for AmneziaWG")),
        (_, None) => "{}".to_string(),
    };

    let subnet = Ipv4Net::from_str(input.subnet.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Subnet must be a valid IPv4 CIDR"))?;
    if !(16..=30).contains(&subnet.prefix_len()) {
        return Err((StatusCode::BAD_REQUEST, "Subnet size must be between /16 and /30"));
    }

    let existing_subnets = sqlx::query_scalar::<_, String>("SELECT subnet FROM protocol_containers")
        .fetch_all(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not check existing subnets"))?;
    for existing in existing_subnets {
        let existing = Ipv4Net::from_str(&existing)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "An existing container has an invalid subnet"))?;
        if subnets_overlap(subnet, existing) {
            return Err((StatusCode::CONFLICT, "Subnet overlaps with another VPN container"));
        }
    }

    let id = Uuid::new_v4().to_string();
    let result = sqlx::query(
        "INSERT INTO protocol_containers (id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, awg_settings_json) VALUES (?, ?, ?, 'preview', ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id).bind(name).bind(&input.protocol).bind(endpoint)
    .bind(i64::from(input.listen_port)).bind(&input.transport)
    .bind(subnet.to_string()).bind(input.dns.trim()).bind(i64::from(input.mtu)).bind(awg_settings)
    .execute(&state.pool).await;

    if let Err(error) = result {
        if let sqlx::Error::Database(db_error) = &error {
            if db_error.is_unique_violation() {
                return Err((StatusCode::CONFLICT, "A container with this name already exists"));
            }
        }
        tracing::error!("Failed to create preview container: {error}");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not save container"));
    }

    let item = sqlx::query_as::<_, ContainerRecord>(
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json, wireguard_server_public_key, (awg_header_protection_key_encrypted IS NOT NULL) AS awg_header_protection_key_configured FROM protocol_containers WHERE id = ?"
    ).bind(&id).fetch_one(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read saved container"))?;

    let details = serde_json::json!({"container_id": id, "protocol": input.protocol}).to_string();
    let _ = sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'container.created', ?)")
        .bind(admin_id).bind(details).execute(&state.pool).await;

    Ok(Json(CreateContainerResponse {
        item,
        runtime_mode: "preview",
        notice: "Saved to the local database. No VPN process or Docker container has been started.",
    }))
}


#[derive(Deserialize)]
pub struct UpdateAwgProfileRequest {
    expected_revision: i64,
    settings: AwgSettings,
}

/// Update AWG metadata using optimistic concurrency. This deliberately does not
/// apply the profile to a running interface; runtime synchronization is separate.
pub async fn update_awg_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(container_id): axum::extract::Path<String>,
    Json(input): Json<UpdateAwgProfileRequest>,
) -> Result<Json<ContainerRecord>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    input.settings.validate()
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let settings_json = serde_json::to_string(&input.settings)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not serialize AWG settings"))?;

    let mut tx = state.pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not begin profile update"))?;
    let has_header_protection_key = sqlx::query_scalar::<_, bool>(
        "SELECT awg_header_protection_key_encrypted IS NOT NULL FROM protocol_containers WHERE id = ? AND protocol = 'amnezia-awg'"
    ).bind(&container_id).fetch_optional(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read AWG profile state"))?
        .ok_or((StatusCode::NOT_FOUND, "AmneziaWG profile not found"))?;
    if has_header_protection_key {
        input.settings.validate_header_protection()
            .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    }
    let result = sqlx::query(
        "UPDATE protocol_containers SET awg_settings_json = ?, revision = revision + 1 WHERE id = ? AND protocol = 'amnezia-awg' AND revision = ?"
    )
    .bind(settings_json)
    .bind(&container_id)
    .bind(input.expected_revision)
    .execute(&mut *tx).await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not update AWG profile"))?;

    if result.rows_affected() == 0 {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM protocol_containers WHERE id = ? AND protocol = 'amnezia-awg'"
        ).bind(&container_id).fetch_one(&mut *tx).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        if exists == 0 {
            return Err((StatusCode::NOT_FOUND, "AmneziaWG profile not found"));
        }
        return Err((StatusCode::CONFLICT, "Profile revision changed; refresh and retry your edit"));
    }

    let details = serde_json::json!({
        "container_id": container_id,
        "revision": input.expected_revision + 1,
        "runtime_applied": false
    }).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'awg.profile.updated', ?)")
        .bind(admin_id).bind(details).execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not record profile update"))?;
    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not commit profile update"))?;

    let item = sqlx::query_as::<_, ContainerRecord>(
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json, wireguard_server_public_key, (awg_header_protection_key_encrypted IS NOT NULL) AS awg_header_protection_key_configured FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_one(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read updated profile"))?;
    Ok(Json(item))
}


/// Generate and store the server identity for a WireGuard-compatible profile.
/// The private key is encrypted before it reaches SQLite and never returned.
pub async fn provision_wireguard_server_key(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(container_id): axum::extract::Path<String>,
) -> Result<Json<ContainerRecord>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let master_key = state.wireguard_master_key.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Set WIREGUARD_MASTER_KEY before provisioning server keys"))?;

    let protocol = sqlx::query_scalar::<_, String>(
        "SELECT protocol FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_optional(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or((StatusCode::NOT_FOUND, "VPN profile not found"))?;
    if protocol != "wireguard" && protocol != "amnezia-awg" {
        return Err((StatusCode::BAD_REQUEST, "Server keys are only supported for WireGuard and AmneziaWG profiles"));
    }

    let (private_key, public_key) = crate::security::wireguard_keys::generate_keypair();
    let encrypted = crate::security::wireguard_keys::encrypt_private_key(master_key, &private_key)
        .map_err(|message| (StatusCode::INTERNAL_SERVER_ERROR, message))?;

    let mut tx = state.pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not begin key provisioning"))?;
    let result = sqlx::query(
        "UPDATE protocol_containers SET wireguard_server_public_key = ?, wireguard_server_private_key_encrypted = ?, revision = revision + 1 WHERE id = ? AND wireguard_server_public_key IS NULL"
    ).bind(&public_key).bind(&encrypted).bind(&container_id)
        .execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not save server keys"))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::CONFLICT, "Server keys already exist; key rotation requires a separate procedure"));
    }

    let details = serde_json::json!({"container_id": container_id, "protocol": protocol, "revision_incremented": true}).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'wireguard.server_key.provisioned', ?)")
        .bind(admin_id).bind(details).execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not record key provisioning"))?;
    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not commit server keys"))?;

    let item = sqlx::query_as::<_, ContainerRecord>(
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json, wireguard_server_public_key, (awg_header_protection_key_encrypted IS NOT NULL) AS awg_header_protection_key_configured FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_one(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read provisioned profile"))?;
    Ok(Json(item))
}


/// Generate a one-time AWG 3.1 HeaderProtectionKey and store it encrypted.
/// The secret itself is never included in API responses or audit records.
pub async fn provision_awg_header_protection_key(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(container_id): axum::extract::Path<String>,
) -> Result<Json<ContainerRecord>, (StatusCode, &'static str)> {
    let (admin_id, _) = authenticated_admin(&state, &jar).await
        .map_err(|status| (status, "Authentication required"))?;
    let master_key = state.wireguard_master_key.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Set WIREGUARD_MASTER_KEY before provisioning AWG header protection"))?;

    let mut tx = state.pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not begin header protection provisioning"))?;
    let profile = sqlx::query_as::<_, (String, bool)>(
        "SELECT awg_settings_json, awg_header_protection_key_encrypted IS NOT NULL FROM protocol_containers WHERE id = ? AND protocol = 'amnezia-awg'"
    ).bind(&container_id).fetch_optional(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read AWG profile"))?
        .ok_or((StatusCode::NOT_FOUND, "AmneziaWG profile not found"))?;
    if profile.1 {
        return Err((StatusCode::CONFLICT, "HeaderProtectionKey is already provisioned; key rotation requires a separate procedure"));
    }
    let settings: AwgSettings = serde_json::from_str(&profile.0)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stored AWG profile is invalid"))?;
    settings.validate()
        .map_err(|_| (StatusCode::CONFLICT, "Save a valid AmneziaWG 3.1 profile before provisioning HeaderProtectionKey"))?;
    settings.validate_header_protection()
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;

    let secret = crate::security::wireguard_keys::generate_header_protection_key();
    let encrypted = crate::security::wireguard_keys::encrypt_header_protection_key(master_key, &secret)
        .map_err(|message| (StatusCode::INTERNAL_SERVER_ERROR, message))?;
    let result = sqlx::query(
        "UPDATE protocol_containers SET awg_header_protection_key_encrypted = ?, revision = revision + 1 WHERE id = ? AND protocol = 'amnezia-awg' AND awg_header_protection_key_encrypted IS NULL"
    ).bind(&encrypted).bind(&container_id)
        .execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not save HeaderProtectionKey"))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::CONFLICT, "HeaderProtectionKey was provisioned concurrently"));
    }

    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_one(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read updated revision"))?;
    let details = serde_json::json!({
        "container_id": container_id,
        "revision": revision,
        "secret_returned": false
    }).to_string();
    sqlx::query("INSERT INTO audit_events (actor_admin_id, action, details_json) VALUES (?, 'awg.header_protection_key.provisioned', ?)")
        .bind(admin_id).bind(details).execute(&mut *tx).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not record HeaderProtectionKey provisioning"))?;
    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not commit HeaderProtectionKey"))?;

    let item = sqlx::query_as::<_, ContainerRecord>(
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json, wireguard_server_public_key, (awg_header_protection_key_encrypted IS NOT NULL) AS awg_header_protection_key_configured FROM protocol_containers WHERE id = ?"
    ).bind(&container_id).fetch_one(&state.pool).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Could not read provisioned AWG profile"))?;
    Ok(Json(item))
}

#[cfg(test)]
mod tests {
    use super::{
        subnets_overlap, validate_dns_servers, validate_endpoint, validate_transport,
        AwgSettings, AwgUint32Range,
    };
    use std::str::FromStr;
    use ipnet::Ipv4Net;

    #[test]
    fn rejects_endpoint_injection_and_accepts_ip_or_hostname() {
        assert!(validate_endpoint("vpn.example.com"));
        assert!(validate_endpoint("vpn-1.example.net"));
        assert!(validate_endpoint("192.0.2.10"));
        assert!(validate_endpoint("2001:db8::1"));
        assert!(validate_endpoint("[2001:db8::1]"));
        assert!(!validate_endpoint("vpn.example.com\nAddress=0.0.0.0/0"));
        assert!(!validate_endpoint("vpn;touch /tmp/pwned"));
        assert!(!validate_endpoint("bad host.example"));
        assert!(!validate_endpoint("-bad.example"));
    }

    #[test]
    fn accepts_only_literal_dns_server_addresses() {
        assert!(validate_dns_servers("1.1.1.1"));
        assert!(validate_dns_servers("1.1.1.1, 8.8.8.8"));
        assert!(validate_dns_servers("2606:4700:4700::1111"));
        assert!(!validate_dns_servers("1.1.1.1\nPrivateKey=bad"));
        assert!(!validate_dns_servers("dns.example.com"));
        assert!(!validate_dns_servers("1.1.1.1,"));
    }

    #[test]
    fn enforces_protocol_transport_compatibility() {
        assert!(validate_transport("amnezia-awg", "udp").is_ok());
        assert!(validate_transport("wireguard", "udp").is_ok());
        assert!(validate_transport("openvpn", "tcp").is_ok());
        assert!(validate_transport("openvpn", "udp").is_ok());
        assert!(validate_transport("amnezia-awg", "tcp").is_err());
        assert!(validate_transport("wireguard", "tcp").is_err());
        assert!(validate_transport("openvpn-cloak", "udp").is_err());
        assert!(validate_transport("openvpn-cloak", "tcp").is_ok());
    }

    #[test]
    fn rejects_identical_and_nested_subnets() {
        let a = Ipv4Net::from_str("10.20.0.0/24").unwrap();
        let same = Ipv4Net::from_str("10.20.0.0/24").unwrap();
        let nested = Ipv4Net::from_str("10.20.0.128/25").unwrap();
        assert!(subnets_overlap(a, same));
        assert!(subnets_overlap(a, nested));
    }

    #[test]
    fn allows_adjacent_and_disjoint_subnets() {
        let a = Ipv4Net::from_str("10.20.0.0/24").unwrap();
        let adjacent = Ipv4Net::from_str("10.20.1.0/24").unwrap();
        let distant = Ipv4Net::from_str("192.168.10.0/24").unwrap();
        assert!(!subnets_overlap(a, adjacent));
        assert!(!subnets_overlap(a, distant));
    }

    #[test]
    fn validates_awg_obfuscation_constraints() {
        let settings = AwgSettings {
            version: "2.0".into(), jc: Some(5), jmin: Some(8), jmax: Some(80),
            s1: Some(32), s2: Some(64), s3: Some(16), s4: Some(8),
            h1: Some("1000-2000".into()), h2: Some("3000-4000".into()),
            h3: Some("5000".into()), h4: Some("6000".into()),
            ..Default::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn rejects_overlapping_awg_header_ranges() {
        let settings = AwgSettings {
            version: "2.0".into(), h1: Some("1000-2000".into()),
            h2: Some("1900-3000".into()), ..Default::default()
        };
        assert_eq!(settings.validate(), Err("H1-H4 values and ranges must not overlap"));
    }

    #[test]
    fn rejects_invalid_junk_and_padding_values() {
        let junk = AwgSettings { version: "2.0".into(), jmin: Some(80), jmax: Some(80), ..Default::default() };
        assert!(junk.validate().is_err());
        let padding = AwgSettings { version: "2.0".into(), s1: Some(10), s2: Some(66), ..Default::default() };
        assert!(padding.validate().is_err());
    }

    #[test]
    fn gates_transport_protection_options_to_awg31() {
        let legacy = AwgSettings {
            version: "2.0".into(), random_trailers: true, ..Default::default()
        };
        assert!(legacy.validate().is_err());
        let modern = AwgSettings {
            version: "3.1".into(), content_padding_addition: Some(AwgUint32Range::Number(16)),
            random_trailers: true, disable_cookies: true, ..Default::default()
        };
        assert!(modern.validate().is_ok());
    }

    #[test]
    fn validates_awg31_content_padding_uint32_and_ranges() {
        for value in [
            AwgUint32Range::Number(u32::MAX),
            AwgUint32Range::Range("16".into()),
            AwgUint32Range::Range("16-32".into()),
            AwgUint32Range::Range("(off)".into()),
        ] {
            let settings = AwgSettings {
                version: "3.1".into(),
                content_padding_addition: Some(value),
                ..Default::default()
            };
            assert!(settings.validate().is_ok());
        }

        for value in [
            AwgUint32Range::Range("32-16".into()),
            AwgUint32Range::Range("4294967296".into()),
            AwgUint32Range::Range("1-4294967296".into()),
            AwgUint32Range::Range("".into()),
        ] {
            let settings = AwgSettings {
                version: "3.1".into(),
                content_padding_addition: Some(value),
                ..Default::default()
            };
            assert!(settings.validate().is_err());
        }
    }

    #[test]
    fn header_protection_requires_awg31_and_all_four_paddings_at_least_12() {
        let valid = AwgSettings {
            version: "3.1".into(),
            s1: Some(12), s2: Some(12), s3: Some(12), s4: Some(12),
            ..Default::default()
        };
        assert!(valid.validate_header_protection().is_ok());

        for invalid in [
            AwgSettings { version: "2.0".into(), s1: Some(12), s2: Some(12), s3: Some(12), s4: Some(12), ..Default::default() },
            AwgSettings { version: "3.1".into(), s1: Some(12), s2: Some(12), s3: Some(12), s4: None, ..Default::default() },
            AwgSettings { version: "3.1".into(), s1: Some(12), s2: Some(11), s3: Some(12), s4: Some(12), ..Default::default() },
            AwgSettings { version: "3.1".into(), s1: Some(12), s2: Some(12), s3: Some(0), s4: Some(12), ..Default::default() },
        ] {
            assert!(invalid.validate_header_protection().is_err());
        }
    }

    #[test]
    fn rejects_malformed_cps_signature_tags() {
        for malformed in [
            "not-a-tag",
            "<r 4>\nPrivateKey=bad<r 4>",
            "<unknown 4>",
            "<r 0>",
            "<b 0x1>",
            "<b 0xzz>",
            "<t",
        ] {
            let settings = AwgSettings {
                version: "1.5".into(), i1: Some(malformed.into()), ..Default::default()
            };
            assert!(settings.validate().is_err(), "accepted malformed signature {malformed:?}");
        }
        let valid = AwgSettings {
            version: "1.5".into(), i1: Some("<r 128><t><b 0x0102ff>".into()), ..Default::default()
        };
        assert!(valid.validate().is_ok());
    }
}
