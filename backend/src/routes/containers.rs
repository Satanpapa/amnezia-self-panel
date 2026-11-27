use std::{collections::HashSet, str::FromStr};

use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::CookieJar;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::state::AppState;
use super::auth::authenticated_admin;

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
    pub content_padding_addition: Option<u16>,
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
            if signature.len() > 1024 || !signature.starts_with('<') || !signature.ends_with('>') {
                return Err("I1-I5 signatures must be at most 1024 characters and use Amnezia tag syntax");
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
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json FROM protocol_containers ORDER BY created_at DESC"
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
    if endpoint.is_empty() || endpoint.len() > 253 || endpoint.chars().any(char::is_whitespace) {
        return Err((StatusCode::BAD_REQUEST, "Endpoint must be a hostname or IP address"));
    }
    if !["udp", "tcp"].contains(&input.transport.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "Transport must be udp or tcp"));
    }
    if !(576..=9000).contains(&input.mtu) {
        return Err((StatusCode::BAD_REQUEST, "MTU must be between 576 and 9000"));
    }
    if input.dns.trim().is_empty() || input.dns.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "DNS must be 1-128 characters"));
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
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at, awg_settings_json FROM protocol_containers WHERE id = ?"
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

#[cfg(test)]
mod tests {
    use super::{subnets_overlap, AwgSettings};
    use std::str::FromStr;
    use ipnet::Ipv4Net;

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
            version: "3.1".into(), content_padding_addition: Some(16),
            random_trailers: true, disable_cookies: true, ..Default::default()
        };
        assert!(modern.validate().is_ok());
    }

    #[test]
    fn rejects_malformed_cps_signature_tags() {
        let malformed = AwgSettings {
            version: "1.5".into(), i1: Some("not-a-tag".into()), ..Default::default()
        };
        assert!(malformed.validate().is_err());
    }
}
