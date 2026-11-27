use std::str::FromStr;

use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::cookie::CookieJar;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::state::AppState;
use super::auth::authenticated_admin;

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
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at FROM protocol_containers ORDER BY created_at DESC"
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
    let subnet = Ipv4Net::from_str(input.subnet.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Subnet must be a valid IPv4 CIDR"))?;
    if !(16..=30).contains(&subnet.prefix_len()) {
        return Err((StatusCode::BAD_REQUEST, "Subnet size must be between /16 and /30"));
    }

    // Different VPN instances must not allocate addresses from overlapping pools.
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
        "INSERT INTO protocol_containers (id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu) VALUES (?, ?, ?, 'preview', ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id).bind(name).bind(&input.protocol).bind(endpoint)
    .bind(i64::from(input.listen_port)).bind(&input.transport)
    .bind(subnet.to_string()).bind(input.dns.trim()).bind(i64::from(input.mtu))
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
        "SELECT id, name, protocol, status, endpoint, listen_port, transport, subnet, dns, mtu, revision, created_at FROM protocol_containers WHERE id = ?"
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
    use super::subnets_overlap;
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
}
