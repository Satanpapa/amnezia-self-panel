use std::{fmt::Write as _, net::Ipv4Addr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ipnet::Ipv4Net;
use zeroize::Zeroizing;

use crate::routes::containers::{AwgSettings, AwgPaddingRange};

#[derive(Debug, Clone, Copy)]
pub struct ConfigPeer<'a> {
    pub public_key: &'a str,
    pub assigned_ip: Ipv4Addr,
}

pub struct ServerConfigInput<'a> {
    pub protocol: &'a str,
    pub private_key: &'a [u8; 32],
    pub subnet: Ipv4Net,
    pub listen_port: u16,
    pub mtu: u16,
    pub peers: &'a [ConfigPeer<'a>],
    pub awg_settings: Option<&'a AwgSettings>,
    pub header_protection_key: Option<&'a [u8; 32]>,
}

pub struct ClientConfigInput<'a> {
    pub protocol: &'a str,
    pub private_key: &'a [u8; 32],
    pub assigned_ip: Ipv4Addr,
    pub dns: &'a str,
    pub endpoint: &'a str,
    pub listen_port: u16,
    pub mtu: u16,
    pub server_public_key: &'a str,
    pub awg_settings: Option<&'a AwgSettings>,
    pub header_protection_key: Option<&'a [u8; 32]>,
    pub persistent_keepalive: u16,
}

fn encode_key(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(key))
}

fn append_common_awg(
    output: &mut Zeroizing<String>,
    settings: &AwgSettings,
    header_protection_key: Option<&[u8; 32]>,
) {
    for (name, value) in [("S1", settings.s1), ("S2", settings.s2), ("S3", settings.s3), ("S4", settings.s4)] {
        if let Some(value) = value {
            let _ = writeln!(output, "{name} = {value}");
        }
    }
    for (name, value) in [
        ("H1", settings.h1.as_deref()),
        ("H2", settings.h2.as_deref()),
        ("H3", settings.h3.as_deref()),
        ("H4", settings.h4.as_deref()),
    ] {
        if let Some(value) = value {
            let _ = writeln!(output, "{name} = {value}");
        }
    }
    if settings.random_trailers {
        let _ = writeln!(output, "RandomTrailers = on");
    }
    if let Some(key) = header_protection_key {
        let encoded = encode_key(key);
        let _ = writeln!(output, "HeaderProtectionKey = {}", encoded.as_str());
    }
}

fn append_content_padding(output: &mut Zeroizing<String>, settings: &AwgSettings) {
    // The upstream AWG guide recommends configuring content padding on both ends.
    if let Some(value) = &settings.content_padding_addition {
        let rendered = match value {
            AwgPaddingRange::Number(value) => value.to_string(),
            AwgPaddingRange::Range(value) => value.clone(),
        };
        let _ = writeln!(output, "ContentPaddingAddition = {rendered}");
    }
}

/// Junk packets and CPS signatures are recommended on the initiating client.
/// DisableCookies is also client-side and removes under-load cookie protection,
/// so it is deliberately not copied into the server's device configuration.
fn append_client_awg(output: &mut Zeroizing<String>, settings: &AwgSettings) {
    for (name, value) in [("Jc", settings.jc), ("Jmin", settings.jmin), ("Jmax", settings.jmax)] {
        if let Some(value) = value {
            let _ = writeln!(output, "{name} = {value}");
        }
    }
    for (name, value) in [
        ("I1", settings.i1.as_deref()),
        ("I2", settings.i2.as_deref()),
        ("I3", settings.i3.as_deref()),
        ("I4", settings.i4.as_deref()),
        ("I5", settings.i5.as_deref()),
    ] {
        if let Some(value) = value {
            let _ = writeln!(output, "{name} = {value}");
        }
    }
    append_content_padding(output, settings);
    if settings.disable_cookies {
        let _ = writeln!(output, "DisableCookies = on");
    }
}

fn validate_protocol(protocol: &str) -> Result<(), &'static str> {
    match protocol {
        "wireguard" | "amnezia-awg" => Ok(()),
        _ => Err("Configuration renderer supports only WireGuard and AmneziaWG"),
    }
}

fn validate_key(key: &str) -> bool {
    STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 32)
}

fn server_interface_ip(subnet: Ipv4Net) -> Result<Ipv4Addr, &'static str> {
    subnet.hosts().next().ok_or("VPN subnet has no usable server address")
}

fn format_endpoint(endpoint: &str, port: u16) -> Result<String, &'static str> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.chars().any(|c| matches!(c, '\r' | '\n' | '\t' | ' ')) {
        return Err("VPN endpoint contains invalid characters");
    }
    let host = if endpoint.starts_with('[') && endpoint.ends_with(']') {
        &endpoint[1..endpoint.len() - 1]
    } else {
        endpoint
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(format!("[{host}]:{port}"))
    } else if host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        Ok(format!("{host}:{port}"))
    } else {
        Err("VPN endpoint must be an IPv4, IPv6 or valid hostname")
    }
}

fn validate_dns_list(dns: &str) -> bool {
    let values: Vec<&str> = dns.split(',').map(str::trim).collect();
    !values.is_empty()
        && values.len() <= 4
        && values.iter().all(|value| !value.is_empty() && value.parse::<std::net::IpAddr>().is_ok())
}

/// Render a server-side wg-quick/awg-quick configuration draft.
/// Firewall, NAT, IP forwarding and service supervision are intentionally separate.
pub fn render_server_config(input: &ServerConfigInput<'_>) -> Result<Zeroizing<String>, &'static str> {
    validate_protocol(input.protocol)?;
    if input.listen_port == 0 || !(576..=9000).contains(&input.mtu) {
        return Err("Server port or MTU is outside the supported range");
    }
    if input.protocol == "amnezia-awg" {
        let settings = input.awg_settings.ok_or("AmneziaWG profile settings are missing")?;
        settings.validate()?;
        if input.header_protection_key.is_some() {
            settings.validate_header_protection()?;
        }
    } else if input.awg_settings.is_some() || input.header_protection_key.is_some() {
        return Err("WireGuard configuration cannot include AmneziaWG settings");
    }

    let mut output = Zeroizing::new(String::with_capacity(2048));
    let private_key = encode_key(input.private_key);
    let server_ip = server_interface_ip(input.subnet)?;
    let _ = writeln!(output, "# Generated by Amnezia Panel; configure NAT and forwarding separately");
    let _ = writeln!(output, "[Interface]");
    let _ = writeln!(output, "Address = {server_ip}/{}", input.subnet.prefix_len());
    let _ = writeln!(output, "ListenPort = {}", input.listen_port);
    let _ = writeln!(output, "MTU = {}", input.mtu);
    let _ = writeln!(output, "PrivateKey = {}", private_key.as_str());

    if let Some(settings) = input.awg_settings {
        append_common_awg(&mut output, settings, input.header_protection_key);
        append_content_padding(&mut output, settings);
    }

    let mut seen_ips = std::collections::HashSet::new();
    let mut seen_keys = std::collections::HashSet::new();
    for peer in input.peers {
        if !input.subnet.contains(&peer.assigned_ip) || peer.assigned_ip == server_ip {
            return Err("Peer address must be a usable address inside the VPN subnet");
        }
        if !seen_ips.insert(peer.assigned_ip) || !seen_keys.insert(peer.public_key) {
            return Err("Server configuration contains duplicate peer addresses or keys");
        }
        if !validate_key(peer.public_key) {
            return Err("Peer public key must be a valid base64 32-byte key");
        }
        let _ = writeln!(output, "\n[Peer]");
        let _ = writeln!(output, "PublicKey = {}", peer.public_key);
        let _ = writeln!(output, "AllowedIPs = {}/32", peer.assigned_ip);
    }
    Ok(output)
}

/// Render a client-side .conf for a WireGuard-compatible client.
pub fn render_client_config(input: &ClientConfigInput<'_>) -> Result<Zeroizing<String>, &'static str> {
    validate_protocol(input.protocol)?;
    if input.listen_port == 0
        || !(576..=9000).contains(&input.mtu)
        || !validate_key(input.server_public_key)
        || !validate_dns_list(input.dns)
    {
        return Err("Client configuration contains invalid network parameters");
    }
    let endpoint = format_endpoint(input.endpoint, input.listen_port)?;
    if input.protocol == "amnezia-awg" {
        let settings = input.awg_settings.ok_or("AmneziaWG profile settings are missing")?;
        settings.validate()?;
        if input.header_protection_key.is_some() {
            settings.validate_header_protection()?;
        }
    } else if input.awg_settings.is_some() || input.header_protection_key.is_some() {
        return Err("WireGuard configuration cannot include AmneziaWG settings");
    }

    let private_key = encode_key(input.private_key);
    let mut output = Zeroizing::new(String::with_capacity(1024));
    let _ = writeln!(output, "# Generated by Amnezia Panel; review route policy before import");
    let _ = writeln!(output, "[Interface]");
    let _ = writeln!(output, "PrivateKey = {}", private_key.as_str());
    let _ = writeln!(output, "Address = {}/32", input.assigned_ip);
    let _ = writeln!(output, "DNS = {}", input.dns.trim());
    let _ = writeln!(output, "MTU = {}", input.mtu);

    if let Some(settings) = input.awg_settings {
        append_common_awg(&mut output, settings, input.header_protection_key);
        append_client_awg(&mut output, settings);
    }

    let _ = writeln!(output, "\n[Peer]");
    let _ = writeln!(output, "PublicKey = {}", input.server_public_key);
    let _ = writeln!(output, "Endpoint = {endpoint}");
    let _ = writeln!(output, "AllowedIPs = 0.0.0.0/0");
    if input.persistent_keepalive > 0 {
        let _ = writeln!(output, "PersistentKeepalive = {}", input.persistent_keepalive);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::containers::AwgSettings;

    fn settings() -> AwgSettings {
        AwgSettings {
            version: "3.1".into(),
            jc: Some(5),
            jmin: Some(8),
            jmax: Some(80),
            s1: Some(12),
            s2: Some(12),
            s3: Some(12),
            s4: Some(12),
            h1: Some("100".into()),
            h2: Some("200".into()),
            h3: Some("300".into()),
            h4: Some("400".into()),
            i1: Some("<r 8><t>".into()),
            content_padding_addition: Some(AwgPaddingRange::Range("16-32".into())),
            random_trailers: true,
            disable_cookies: true,
            ..Default::default()
        }
    }

    #[test]
    fn renders_server_and_client_awg_options_on_the_correct_side() {
        let private = [7u8; 32];
        let hpk = [8u8; 32];
        let pubkey = STANDARD.encode([9u8; 32]);
        let subnet = "10.66.0.0/24".parse().unwrap();
        let peers = [ConfigPeer { public_key: &pubkey, assigned_ip: Ipv4Addr::new(10, 66, 0, 2) }];
        let server_settings = settings();
        let server = render_server_config(&ServerConfigInput {
            protocol: "amnezia-awg",
            private_key: &private,
            subnet,
            listen_port: 443,
            mtu: 1280,
            peers: &peers,
            awg_settings: Some(&server_settings),
            header_protection_key: Some(&hpk),
        }).unwrap();
        assert!(server.contains("HeaderProtectionKey = "));
        assert!(server.contains("RandomTrailers = on"));
        assert!(server.contains("S4 = 12"));
        assert!(!server.contains("DisableCookies = on"));
        assert!(server.contains("ContentPaddingAddition = 16-32"));
        assert!(!server.contains("Jc = "));
        assert!(!server.contains("I1 = "));

        let client_settings = settings();
        let client = render_client_config(&ClientConfigInput {
            protocol: "amnezia-awg",
            private_key: &private,
            assigned_ip: Ipv4Addr::new(10, 66, 0, 2),
            dns: "1.1.1.1, 8.8.8.8",
            endpoint: "vpn.example.com",
            listen_port: 443,
            mtu: 1280,
            server_public_key: &pubkey,
            awg_settings: Some(&client_settings),
            header_protection_key: Some(&hpk),
            persistent_keepalive: 25,
        }).unwrap();
        assert!(client.contains("HeaderProtectionKey = "));
        assert!(client.contains("DisableCookies = on"));
        assert!(client.contains("ContentPaddingAddition = 16-32"));
        assert!(client.contains("Jc = 5"));
        assert!(client.contains("I1 = <r 8><t>"));
    }

    #[test]
    fn rejects_duplicate_or_out_of_subnet_server_peers() {
        let private = [7u8; 32];
        let pubkey_one = STANDARD.encode([9u8; 32]);
        let pubkey_two = STANDARD.encode([10u8; 32]);
        let subnet = "10.66.0.0/24".parse().unwrap();
        let peers = [
            ConfigPeer { public_key: &pubkey_one, assigned_ip: Ipv4Addr::new(10, 66, 0, 2) },
            ConfigPeer { public_key: &pubkey_two, assigned_ip: Ipv4Addr::new(10, 66, 0, 2) },
        ];
        let result = render_server_config(&ServerConfigInput {
            protocol: "wireguard",
            private_key: &private,
            subnet,
            listen_port: 51820,
            mtu: 1420,
            peers: &peers,
            awg_settings: None,
            header_protection_key: None,
        });
        assert!(matches!(result, Err("Server configuration contains duplicate peer addresses or keys")));
    }

    #[test]
    fn brackets_ipv6_endpoints_and_rejects_injection() {
        assert_eq!(format_endpoint("2001:db8::1", 443).unwrap(), "[2001:db8::1]:443");
        assert!(format_endpoint("vpn.example.com\nPrivateKey=bad", 443).is_err());
    }
}
