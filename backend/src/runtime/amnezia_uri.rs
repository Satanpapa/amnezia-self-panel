use std::{fmt::Write as FmtWrite, io::{Read, Write}};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use qrcodegen::{QrCode, QrCodeEcc};
use zeroize::Zeroizing;

const MAX_PROFILE_BYTES: usize = 2 * 1024 * 1024;

/// Encode the Amnezia client import envelope:
/// 4-byte big-endian uncompressed length + zlib stream, then URL-safe Base64.
/// The URI intentionally contains client credentials and must be treated as a secret.
pub fn encode_vpn_uri(payload: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    if payload.is_empty() {
        return Err("Amnezia profile payload is empty");
    }
    if payload.len() > MAX_PROFILE_BYTES || payload.len() > u32::MAX as usize {
        return Err("Amnezia profile payload exceeds the 2 MiB export limit");
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(8));
    encoder.write_all(payload)
        .map_err(|_| "Could not compress Amnezia profile")?;
    let compressed = Zeroizing::new(
        encoder.finish().map_err(|_| "Could not finish Amnezia profile compression")?
    );

    let mut envelope = Zeroizing::new(Vec::with_capacity(4 + compressed.len()));
    envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&compressed);

    let encoded = URL_SAFE_NO_PAD.encode(&*envelope);
    Ok(Zeroizing::new(format!("vpn://{encoded}")))
}

/// Render a `vpn://` URI as an SVG QR image.
/// The image contains the same secret as the URI and must be served no-store.
pub fn encode_qr_svg(vpn_uri: &str) -> Result<Zeroizing<String>, &'static str> {
    if !vpn_uri.starts_with("vpn://") || vpn_uri.len() <= "vpn://".len() {
        return Err("A valid Amnezia vpn:// URI is required for QR generation");
    }

    let qr = QrCode::encode_text(vpn_uri, QrCodeEcc::Low)
        .map_err(|_| "The Amnezia profile is too large for a single QR code")?;
    let size = qr.size();
    let quiet_zone = 4;
    let view_size = size + quiet_zone * 2;
    let mut path = String::new();

    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                let x = x + quiet_zone;
                let y = y + quiet_zone;
                write!(&mut path, "M{x},{y}h1v1h-1z")
                    .map_err(|_| "Could not render Amnezia QR path")?;
            }
        }
    }

    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"512\" height=\"512\" viewBox=\"0 0 {view_size} {view_size}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><path fill=\"#000\" d=\"{path}\"/></svg>"
    );
    Ok(Zeroizing::new(svg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encodes_qcompress_compatible_url_safe_envelope() {
        let payload = br#"{"format_version":1,"defaultContainer":"amnezia-awg"}"#;
        let uri = encode_vpn_uri(payload).unwrap();
        let encoded = uri.strip_prefix("vpn://").unwrap();
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let envelope = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        assert!(envelope.len() > 4);
        assert_eq!(
            u32::from_be_bytes(envelope[..4].try_into().unwrap()) as usize,
            payload.len()
        );

        let mut decoder = ZlibDecoder::new(&envelope[4..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&decoded).unwrap(),
            json!({"format_version": 1, "defaultContainer": "amnezia-awg"})
        );
    }

    #[test]
    fn preserves_native_awg_config_payload_for_import() {
        let native_config = br#"[Interface]
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.66.0.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 5
Jmin = 8
Jmax = 80
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
PresharedKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=

[Peer]
PublicKey = ccccccccccccccccccccccccccccccccccccccccccc=
Endpoint = vpn.example.com:443
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"#;
        let uri = encode_vpn_uri(native_config).unwrap();
        let encoded = uri.strip_prefix("vpn://").unwrap();
        let envelope = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let mut decoded = Vec::new();
        ZlibDecoder::new(&envelope[4..]).read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, native_config);
        let text = String::from_utf8(decoded).unwrap();
        assert!(text.starts_with("[Interface]"));
        assert!(text.contains("Jc = 5"));
        assert!(text.contains("PresharedKey = "));
        assert!(text.contains("[Peer]"));
        assert!(text.ends_with("PersistentKeepalive = 25\n"));
    }

    #[test]
    fn renders_a_valid_svg_qr_for_vpn_uri() {
        let uri = encode_vpn_uri(b"[Interface]\nPrivateKey = test\n").unwrap();
        let svg = encode_qr_svg(&uri).unwrap();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("viewBox=\"0 0 "));
        assert!(svg.contains("<path fill=\"#000\" d=\"M"));
        assert!(svg.ends_with("</svg>"));
        assert!(!svg.contains("PrivateKey"));
    }

    #[test]
    fn rejects_non_vpn_qr_payloads() {
        assert_eq!(
            encode_qr_svg("not-a-vpn-uri").unwrap_err(),
            "A valid Amnezia vpn:// URI is required for QR generation"
        );
    }

    #[test]
    fn rejects_empty_and_oversized_payloads() {
        assert_eq!(encode_vpn_uri(b"").unwrap_err(), "Amnezia profile payload is empty");
        let too_large = vec![b'x'; MAX_PROFILE_BYTES + 1];
        assert_eq!(
            encode_vpn_uri(&too_large).unwrap_err(),
            "Amnezia profile payload exceeds the 2 MiB export limit"
        );
    }
}
