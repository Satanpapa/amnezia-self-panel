use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const KEY_ENVELOPE_VERSION: &[u8; 4] = b"WGK1";
const HEADER_PROTECTION_ENVELOPE_VERSION: &[u8; 4] = b"HPK1";
const PEER_PRESHARED_KEY_ENVELOPE_VERSION: &[u8; 4] = b"PSK1";

/// Generate a WireGuard-compatible Curve25519 keypair.
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        Zeroizing::new(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    )
}

/// Derive the public key corresponding to a stored WireGuard-compatible private key.
pub fn public_key_from_private(private_key: &[u8; 32]) -> String {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(&secret);
    STANDARD.encode(public.as_bytes())
}

/// Encrypt a private key with an installation master key.
/// Stored format: version tag || 12-byte random nonce || authenticated ciphertext.
pub fn encrypt_private_key(master_key: &[u8; 32], private_key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| "Invalid WireGuard master key")?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, private_key.as_ref())
        .map_err(|_| "Could not encrypt WireGuard private key")?;
    let mut stored = Vec::with_capacity(KEY_ENVELOPE_VERSION.len() + nonce_bytes.len() + ciphertext.len());
    stored.extend_from_slice(KEY_ENVELOPE_VERSION);
    stored.extend_from_slice(&nonce_bytes);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Generate a cryptographically random WireGuard peer preshared key.
pub fn generate_peer_preshared_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

/// Generate a cryptographically random 32-byte AmneziaWG header-protection key.
pub fn generate_header_protection_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

/// Encrypt a header-protection secret with a distinct versioned envelope.
pub fn encrypt_header_protection_key(
    master_key: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    encrypt_versioned_secret(master_key, secret, HEADER_PROTECTION_ENVELOPE_VERSION)
}

/// Encrypt a peer preshared key with a distinct PSK1 envelope and AAD.
pub fn encrypt_peer_preshared_key(
    master_key: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    encrypt_versioned_secret(master_key, secret, PEER_PRESHARED_KEY_ENVELOPE_VERSION)
}

fn encrypt_versioned_secret(
    master_key: &[u8; 32],
    secret: &[u8; 32],
    version: &[u8; 4],
) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| "Invalid WireGuard master key")?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, Payload { msg: &secret[..], aad: version })
        .map_err(|_| "Could not encrypt header-protection key")?;
    let mut stored = Vec::with_capacity(version.len() + nonce_bytes.len() + ciphertext.len());
    stored.extend_from_slice(version);
    stored.extend_from_slice(&nonce_bytes);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Decrypt a peer preshared key only for an authorized runtime/config path.
pub fn decrypt_peer_preshared_key(
    master_key: &[u8; 32],
    stored: &[u8],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    decrypt_versioned_secret(master_key, stored, PEER_PRESHARED_KEY_ENVELOPE_VERSION)
}

/// Decrypt the header-protection key only for an authorized runtime/config path.
pub fn decrypt_header_protection_key(
    master_key: &[u8; 32],
    stored: &[u8],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    decrypt_versioned_secret(master_key, stored, HEADER_PROTECTION_ENVELOPE_VERSION)
}

fn decrypt_versioned_secret(
    master_key: &[u8; 32],
    stored: &[u8],
    expected_version: &[u8; 4],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if stored.len() < 4 + 12 + 16 {
        return Err("Encrypted header-protection key is truncated");
    }
    if &stored[..4] != expected_version {
        return Err("Unsupported encrypted header-protection key format");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| "Invalid WireGuard master key")?;
    let nonce = Nonce::from_slice(&stored[4..16]);
    let plaintext = Zeroizing::new(
        cipher.decrypt(nonce, Payload { msg: &stored[16..], aad: expected_version })
            .map_err(|_| "Could not authenticate encrypted header-protection key")?
    );
    let key: [u8; 32] = plaintext.as_slice().try_into()
        .map_err(|_| "Decrypted header-protection key has an invalid length")?;
    Ok(Zeroizing::new(key))
}

/// Decrypt a stored private key for an authorized configuration-export path.
/// Plaintext buffers are zeroized when dropped.
pub fn decrypt_private_key(master_key: &[u8; 32], stored: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if stored.len() < 4 + 12 + 16 {
        return Err("Encrypted WireGuard private key is truncated");
    }
    if &stored[..4] != KEY_ENVELOPE_VERSION {
        return Err("Unsupported encrypted WireGuard private-key format");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| "Invalid WireGuard master key")?;
    let nonce = Nonce::from_slice(&stored[4..16]);
    let plaintext = Zeroizing::new(
        cipher.decrypt(nonce, &stored[16..])
            .map_err(|_| "Could not authenticate encrypted WireGuard private key")?
    );
    let key: [u8; 32] = plaintext.as_slice().try_into()
        .map_err(|_| "Decrypted WireGuard private key has an invalid length")?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_protection_key_is_random_and_uses_separate_authenticated_envelope() {
        let master = [9u8; 32];
        let first = generate_header_protection_key();
        let second = generate_header_protection_key();
        assert_ne!(&*first, &*second);

        let encrypted_a = encrypt_header_protection_key(&master, &first).unwrap();
        let encrypted_b = encrypt_header_protection_key(&master, &first).unwrap();
        assert_ne!(encrypted_a, encrypted_b);
        assert_eq!(&encrypted_a[..4], b"HPK1");
        assert_eq!(&*decrypt_header_protection_key(&master, &encrypted_a).unwrap(), &*first);
        assert!(decrypt_header_protection_key(&[8u8; 32], &encrypted_a).is_err());

        let mut tampered = encrypted_a.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_header_protection_key(&master, &tampered).is_err());
        assert!(decrypt_private_key(&master, &encrypted_a).is_err());
        assert!(decrypt_header_protection_key(&master, &encrypt_private_key(&master, &[0u8; 32]).unwrap()).is_err());
        let mut wrong_version = encrypted_a.clone();
        wrong_version[..4].copy_from_slice(b"WGK1");
        assert!(decrypt_header_protection_key(&master, &wrong_version).is_err());
    }

    #[test]
    fn peer_preshared_keys_use_separate_authenticated_envelope() {
        let master = [11_u8; 32];
        let first = generate_peer_preshared_key();
        let second = generate_peer_preshared_key();
        assert_ne!(&*first, &*second);

        let encrypted = encrypt_peer_preshared_key(&master, &first).unwrap();
        assert_eq!(&encrypted[..4], b"PSK1");
        assert_eq!(&*decrypt_peer_preshared_key(&master, &encrypted).unwrap(), &*first);
        assert!(decrypt_peer_preshared_key(&[12_u8; 32], &encrypted).is_err());
        assert!(decrypt_private_key(&master, &encrypted).is_err());
        assert!(decrypt_header_protection_key(&master, &encrypted).is_err());
        assert!(decrypt_peer_preshared_key(&master, &encrypt_header_protection_key(&master, &first).unwrap()).is_err());

        let mut tampered = encrypted;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_peer_preshared_key(&master, &tampered).is_err());
    }

    #[test]
    fn generates_valid_base64_curve25519_keypair() {
        let (private, public) = generate_keypair();
        let private_bytes: [u8; 32] = *private;
        let public_bytes: [u8; 32] = STANDARD.decode(&public).unwrap().try_into().unwrap();
        let derived = PublicKey::from(&StaticSecret::from(private_bytes));
        assert_eq!(derived.as_bytes(), &public_bytes);
        assert_eq!(public_key_from_private(&private_bytes), public);
    }

    #[test]
    fn encrypts_with_random_nonce_and_authentication() {
        let key = [7u8; 32];
        let first = encrypt_private_key(&key, &[0x42u8; 32]).unwrap();
        let second = encrypt_private_key(&key, &[0x42u8; 32]).unwrap();
        assert_ne!(first, second);
        assert!(first.len() > 4 + 12 + 16);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        assert_eq!(&first[..4], b"WGK1");
        let nonce = Nonce::from_slice(&first[4..16]);
        assert_eq!(cipher.decrypt(nonce, &first[16..]).unwrap().as_slice(), &[0x42u8; 32]);
        let decrypted = decrypt_private_key(&key, &first).unwrap();
        assert_eq!(&*decrypted, &[0x42u8; 32]);
        assert!(decrypt_private_key(&[8u8; 32], &first).is_err());
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(cipher.decrypt(nonce, &tampered[16..]).is_err());
    }
}
