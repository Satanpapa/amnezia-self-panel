use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Generate a WireGuard-compatible Curve25519 keypair.
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        Zeroizing::new(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    )
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
    let mut stored = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    stored.extend_from_slice(&nonce_bytes);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Decrypt a stored private key for an authorized configuration-export path.
/// Plaintext buffers are zeroized when dropped.
pub fn decrypt_private_key(master_key: &[u8; 32], stored: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if stored.len() < 12 + 16 {
        return Err("Encrypted WireGuard private key is truncated");
    }
    let cipher = ChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| "Invalid WireGuard master key")?;
    let nonce = Nonce::from_slice(&stored[..12]);
    let plaintext = Zeroizing::new(
        cipher.decrypt(nonce, &stored[12..])
            .map_err(|_| "Could not authenticate encrypted WireGuard private key")?
    );
    let key: [u8; 32] = plaintext.as_slice().try_into()
        .map_err(|_| "Decrypted WireGuard private key has an invalid length")?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead as _;

    #[test]
    fn generates_valid_base64_curve25519_keypair() {
        let (private, public) = generate_keypair();
        let private_bytes: [u8; 32] = *private;
        let public_bytes: [u8; 32] = STANDARD.decode(public).unwrap().try_into().unwrap();
        let derived = PublicKey::from(&StaticSecret::from(private_bytes));
        assert_eq!(derived.as_bytes(), &public_bytes);
    }

    #[test]
    fn encrypts_with_random_nonce_and_authentication() {
        let key = [7u8; 32];
        let first = encrypt_private_key(&key, &[0x42u8; 32]).unwrap();
        let second = encrypt_private_key(&key, &[0x42u8; 32]).unwrap();
        assert_ne!(first, second);
        assert!(first.len() > 12 + 16);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&first[..12]);
        assert_eq!(cipher.decrypt(nonce, &first[12..]).unwrap().as_slice(), &[0x42u8; 32]);
        let decrypted = decrypt_private_key(&key, &first).unwrap();
        assert_eq!(&*decrypted, &[0x42u8; 32]);
        assert!(decrypt_private_key(&[8u8; 32], &first).is_err());
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(cipher.decrypt(nonce, &tampered[12..]).is_err());
    }
}
