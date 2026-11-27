use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn new_session_token() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{hash_session_token, new_session_token};

    #[test]
    fn session_tokens_are_unique_and_not_stored_as_plaintext() {
        let first = new_session_token();
        let second = new_session_token();
        assert_ne!(first, second);
        assert_ne!(first, hash_session_token(&first));
        assert_eq!(hash_session_token(&first).len(), 64);
    }
}
