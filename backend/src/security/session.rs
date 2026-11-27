use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn new_session_token() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
