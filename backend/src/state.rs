use std::sync::Arc;

use sqlx::SqlitePool;

use crate::runtime::RuntimeAdapter;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub cookie_secure: bool,
    pub runtime: Arc<dyn RuntimeAdapter>,
    pub wireguard_master_key: Option<Arc<[u8; 32]>>,
}
