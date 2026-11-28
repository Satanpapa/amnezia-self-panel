use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn all_sqlite_migrations_apply_to_a_fresh_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite pool should open");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("all migrations should apply to a fresh SQLite database");

    let operation_column: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('protocol_containers') WHERE name = 'runtime_operation'"
    )
    .fetch_one(&pool)
    .await
    .expect("protocol container runtime operation column should exist");
    assert_eq!(operation_column, 1);

    for column in ["last_rx_bytes", "last_tx_bytes", "wireguard_preshared_key_encrypted"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name = ?"
        )
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("client traffic snapshot columns should exist");
        assert_eq!(count, 1, "missing client traffic column {column}");
    }

    let client_ip_trigger_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('clients_prevent_duplicate_ip_insert', 'clients_prevent_duplicate_ip_update')"
    )
    .fetch_one(&pool)
    .await
    .expect("client IP allocation triggers should exist");
    assert_eq!(client_ip_trigger_count, 2);

    let login_throttle_table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'auth_login_attempts'"
    )
    .fetch_one(&pool)
    .await
    .expect("login throttle table should exist");
    assert_eq!(login_throttle_table, 1);

    for column in ["username_hash", "window_started_at", "failure_count", "blocked_until"] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('auth_login_attempts') WHERE name = ?"
        )
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("login throttle column should exist");
        assert_eq!(count, 1, "missing auth throttle column {column}");
    }

    let operation_lock = sqlx::query(
        "UPDATE protocol_containers SET runtime_operation = 'start' WHERE 1 = 0"
    )
    .execute(&pool)
    .await;
    assert!(operation_lock.is_ok());
}
