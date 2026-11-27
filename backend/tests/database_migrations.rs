use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn migrations_create_the_panel_schema() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite should start");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("all migrations should apply");

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('admins', 'sessions', 'audit_events', 'protocol_containers', 'clients')"
    )
    .fetch_one(&pool)
    .await
    .expect("schema query should work");

    assert_eq!(table_count, 5, "all expected tables must exist");
}
