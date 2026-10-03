use std::process::Command;

#[test]
fn migration_command_reports_missing_or_invalid_database() {
    for database in [None, Some("invalid-database-url")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_betterbase-sync-migrate"));
        command.env_remove("DATABASE_URL");
        if let Some(url) = database {
            command.env("DATABASE_URL", url);
        }
        let output = command.output().expect("run migrate");
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).expect("stderr");
        assert!(
            error.contains(if database.is_some() {
                "database error"
            } else {
                "DATABASE_URL"
            }),
            "{error}"
        );
        assert!(
            output.stdout.is_empty(),
            "failed migrations must not print success"
        );
    }
}

#[tokio::test]
async fn migration_command_creates_schema_and_is_idempotent() {
    let database = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            assert_ne!(
                std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref(),
                Some("1")
            );
            return;
        }
    };
    let pool = sqlx::PgPool::connect(&database).await.expect("database");
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .expect("schema");
    let separator = if database.contains('?') { '&' } else { '?' };
    let url = format!("{database}{separator}options=-csearch_path%3D{schema}");
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_betterbase-sync-migrate"))
            .env("DATABASE_URL", &url)
            .output()
            .expect("run migrate");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "migrations complete"
        );
        let tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name IN ('spaces', 'records', 'files', 'members', 'epoch_keys')")
            .bind(&schema).fetch_one(&pool).await.expect("tables");
        assert_eq!(tables, 5);
    }
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("cleanup");
    pool.close().await;
}
