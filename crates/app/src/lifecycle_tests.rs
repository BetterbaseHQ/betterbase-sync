use super::*;

fn config(database_url: String) -> AppConfig {
    AppConfig::from_values(
        Some("127.0.0.1:0".into()),
        Some(database_url),
        Some("https://issuer.example".into()),
        None,
    )
    .expect("config")
}

struct TestDatabase {
    pool: sqlx::PgPool,
    schema: String,
    url: String,
}

impl TestDatabase {
    async fn new() -> Option<Self> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert_ne!(
                    std::env::var("BB_TEST_REQUIRE_DB").ok().as_deref(),
                    Some("1"),
                    "DATABASE_URL required"
                );
                return None;
            }
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("database");
        let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .expect("schema");
        let mut url = Url::parse(&url).expect("url");
        url.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"))
            .append_pair("application_name", &schema);
        Some(Self {
            pool,
            schema,
            url: url.to_string(),
        })
    }

    async fn assert_workers_stopped(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let connections: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name = $1",
                )
                .bind(&self.schema)
                .fetch_one(&self.pool)
                .await
                .expect("connections");
                if connections == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all startup and background database connections must close");
    }

    async fn close(self) {
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.pool)
            .await
            .expect("drop schema");
        self.pool.close().await;
    }
}

#[tokio::test]
async fn startup_rejects_invalid_database_url_without_serving() {
    let error = run(config("invalid-database-url".into()))
        .await
        .expect_err("invalid database URL");
    assert!(!error.to_string().is_empty());
}

#[tokio::test]
async fn startup_bind_failure_releases_database_and_background_workers() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupy port");
    let mut config = config(db.url.clone());
    config.listen_addr = occupied.local_addr().expect("address");
    let directory = std::env::temp_dir().join(&db.schema);
    config.file_storage = FileStorageConfig::Local {
        path: directory.clone(),
    };
    let error = run(config).await.expect_err("occupied port");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("bind error")
            .kind(),
        std::io::ErrorKind::AddrInUse
    );
    db.assert_workers_stopped().await;
    db.close().await;
    std::fs::remove_dir_all(directory).expect("remove file store");
}

#[tokio::test]
async fn startup_migrates_serves_health_and_cancellation_stops_workers() {
    let Some(db) = TestDatabase::new().await else {
        return;
    };
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let address = reservation.local_addr().expect("address");
    let mut config = config(db.url.clone());
    config.listen_addr = address;
    config.identity_hash_key = Some(vec![7; 32]);
    let directory = std::env::temp_dir().join(&db.schema);
    config.file_storage = FileStorageConfig::Local {
        path: directory.clone(),
    };
    drop(reservation);
    let task = tokio::spawn(run(config));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("http client");
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client.get(format!("http://{address}/health")).send().await {
                break response;
            }
            assert!(!task.is_finished(), "startup must not exit before serving");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("startup deadline");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-Protocol-Version")
            .expect("protocol header"),
        "1"
    );
    let migrated: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'epoch_keys')").bind(&db.schema).fetch_one(&db.pool).await.expect("migration check");
    assert!(migrated);
    task.abort();
    assert!(task.await.expect_err("cancelled server").is_cancelled());
    db.assert_workers_stopped().await;
    db.close().await;
    std::fs::remove_dir_all(directory).expect("remove file store");
}
