use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use less_sync_core::protocol::Change;
use less_sync_storage::{
    migrate_with_pool, FileStorage, PostgresStorage, RecordStorage, SpaceStorage,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const SEED_RECORDS_PULL_HOT: usize = 2_000;
const SEED_RECORDS_FILE_HEAVY: usize = 1_200;
const SEED_FILES_FILE_HEAVY: usize = 5_000;

fn bench_postgres_push_hot(c: &mut Criterion) {
    let Some(context) = BenchContext::new() else {
        eprintln!("Skipping postgres_push_hot benchmark: set DATABASE_URL to run storage benches");
        return;
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    let space_id = Uuid::new_v4();
    let storage = context.storage.clone();
    runtime.block_on(async {
        storage
            .get_or_create_space(space_id, "bench-client")
            .await
            .expect("create benchmark space");
    });

    let next_id = Arc::new(AtomicU64::new(1));
    c.bench_function("postgres_push_hot", |b| {
        b.to_async(&runtime).iter(|| {
            let storage = storage.clone();
            let next_id = Arc::clone(&next_id);
            async move {
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let change = Change {
                    id: benchmark_record_id(id),
                    blob: Some(b"bench-data".to_vec()),
                    cursor: 0,
                    wrapped_dek: None,
                    deleted: false,
                };
                let result = storage
                    .push(space_id, &[change], None)
                    .await
                    .expect("push should succeed");
                black_box(result.cursor);
            }
        });
    });
}

fn bench_postgres_pull_hot(c: &mut Criterion) {
    let Some(context) = BenchContext::new() else {
        eprintln!("Skipping postgres_pull_hot benchmark: set DATABASE_URL to run storage benches");
        return;
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    let space_id = Uuid::new_v4();
    let storage = context.storage.clone();
    runtime.block_on(async {
        storage
            .get_or_create_space(space_id, "bench-client")
            .await
            .expect("create benchmark space");

        let mut changes = Vec::with_capacity(SEED_RECORDS_PULL_HOT);
        for index in 0..SEED_RECORDS_PULL_HOT {
            changes.push(Change {
                id: benchmark_record_id(index as u64 + 1),
                blob: Some(b"bench-data".to_vec()),
                cursor: 0,
                wrapped_dek: None,
                deleted: false,
            });
        }

        storage
            .push(space_id, &changes, None)
            .await
            .expect("seed push should succeed");
    });

    c.bench_function("postgres_pull_hot", |b| {
        b.to_async(&runtime).iter(|| {
            let storage = storage.clone();
            async move {
                let result = storage
                    .stream_pull(space_id, 0)
                    .await
                    .expect("stream_pull should succeed")
                    .collect()
                    .await
                    .expect("collect should succeed");
                black_box(result.entries.len());
            }
        });
    });
}

fn bench_postgres_pull_hot_file_heavy(c: &mut Criterion) {
    let Some(context) = BenchContext::new() else {
        eprintln!(
            "Skipping postgres_pull_hot_file_heavy benchmark: set DATABASE_URL to run storage benches"
        );
        return;
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    let space_id = Uuid::new_v4();
    let storage = context.storage.clone();
    runtime.block_on(async {
        storage
            .get_or_create_space(space_id, "bench-client")
            .await
            .expect("create benchmark space");

        let wrapped_dek = wrapped_dek_with_epoch(1, 0xAA);
        let mut record_ids = Vec::with_capacity(SEED_RECORDS_FILE_HEAVY);
        let mut changes = Vec::with_capacity(SEED_RECORDS_FILE_HEAVY);

        for index in 0..SEED_RECORDS_FILE_HEAVY {
            let id = benchmark_record_id(index as u64 + 1);
            record_ids.push(id.clone());
            changes.push(Change {
                id,
                blob: Some(b"bench-data".to_vec()),
                cursor: 0,
                wrapped_dek: Some(wrapped_dek.clone()),
                deleted: false,
            });
        }

        storage
            .push(space_id, &changes, None)
            .await
            .expect("seed record push should succeed");

        for index in 0..SEED_FILES_FILE_HEAVY {
            let record_id = Uuid::parse_str(&record_ids[index % record_ids.len()])
                .expect("seed record id should parse");
            storage
                .record_file(
                    space_id,
                    Uuid::new_v4(),
                    record_id,
                    1024 + (index % 256) as i64,
                    &wrapped_dek,
                )
                .await
                .expect("record_file should succeed");
        }

        let mut tombstones = Vec::with_capacity(SEED_RECORDS_FILE_HEAVY / 2);
        for record_id in record_ids.iter().take(SEED_RECORDS_FILE_HEAVY / 2) {
            tombstones.push(Change {
                id: record_id.clone(),
                blob: None,
                cursor: 1,
                wrapped_dek: Some(wrapped_dek.clone()),
                deleted: false,
            });
        }

        storage
            .push(space_id, &tombstones, None)
            .await
            .expect("seed tombstones should succeed");
    });

    c.bench_function("postgres_pull_hot_file_heavy", |b| {
        b.to_async(&runtime).iter(|| {
            let storage = storage.clone();
            async move {
                let result = storage
                    .stream_pull(space_id, 0)
                    .await
                    .expect("stream_pull should succeed")
                    .collect()
                    .await
                    .expect("collect should succeed");
                black_box(result.entries.len());
            }
        });
    });
}

#[derive(Clone)]
struct BenchContext {
    storage: PostgresStorage,
}

impl BenchContext {
    fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build setup runtime");

        let storage = runtime.block_on(async {
            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&database_url)
                .await
                .expect("connect admin pool");

            let schema = format!("bench_storage_{}", unique_suffix());
            let drop_schema = format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE");
            sqlx::query(&drop_schema)
                .execute(&admin_pool)
                .await
                .expect("drop old benchmark schema");

            let create_schema = format!("CREATE SCHEMA \"{schema}\"");
            sqlx::query(&create_schema)
                .execute(&admin_pool)
                .await
                .expect("create benchmark schema");

            let scoped_url = scoped_database_url(&database_url, &schema);
            let storage = PostgresStorage::connect(&scoped_url)
                .await
                .expect("connect scoped benchmark storage");
            migrate_with_pool(storage.pool())
                .await
                .expect("run benchmark migrations");
            storage
        });

        Some(Self { storage })
    }
}

fn benchmark_record_id(index: u64) -> String {
    format!("019400e8-7b5d-7000-8000-{index:012}")
}

fn wrapped_dek_with_epoch(epoch: i32, fill: u8) -> Vec<u8> {
    let mut out = vec![0_u8; 44];
    out[..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..].fill(fill);
    out
}

fn scoped_database_url(base_database_url: &str, schema: &str) -> String {
    let separator = if base_database_url.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{base_database_url}{separator}options=-csearch_path%3D{schema}")
}

fn unique_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch");
    format!("{}{}", now.as_secs(), now.subsec_nanos())
}

criterion_group!(
    benches,
    bench_postgres_push_hot,
    bench_postgres_pull_hot,
    bench_postgres_pull_hot_file_heavy
);
criterion_main!(benches);
