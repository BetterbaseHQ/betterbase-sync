//! HTTP -> PostgreSQL -> local object-store lifecycle with controlled failures.
use super::*;
use betterbase_sync_core::protocol::Change;
use betterbase_sync_realtime::broker::{BrokerConfig, MultiBroker, Subscriber};
use betterbase_sync_storage::postgres::PostgresStorage;
use betterbase_sync_storage::PendingFileDeletion;
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Default)]
struct Gate {
    entered: Notify,
    resume: Notify,
}
impl Gate {
    async fn pause(&self) {
        self.entered.notify_one();
        self.resume.notified().await;
    }
    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
            .await
            .expect("operation reached gate");
    }
    fn release(&self) {
        self.resume.notify_one();
    }
}

struct LocalDirectory(PathBuf);
impl Drop for LocalDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FaultBlobs {
    local: ObjectStoreFileBlobStorage,
    fail_store: AtomicBool,
    fail_get: AtomicBool,
    fail_delete: Mutex<HashSet<Uuid>>,
    after_store: Mutex<Option<Arc<Gate>>>,
    before_delete: Mutex<Option<Arc<Gate>>>,
}
#[async_trait]
impl FileBlobStorage for FaultBlobs {
    async fn store(
        &self,
        space: Uuid,
        file: Uuid,
        payload: &[u8],
    ) -> Result<bool, FileBlobStorageError> {
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(FileBlobStorageError::Internal);
        }
        let result = self.local.store(space, file, payload).await?;
        let gate = self.after_store.lock().expect("gate").take();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        Ok(result)
    }
    async fn get(&self, space: Uuid, file: Uuid) -> Result<Vec<u8>, FileBlobStorageError> {
        if self.fail_get.load(Ordering::SeqCst) {
            return Err(FileBlobStorageError::Internal);
        }
        self.local.get(space, file).await
    }
    async fn delete(&self, space: Uuid, file: Uuid) -> Result<bool, FileBlobStorageError> {
        if self.fail_delete.lock().expect("failures").contains(&file) {
            return Err(FileBlobStorageError::Internal);
        }
        let gate = self.before_delete.lock().expect("gate").take();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        self.local.delete(space, file).await
    }
}

struct FaultMetadata {
    db: Arc<PostgresStorage>,
    fail_commit: AtomicBool,
    fail_schedule: AtomicBool,
}
#[async_trait]
impl FileSyncStorage for FaultMetadata {
    async fn lock_file(
        &self,
        space: Uuid,
        file: Uuid,
    ) -> Result<betterbase_sync_storage::FileOperationLock, StorageError> {
        FileStorageTrait::lock_file(&*self.db, space, file).await
    }
    async fn schedule_file_deletions(
        &self,
        space: Uuid,
        files: &[Uuid],
    ) -> Result<(), StorageError> {
        if self.fail_schedule.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        FileStorageTrait::schedule_file_deletions(&*self.db, space, files).await
    }
    async fn get_space(&self, space: Uuid) -> Result<Space, StorageError> {
        SpaceStorage::get_space(&*self.db, space).await
    }
    async fn get_or_create_space(&self, space: Uuid, client: &str) -> Result<Space, StorageError> {
        SpaceStorage::get_or_create_space(&*self.db, space, client).await
    }
    async fn record_exists(&self, space: Uuid, record: Uuid) -> Result<bool, StorageError> {
        RecordStorage::record_exists(&*self.db, space, record).await
    }
    async fn record_file(
        &self,
        space: Uuid,
        file: Uuid,
        record: Uuid,
        size: i64,
        dek: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        FileStorageTrait::record_file(&*self.db, space, file, record, size, dek).await
    }
    async fn tombstone_file(&self, space: Uuid, file: Uuid) -> Result<Option<i64>, StorageError> {
        FileStorageTrait::tombstone_file(&*self.db, space, file).await
    }
    async fn get_file_metadata(
        &self,
        space: Uuid,
        file: Uuid,
    ) -> Result<FileMetadata, StorageError> {
        FileStorageTrait::get_file_metadata(&*self.db, space, file).await
    }
    async fn is_revoked(&self, space: Uuid, cid: &str) -> Result<bool, StorageError> {
        RevocationStorage::is_revoked(&*self.db, space, cid).await
    }
}

struct FaultQueue {
    db: Arc<PostgresStorage>,
    fail_exists: AtomicBool,
    fail_complete: AtomicBool,
    after_list: Mutex<Option<Arc<Gate>>>,
    after_exists: Mutex<Option<Arc<Gate>>>,
    before_complete: Mutex<Option<Arc<Gate>>>,
}
impl FaultQueue {
    fn new(db: Arc<PostgresStorage>) -> Self {
        Self {
            db,
            fail_exists: AtomicBool::new(false),
            fail_complete: AtomicBool::new(false),
            after_list: Mutex::new(None),
            after_exists: Mutex::new(None),
            before_complete: Mutex::new(None),
        }
    }
}
#[async_trait]
impl FileDeletionQueue for FaultQueue {
    async fn lock_file(
        &self,
        space: Uuid,
        file: Uuid,
    ) -> Result<betterbase_sync_storage::FileOperationLock, StorageError> {
        FileStorageTrait::lock_file(&*self.db, space, file).await
    }
    async fn pending_file_deletions(
        &self,
        cutoff: SystemTime,
        limit: usize,
    ) -> Result<Vec<PendingFileDeletion>, StorageError> {
        let result = FileStorageTrait::pending_file_deletions(&*self.db, cutoff, limit).await?;
        let gate = self.after_list.lock().expect("gate").take();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        Ok(result)
    }
    async fn file_exists(&self, space: Uuid, file: Uuid) -> Result<bool, StorageError> {
        if self.fail_exists.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        let exists = FileStorageTrait::file_exists(&*self.db, space, file).await?;
        let gate = self.after_exists.lock().expect("gate").take();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        Ok(exists)
    }
    async fn file_deletion_due(
        &self,
        space: Uuid,
        file: Uuid,
        cutoff: SystemTime,
    ) -> Result<bool, StorageError> {
        FileStorageTrait::file_deletion_due(&*self.db, space, file, cutoff).await
    }
    async fn clear_file_deletion_if_live(
        &self,
        space: Uuid,
        file: Uuid,
    ) -> Result<(), StorageError> {
        FileStorageTrait::clear_file_deletion_if_live(&*self.db, space, file).await
    }
    async fn complete_file_deletion(&self, space: Uuid, file: Uuid) -> Result<(), StorageError> {
        let gate = self.before_complete.lock().expect("gate").take();
        if let Some(gate) = gate {
            gate.pause().await;
        }
        if self.fail_complete.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        FileStorageTrait::complete_file_deletion(&*self.db, space, file).await
    }
}

struct Fixture {
    broker: Arc<MultiBroker>,
    app: axum::Router,
    db: Arc<PostgresStorage>,
    metadata: Arc<FaultMetadata>,
    blobs: Arc<FaultBlobs>,
    directory: LocalDirectory,
    schema: String,
    space: Uuid,
    record: Uuid,
    file: Uuid,
}
impl Fixture {
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
        let schema = format!("test_{}", Uuid::new_v4().simple());
        let opts: sqlx::postgres::PgConnectOptions = url.parse().expect("DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(opts.options([("search_path", schema.as_str())]))
            .await
            .expect("database");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .expect("schema");
        betterbase_sync_storage::migrate_with_pool(&pool)
            .await
            .expect("migrations");
        let db = Arc::new(PostgresStorage::from_pool(pool));
        let space = personal_space_user1();
        let record = Uuid::new_v4();
        SpaceStorage::create_space(&*db, space, "client", None)
            .await
            .expect("space");
        RecordStorage::push(
            &*db,
            space,
            &[change(record, Some(b"encrypted record"), 0)],
            None,
        )
        .await
        .expect("record");
        let directory =
            LocalDirectory(std::env::temp_dir().join(format!("sync-files-{}", Uuid::new_v4())));
        std::fs::create_dir_all(&directory.0).expect("directory");
        let blobs = Arc::new(FaultBlobs {
            local: ObjectStoreFileBlobStorage::local_filesystem(&directory.0).expect("local store"),
            fail_store: AtomicBool::new(false),
            fail_get: AtomicBool::new(false),
            fail_delete: Mutex::new(HashSet::new()),
            after_store: Mutex::new(None),
            before_delete: Mutex::new(None),
        });
        let metadata = Arc::new(FaultMetadata {
            db: db.clone(),
            fail_commit: AtomicBool::new(false),
            fail_schedule: AtomicBool::new(false),
        });
        let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
        let app = router(
            ApiState::new(db.clone())
                .with_websocket(Arc::new(build_validator()))
                .with_sync_storage(db.clone())
                .with_realtime_broker(broker.clone())
                .with_file_sync_storage_adapter(metadata.clone())
                .with_file_blob_storage_adapter(blobs.clone()),
        );
        Some(Self {
            broker,
            app,
            db,
            metadata,
            blobs,
            directory,
            schema,
            space,
            record,
            file: Uuid::new_v4(),
        })
    }
    async fn upload(&self, payload: &[u8]) -> Response {
        self.app
            .clone()
            .oneshot(put_file_request(
                self.space,
                self.file,
                self.record,
                payload,
            ))
            .await
            .expect("upload")
    }
    async fn read(&self, method: &str) -> Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/api/v1/spaces/{}/files/{}", self.space, self.file))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("read")
    }
    async fn cursor(&self) -> i64 {
        SpaceStorage::get_space(&*self.db, self.space)
            .await
            .expect("space")
            .cursor
    }
    async fn queued(&self) -> Vec<PendingFileDeletion> {
        FileStorageTrait::pending_file_deletions(
            &*self.db,
            SystemTime::now() + Duration::from_secs(86400),
            100,
        )
        .await
        .expect("queue")
    }
    async fn tombstone(&self, cursor: i64) -> i64 {
        let result = RecordStorage::push(
            &*self.db,
            self.space,
            &[change(self.record, None, cursor)],
            None,
        )
        .await
        .expect("tombstone");
        assert!(result.ok);
        result.cursor
    }
    async fn restore(&self, cursor: i64) {
        assert!(
            RecordStorage::push(
                &*self.db,
                self.space,
                &[change(self.record, Some(b"restored"), cursor)],
                None
            )
            .await
            .expect("restore")
            .ok
        );
    }
    async fn age_queue(&self) {
        sqlx::query("UPDATE pending_file_deletions SET scheduled_at = to_timestamp(1)")
            .execute(self.db.pool())
            .await
            .expect("age queue");
    }
    async fn wait_for_file_lock_waiter(&self) {
        // Inspect the exact advisory key so parallel tests cannot satisfy the check.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND objsubid = 1 AND classid::bigint = ((hashtextextended($1, 0) >> 32) & 4294967295) AND objid::bigint = (hashtextextended($1, 0) & 4294967295))",
                ).bind(format!("betterbase-sync:file:{}:{}", self.space, self.file))
                    .fetch_one(self.db.pool()).await.expect("lock waiters");
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("upload waits for collector");
    }
    async fn finish(self) {
        let Self {
            app,
            db,
            metadata,
            blobs,
            directory,
            schema,
            broker,
            ..
        } = self;
        drop((app, metadata, blobs, broker));
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(db.pool())
            .await
            .expect("drop schema");
        db.as_ref().clone().close().await;
        drop(directory);
    }
}
fn change(id: Uuid, blob: Option<&[u8]>, cursor: i64) -> Change {
    Change {
        id: id.to_string(),
        blob: blob.map(ToOwned::to_owned),
        cursor,
        wrapped_dek: None,
        deleted: blob.is_none(),
    }
}

#[tokio::test]
async fn postgres_local_upload_download_head_and_replay_preserve_metadata() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let bytes = [0, 128, 255];
    assert_eq!(f.upload(&bytes).await.status(), StatusCode::CREATED);
    assert_eq!(f.cursor().await, 2);
    let response = f.read("GET").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-Protocol-Version")
            .expect("version"),
        "1"
    );
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 100)
            .await
            .expect("body")
            .as_ref(),
        &bytes
    );
    let response = f.read("HEAD").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(CONTENT_LENGTH).expect("length"), "3");
    assert_eq!(f.upload(&bytes).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(f.cursor().await, 2);
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn metadata_commit_failure_can_be_retried_without_overwriting_object() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.metadata.fail_commit.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(f.cursor().await, 1);
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("stored before metadata"),
        b"ciphertext"
    );
    assert_eq!(f.read("GET").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.queued().await.len(), 1);
    f.metadata.fail_commit.store(false, Ordering::SeqCst);
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    assert_eq!(f.cursor().await, 2);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(f.cursor().await, 2);
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn object_store_failure_never_commits_metadata_and_retry_succeeds() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.blobs.fail_store.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(f.cursor().await, 1);
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    f.blobs.fail_store.store(false, Ordering::SeqCst);
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.finish().await;
}

#[tokio::test]
async fn tombstone_during_upload_cannot_recreate_file_metadata() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let gate = Arc::new(Gate::default());
    *f.blobs.after_store.lock().expect("gate") = Some(gate.clone());
    let request = put_file_request(f.space, f.file, f.record, b"ciphertext");
    let task = tokio::spawn(f.app.clone().oneshot(request));
    gate.wait().await;
    assert_eq!(f.tombstone(1).await, 2);
    gate.release();
    let response = task.await.expect("upload task").expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.cursor().await, 2);
    assert_eq!(f.read("GET").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("cleanup"),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn delete_route_tombstones_streams_pull_and_collects_after_grace() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);

    // DELETE via the route: tombstone + queue intent, atomically.
    let delete = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/spaces/{}/files/{}", f.space, f.file))
                .header(AUTHORIZATION, "Bearer files-user1")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("dispatch request");
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert_eq!(f.read("GET").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.queued().await.len(), 1);

    // The tombstone streams through cursor-based pull (deleted: true), so
    // offline peers learn the file is gone on their next incremental pull.
    let pull =
        f.db.stream_pull(f.space, 1)
            .await
            .expect("stream pull")
            .collect()
            .await
            .expect("collect pull");
    let entry = pull
        .entries
        .iter()
        .find(|entry| entry.file.as_ref().is_some_and(|file| file.id == f.file))
        .expect("file entry in pull");
    let file = entry.file.as_ref().expect("file");
    assert!(file.deleted);

    // Grace elapses: the sweep removes the object and completes the queue.
    f.age_queue().await;
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("sweep"),
        1
    );
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    assert!(f.queued().await.is_empty());

    // With the object gone, re-uploading the same id — even with fresh
    // bytes — recreates it (no immutability conflict against a void).
    assert_eq!(f.upload(b"fresh bytes").await.status(), StatusCode::CREATED);
    let response = f.read("GET").await;
    assert_eq!(response.status(), StatusCode::OK);
    f.finish().await;
}

#[tokio::test]
async fn tombstone_hides_file_immediately_and_gc_obeys_grace_period() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.tombstone(1).await;
    for method in ["GET", "HEAD"] {
        assert_eq!(f.read(method).await.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::UNIX_EPOCH, 100)
            .await
            .expect("not due"),
        0
    );
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("retained during grace"),
        b"ciphertext"
    );
    f.age_queue().await;
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("sweep"),
        1
    );
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    assert!(f.queued().await.is_empty());
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("repeat"),
        0
    );
    f.finish().await;
}

#[tokio::test]
async fn stale_gc_snapshot_spares_metadata_restored_before_delete_check() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    let gate = Arc::new(Gate::default());
    *queue.after_list.lock().expect("gate") = Some(gate.clone());
    let blobs = f.blobs.clone();
    let task = tokio::spawn(async move {
        sweep_file_deletions(queue.clone(), blobs.clone(), SystemTime::now(), 100).await
    });
    gate.wait().await;
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    gate.release();
    assert_eq!(task.await.expect("sweep task").expect("sweep"), 0);
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn reupload_during_gc_cannot_leave_live_metadata_over_missing_object() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(
        f.upload(b"old ciphertext").await.status(),
        StatusCode::CREATED
    );
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let gate = Arc::new(Gate::default());
    *f.blobs.before_delete.lock().expect("gate") = Some(gate.clone());
    // A separately constructed storage instance models another server worker.
    let other = Arc::new(PostgresStorage::from_pool(f.db.pool().clone()));
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(other.clone(), blobs.clone(), SystemTime::now(), 100).await
    });
    gate.wait().await;
    let upload = tokio::spawn(f.app.clone().oneshot(put_file_request(
        f.space,
        f.file,
        f.record,
        b"new ciphertext",
    )));
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(sweep.await.expect("sweep task").expect("sweep"), 1);
    assert_eq!(
        upload
            .await
            .expect("upload task")
            .expect("response")
            .status(),
        StatusCode::CREATED
    );
    let response = f.read("GET").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 100)
            .await
            .expect("body")
            .as_ref(),
        b"new ciphertext"
    );
    f.finish().await;
}

#[tokio::test]
async fn failed_deletion_retries_without_stopping_other_files_in_batch() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    let second = Uuid::new_v4();
    assert_eq!(
        f.app
            .clone()
            .oneshot(put_file_request(f.space, second, f.record, b"second"))
            .await
            .expect("upload")
            .status(),
        StatusCode::CREATED
    );
    f.tombstone(1).await;
    f.blobs.fail_delete.lock().expect("failures").insert(f.file);
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("partial sweep"),
        1
    );
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("failed object retained"),
        b"ciphertext"
    );
    assert_eq!(
        f.blobs.local.get(f.space, second).await,
        Err(FileBlobStorageError::NotFound)
    );
    f.blobs.fail_delete.lock().expect("failures").clear();
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("retry"),
        1
    );
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn queue_completion_failure_retries_an_already_missing_object() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.tombstone(1).await;
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    queue.fail_complete.store(true, Ordering::SeqCst);
    assert_eq!(
        sweep_file_deletions(queue.clone(), f.blobs.clone(), SystemTime::now(), 100).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    assert_eq!(f.queued().await.len(), 1);
    queue.fail_complete.store(false, Ordering::SeqCst);
    assert_eq!(
        sweep_file_deletions(queue.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("retry"),
        1
    );
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn failed_live_metadata_check_never_deletes_object_or_queue() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.tombstone(1).await;
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    queue.fail_exists.store(true, Ordering::SeqCst);
    assert_eq!(
        sweep_file_deletions(queue.clone(), f.blobs.clone(), SystemTime::now(), 100).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await.expect("untouched"),
        b"ciphertext"
    );
    f.finish().await;
}

#[tokio::test]
async fn download_object_store_failure_is_retryable_without_metadata_changes() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.blobs.fail_get.store(true, Ordering::SeqCst);
    assert_eq!(
        f.read("GET").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(f.read("HEAD").await.status(), StatusCode::OK);
    f.blobs.fail_get.store(false, Ordering::SeqCst);
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    assert_eq!(f.cursor().await, 2);
    f.finish().await;
}

#[tokio::test]
async fn failed_cleanup_intent_never_writes_an_untracked_object() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.metadata.fail_schedule.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    assert_eq!(f.cursor().await, 1);
    assert!(f.queued().await.is_empty());
    f.metadata.fail_schedule.store(false, Ordering::SeqCst);
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.finish().await;
}

#[tokio::test]
async fn cancelled_upload_finishes_bookkeeping_before_releasing_lock() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let gate = Arc::new(Gate::default());
    *f.blobs.after_store.lock().expect("gate") = Some(gate.clone());
    let upload = tokio::spawn(
        f.app
            .clone()
            .oneshot(put_file_request(f.space, f.file, f.record, b"orphan")),
    );
    gate.wait().await;
    upload.abort();
    assert!(upload.await.expect_err("cancelled upload").is_cancelled());
    assert_eq!(f.cursor().await, 1);
    assert_eq!(f.read("GET").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(f.queued().await.len(), 1);
    let sweep = tokio::spawn(sweep_file_deletions(
        f.db.clone(),
        f.blobs.clone(),
        SystemTime::now(),
        100,
    ));
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), sweep)
            .await
            .expect("sweep after upload")
            .expect("sweep task")
            .expect("sweep"),
        0
    );
    assert_eq!(f.cursor().await, 2);
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    assert!(f.queued().await.is_empty());
    // Byte-identical replay of the completed upload is the idempotent 204;
    // different bytes under the live id now surface as 409 (covered by
    // put_file_with_conflicting_bytes_returns_409_and_keeps_state).
    assert_eq!(f.upload(b"orphan").await.status(), StatusCode::NO_CONTENT);
    f.finish().await;
}

#[tokio::test]
async fn permanent_metadata_failure_leaves_object_collectible() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.metadata.fail_commit.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"orphan").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("sweep"),
        1
    );
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    assert_eq!(f.cursor().await, 1);
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn metadata_rejects_missing_tombstoned_and_other_space_parents_without_cursor_change() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let other = Uuid::new_v4();
    SpaceStorage::create_space(&*f.db, other, "other", None)
        .await
        .expect("space");
    for (space, record) in [(other, f.record), (f.space, Uuid::new_v4())] {
        let before = SpaceStorage::get_space(&*f.db, space)
            .await
            .expect("space")
            .cursor;
        assert_eq!(
            FileStorageTrait::record_file(&*f.db, space, f.file, record, 1, &[9; 44]).await,
            Err(StorageError::RecordNotFound)
        );
        assert_eq!(
            SpaceStorage::get_space(&*f.db, space)
                .await
                .expect("space")
                .cursor,
            before
        );
    }
    f.tombstone(1).await;
    assert_eq!(
        FileStorageTrait::record_file(&*f.db, f.space, f.file, f.record, 1, &[9; 44]).await,
        Err(StorageError::RecordNotFound)
    );
    assert_eq!(f.cursor().await, 2);
    f.finish().await;
}

#[tokio::test]
async fn stale_gc_snapshot_cannot_shorten_a_new_tombstones_grace_period() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    f.age_queue().await;
    let cutoff = SystemTime::now() - Duration::from_secs(60);
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    let gate = Arc::new(Gate::default());
    *queue.after_list.lock().expect("gate") = Some(gate.clone());
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(queue.clone(), blobs.clone(), cutoff, 100).await
    });
    gate.wait().await;
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.tombstone(tombstone + 1).await;
    gate.release();
    assert_eq!(sweep.await.expect("sweep task").expect("sweep"), 0);
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("grace protected bytes"),
        b"ciphertext"
    );
    assert_eq!(f.queued().await.len(), 1);
    f.age_queue().await;
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), cutoff, 100)
            .await
            .expect("aged sweep"),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn live_metadata_cleanup_cannot_erase_a_concurrent_tombstones_queue_entry() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    FileStorageTrait::schedule_file_deletions(&*f.db, f.space, &[f.file])
        .await
        .expect("stale intent");
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    let gate = Arc::new(Gate::default());
    *queue.after_exists.lock().expect("gate") = Some(gate.clone());
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(queue.clone(), blobs.clone(), SystemTime::now(), 100).await
    });
    gate.wait().await;
    f.tombstone(1).await;
    gate.release();
    assert_eq!(sweep.await.expect("sweep task").expect("sweep"), 0);
    assert_eq!(f.queued().await.len(), 1);
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("retained object"),
        b"ciphertext"
    );
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("next sweep"),
        1
    );
    f.finish().await;
}

#[tokio::test]
async fn live_metadata_cleanup_removes_stale_intent_without_deleting_bytes() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    FileStorageTrait::schedule_file_deletions(&*f.db, f.space, &[f.file])
        .await
        .expect("stale intent");
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), SystemTime::now(), 100)
            .await
            .expect("sweep"),
        0
    );
    assert!(f.queued().await.is_empty());
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    f.finish().await;
}

#[tokio::test]
async fn cancelled_collector_finishes_its_locked_operation_before_upload_recovers() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let gate = Arc::new(Gate::default());
    *f.blobs.before_delete.lock().expect("gate") = Some(gate.clone());
    let other = Arc::new(PostgresStorage::from_pool(f.db.pool().clone()));
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(other.clone(), blobs.clone(), SystemTime::now(), 100).await
    });
    gate.wait().await;
    let upload = tokio::spawn(f.app.clone().oneshot(put_file_request(
        f.space,
        f.file,
        f.record,
        b"ciphertext",
    )));
    f.wait_for_file_lock_waiter().await;
    sweep.abort();
    assert!(sweep.await.expect_err("cancelled collector").is_cancelled());
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), upload)
            .await
            .expect("released lock")
            .expect("upload task")
            .expect("response")
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn collecting_one_file_does_not_block_another_files_upload() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(
        f.upload(b"old ciphertext").await.status(),
        StatusCode::CREATED
    );
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let gate = Arc::new(Gate::default());
    *f.blobs.before_delete.lock().expect("gate") = Some(gate.clone());
    let other = Arc::new(PostgresStorage::from_pool(f.db.pool().clone()));
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(other.clone(), blobs.clone(), SystemTime::now(), 100).await
    });
    gate.wait().await;
    let second = Uuid::new_v4();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        f.app
            .clone()
            .oneshot(put_file_request(f.space, second, f.record, b"second")),
    )
    .await
    .expect("independent file progresses")
    .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    gate.release();
    assert_eq!(sweep.await.expect("sweep task").expect("sweep"), 1);
    assert_eq!(
        f.blobs
            .local
            .get(f.space, second)
            .await
            .expect("other file"),
        b"second"
    );
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

struct FileWatcher(tokio::sync::mpsc::UnboundedSender<Arc<[u8]>>);
impl Subscriber for FileWatcher {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        self.0.send(payload).is_ok()
    }
    fn exclude_id(&self) -> &str {
        "file-watcher"
    }
    fn mailbox_id(&self) -> &str {
        "file-watcher"
    }
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

#[tokio::test]
async fn upload_broadcasts_committed_cursor_once_to_only_the_matching_space() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let (tx, mut notifications) = tokio::sync::mpsc::unbounded_channel();
    let subscriber = f
        .broker
        .register_subscriber(
            Arc::new(FileWatcher(tx)),
            &[f.space.as_simple().to_string()],
        )
        .await
        .expect("subscriber");
    let (other_tx, mut other_notifications) = tokio::sync::mpsc::unbounded_channel();
    let other = f
        .broker
        .register_subscriber(
            Arc::new(FileWatcher(other_tx)),
            &[Uuid::new_v4().as_simple().to_string()],
        )
        .await
        .expect("other subscriber");
    f.metadata.fail_commit.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(matches!(
        notifications.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    f.metadata.fail_commit.store(false, Ordering::SeqCst);
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    #[derive(serde::Deserialize)]
    struct Notification {
        #[serde(rename = "type")]
        frame_type: i32,
        method: String,
        params: WsFileData,
    }
    let notification: Notification =
        minicbor_serde::from_slice(&notifications.try_recv().expect("file notification"))
            .expect("CBOR notification");
    assert_eq!(
        notification.frame_type,
        betterbase_sync_core::protocol::RPC_NOTIFICATION
    );
    assert_eq!(notification.method, "file");
    assert_eq!(notification.params.space, f.space.as_simple().to_string());
    assert_eq!(notification.params.cursor, f.cursor().await);
    assert_eq!(notification.params.cursor, 2);
    assert_eq!(notification.params.files.len(), 1);
    let file = &notification.params.files[0];
    assert_eq!(file.id, f.file.to_string());
    assert_eq!(file.record_id, f.record.to_string());
    assert_eq!(file.size, 10);
    assert_eq!(file.wrapped_dek.as_deref(), Some([9; 44].as_slice()));
    assert!(!file.deleted);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::NO_CONTENT
    );
    assert!(matches!(
        notifications.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        other_notifications.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    f.broker
        .unregister_subscriber(subscriber)
        .await
        .expect("unsubscribe");
    f.broker
        .unregister_subscriber(other)
        .await
        .expect("unsubscribe other");
    f.finish().await;
}

/// Dispatched backend I/O continues independently if its awaiting future is
/// dropped, as with blocking filesystem I/O or an accepted remote request.
struct DispatchedDelete {
    inner: Arc<FaultBlobs>,
    gate: Arc<Gate>,
}
#[async_trait]
impl FileBlobStorage for DispatchedDelete {
    async fn store(
        &self,
        space: Uuid,
        file: Uuid,
        data: &[u8],
    ) -> Result<bool, FileBlobStorageError> {
        self.inner.store(space, file, data).await
    }
    async fn get(&self, space: Uuid, file: Uuid) -> Result<Vec<u8>, FileBlobStorageError> {
        self.inner.get(space, file).await
    }
    async fn delete(&self, space: Uuid, file: Uuid) -> Result<bool, FileBlobStorageError> {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        tokio::spawn(async move {
            gate.pause().await;
            inner.delete(space, file).await
        })
        .await
        .map_err(|_| FileBlobStorageError::Internal)?
    }
}

#[tokio::test]
async fn cancelling_sweep_after_delete_dispatch_preserves_reuploaded_bytes() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(
        f.upload(b"old ciphertext").await.status(),
        StatusCode::CREATED
    );
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let gate = Arc::new(Gate::default());
    let blobs = Arc::new(DispatchedDelete {
        inner: f.blobs.clone(),
        gate: gate.clone(),
    });
    let db = f.db.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(
            db,
            blobs,
            SystemTime::now() + Duration::from_secs(86400),
            100,
        )
        .await
    });
    gate.wait().await;
    sweep.abort();
    assert!(sweep.await.expect_err("cancelled sweep").is_cancelled());
    let upload = tokio::spawn(f.app.clone().oneshot(put_file_request(
        f.space,
        f.file,
        f.record,
        b"new ciphertext",
    )));
    // The caller was cancelled, but dispatched deletion still owns the lock.
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), upload)
            .await
            .expect("upload after deletion")
            .expect("upload task")
            .expect("response")
            .status(),
        StatusCode::CREATED
    );
    let response = f.read("GET").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 100)
            .await
            .expect("body")
            .as_ref(),
        b"new ciphertext"
    );
    assert!(FileStorageTrait::file_exists(&*f.db, f.space, f.file)
        .await
        .expect("metadata"));
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

#[tokio::test]
async fn cancelling_sweep_during_queue_completion_cannot_erase_a_later_tombstone() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(
        f.upload(b"old ciphertext").await.status(),
        StatusCode::CREATED
    );
    let tombstone = f.tombstone(1).await;
    f.restore(tombstone).await;
    let gate = Arc::new(Gate::default());
    let queue = Arc::new(FaultQueue::new(f.db.clone()));
    *queue.before_complete.lock().expect("gate") = Some(gate.clone());
    let blobs = f.blobs.clone();
    let sweep = tokio::spawn(async move {
        sweep_file_deletions(
            queue,
            blobs,
            SystemTime::now() + Duration::from_secs(86400),
            100,
        )
        .await
    });
    gate.wait().await;
    assert_eq!(
        f.blobs.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    sweep.abort();
    assert!(sweep.await.expect_err("cancelled sweep").is_cancelled());
    let upload = tokio::spawn(f.app.clone().oneshot(put_file_request(
        f.space,
        f.file,
        f.record,
        b"new ciphertext",
    )));
    // Queue completion, as well as object deletion, stays inside the lock.
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), upload)
            .await
            .expect("upload after completion")
            .expect("upload task")
            .expect("response")
            .status(),
        StatusCode::CREATED
    );
    assert!(f.queued().await.is_empty());
    f.tombstone(tombstone + 1).await;
    assert_eq!(
        f.queued().await.len(),
        1,
        "the new tombstone retains its cleanup intent"
    );
    assert_eq!(
        f.blobs.get(f.space, f.file).await.expect("new orphan"),
        b"new ciphertext"
    );
    f.finish().await;
}

#[tokio::test]
async fn review_failed_replay_then_tombstone_starts_a_fresh_deletion_grace_period() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    assert_eq!(f.upload(b"ciphertext").await.status(), StatusCode::CREATED);
    f.metadata.fail_commit.store(true, Ordering::SeqCst);
    assert_eq!(
        f.upload(b"ciphertext").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    f.age_queue().await;
    // An old failed replay intent must not bypass the tombstone's 24h grace.
    f.tombstone(1).await;
    let cutoff = SystemTime::now() - Duration::from_secs(86400);
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), cutoff, 100)
            .await
            .expect("grace sweep"),
        0
    );
    assert_eq!(
        f.blobs
            .local
            .get(f.space, f.file)
            .await
            .expect("retained object"),
        b"ciphertext"
    );
    assert_eq!(f.queued().await.len(), 1);
    f.age_queue().await;
    assert_eq!(
        sweep_file_deletions(f.db.clone(), f.blobs.clone(), cutoff, 100)
            .await
            .expect("expired sweep"),
        1
    );
    assert!(f.queued().await.is_empty());
    f.finish().await;
}

struct DispatchedStore {
    inner: Arc<FaultBlobs>,
    gate: Arc<Gate>,
}
#[async_trait]
impl FileBlobStorage for DispatchedStore {
    async fn store(
        &self,
        space: Uuid,
        file: Uuid,
        payload: &[u8],
    ) -> Result<bool, FileBlobStorageError> {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        let payload = payload.to_vec();
        tokio::spawn(async move {
            gate.pause().await;
            inner.store(space, file, &payload).await
        })
        .await
        .map_err(|_| FileBlobStorageError::Internal)?
    }
    async fn get(&self, space: Uuid, file: Uuid) -> Result<Vec<u8>, FileBlobStorageError> {
        self.inner.get(space, file).await
    }
    async fn delete(&self, space: Uuid, file: Uuid) -> Result<bool, FileBlobStorageError> {
        self.inner.delete(space, file).await
    }
}

#[tokio::test]
async fn review_cancelled_dispatched_upload_keeps_collector_locked_until_metadata_commits() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    FileStorageTrait::schedule_file_deletions(&*f.db, f.space, &[f.file])
        .await
        .expect("older failed attempt");
    f.age_queue().await;
    let gate = Arc::new(Gate::default());
    let blobs = Arc::new(DispatchedStore {
        inner: f.blobs.clone(),
        gate: gate.clone(),
    });
    let app = router(
        ApiState::new(f.db.clone())
            .with_websocket(Arc::new(build_validator()))
            .with_sync_storage(f.db.clone())
            .with_file_sync_storage_adapter(f.metadata.clone())
            .with_file_blob_storage_adapter(blobs.clone()),
    );
    let upload = tokio::spawn(app.oneshot(put_file_request(
        f.space,
        f.file,
        f.record,
        b"late ciphertext",
    )));
    gate.wait().await;
    upload.abort();
    assert!(upload.await.expect_err("cancelled request").is_cancelled());
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await,
        Err(FileBlobStorageError::NotFound)
    );
    let sweep = tokio::spawn(sweep_file_deletions(
        f.db.clone(),
        blobs,
        SystemTime::now(),
        100,
    ));
    f.wait_for_file_lock_waiter().await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), sweep)
            .await
            .expect("sweep finished")
            .expect("sweep task")
            .expect("sweep"),
        0
    );
    assert_eq!(f.cursor().await, 2);
    assert!(f.queued().await.is_empty());
    assert_eq!(
        f.blobs.local.get(f.space, f.file).await.expect("object"),
        b"late ciphertext"
    );
    assert_eq!(f.read("GET").await.status(), StatusCode::OK);
    f.finish().await;
}
