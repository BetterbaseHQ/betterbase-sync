//! Worker scheduling, retry and cancellation with a controlled Tokio clock.
use super::*;
use async_trait::async_trait;
use betterbase_sync_api::{FileBlobStorage, FileBlobStorageError, FileDeletionQueue};
use betterbase_sync_storage::{FileOperationLock, PendingFileDeletion, StorageError};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;
use uuid::Uuid;

struct Queue {
    calls: AtomicUsize,
    completed: AtomicUsize,
    outcomes: Mutex<VecDeque<Result<Vec<PendingFileDeletion>, StorageError>>>,
}
#[async_trait]
impl FileDeletionQueue for Queue {
    async fn lock_file(&self, _: Uuid, _: Uuid) -> Result<FileOperationLock, StorageError> {
        Ok(Box::new(()))
    }
    async fn pending_file_deletions(
        &self,
        _: SystemTime,
        limit: usize,
    ) -> Result<Vec<PendingFileDeletion>, StorageError> {
        assert_eq!(limit, 500);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcomes
            .lock()
            .expect("outcomes")
            .pop_front()
            .unwrap_or(Ok(Vec::new()))
    }
    async fn file_exists(&self, _: Uuid, _: Uuid) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn file_deletion_due(
        &self,
        _: Uuid,
        _: Uuid,
        _: SystemTime,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }
    async fn clear_file_deletion_if_live(&self, _: Uuid, _: Uuid) -> Result<(), StorageError> {
        panic!("no live files")
    }
    async fn complete_file_deletion(&self, _: Uuid, _: Uuid) -> Result<(), StorageError> {
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Blobs(AtomicUsize);
#[async_trait]
impl FileBlobStorage for Blobs {
    async fn store(&self, _: Uuid, _: Uuid, _: &[u8]) -> Result<bool, FileBlobStorageError> {
        panic!("GC does not upload")
    }
    async fn get(&self, _: Uuid, _: Uuid) -> Result<Vec<u8>, FileBlobStorageError> {
        panic!("GC does not download")
    }
    async fn delete(&self, _: Uuid, _: Uuid) -> Result<bool, FileBlobStorageError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}
fn queue(outcomes: Vec<Result<Vec<PendingFileDeletion>, StorageError>>) -> Arc<Queue> {
    Arc::new(Queue {
        calls: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        outcomes: Mutex::new(outcomes.into()),
    })
}
async fn tick(seconds: u64) {
    tokio::time::advance(Duration::from_secs(seconds)).await;
    tokio::task::yield_now().await;
}

#[tokio::test(start_paused = true)]
async fn file_gc_waits_for_interval_retries_errors_and_collects_on_later_passes() {
    let queue = queue(vec![
        Err(StorageError::Unavailable),
        Ok(Vec::new()),
        Ok(vec![PendingFileDeletion {
            space_id: Uuid::new_v4(),
            file_id: Uuid::new_v4(),
        }]),
    ]);
    let blobs = Arc::new(Blobs(AtomicUsize::new(0)));
    let worker = tokio::spawn(file_gc_loop(
        queue.clone(),
        blobs.clone(),
        Duration::from_secs(1),
        Duration::from_secs(900),
    ));
    tokio::task::yield_now().await;
    assert_eq!(queue.calls.load(Ordering::SeqCst), 0);
    tick(900).await;
    assert_eq!(queue.calls.load(Ordering::SeqCst), 1);
    assert!(!worker.is_finished());
    tick(900).await;
    assert_eq!(queue.calls.load(Ordering::SeqCst), 2);
    tick(900).await;
    assert_eq!(queue.completed.load(Ordering::SeqCst), 1);
    assert_eq!(blobs.0.load(Ordering::SeqCst), 1);
    worker.abort();
    assert!(worker.await.expect_err("cancelled worker").is_cancelled());
    tick(900).await;
    assert_eq!(queue.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn file_gc_does_not_query_storage_when_cutoff_cannot_be_represented() {
    let queue = queue(Vec::new());
    let worker = tokio::spawn(file_gc_loop(
        queue.clone(),
        Arc::new(Blobs(AtomicUsize::new(0))),
        Duration::MAX,
        Duration::from_secs(900),
    ));
    tokio::task::yield_now().await;
    tick(900).await;
    assert_eq!(queue.calls.load(Ordering::SeqCst), 0);
    assert!(!worker.is_finished());
    worker.abort();
    assert!(worker.await.expect_err("cancelled worker").is_cancelled());
}

struct Watcher(tokio::sync::mpsc::UnboundedSender<Arc<[u8]>>);
impl betterbase_sync_realtime::broker::Subscriber for Watcher {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        self.0.send(payload).is_ok()
    }
    fn exclude_id(&self) -> &str {
        "watcher"
    }
    fn mailbox_id(&self) -> &str {
        "watcher"
    }
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}
#[tokio::test(start_paused = true)]
async fn presence_worker_stays_running_and_leave_broadcast_uses_protocol_frame() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    broker
        .register_subscriber(Arc::new(Watcher(tx)), &["space".into()])
        .await
        .expect("watcher");
    let worker = tokio::spawn(presence_cleanup_loop(
        Arc::new(betterbase_sync_api::PresenceRegistry::new()),
        broker.clone(),
    ));
    tokio::task::yield_now().await;
    tick(15).await;
    assert!(!worker.is_finished());
    broadcast_presence_leave(&broker, "space", "pseudonym").await;
    let frame: serde_json::Value =
        minicbor_serde::from_slice(&rx.try_recv().expect("leave notification")).expect("frame");
    assert_eq!(
        frame["type"],
        betterbase_sync_core::protocol::RPC_NOTIFICATION
    );
    assert_eq!(frame["method"], "presence.leave");
    assert_eq!(frame["params"]["space"], "space");
    assert_eq!(frame["params"]["peer"], "pseudonym");
    worker.abort();
    assert!(worker.await.expect_err("cancelled worker").is_cancelled());
}
