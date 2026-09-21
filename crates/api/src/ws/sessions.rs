//! Per-space session registry for revocation teardown (AUD-024).
//!
//! Tracks, per (space, member DID), the connections subscribed to that space
//! as that member. When a member is removed, the revocation handler detaches
//! every registered connection's subscription for that space: no further
//! ciphertext/DEK broadcasts reach the revoked socket, while the connection
//! itself stays available for the member's other spaces (re-subscribe
//! attempts are rejected by authorization).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

#[derive(Default)]
pub(crate) struct SessionRegistry {
    /// (space_id, member_did) -> registered connections.
    inner: RwLock<HashMap<(String, String), Vec<RegisteredConnection>>>,
}

struct RegisteredConnection {
    /// Outbound channel — used only to detect dead connections.
    outbound: super::realtime::OutboundSender,
    /// Detach-command channel into the connection's main loop.
    detach: mpsc::Sender<String>,
}

impl SessionRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record that a connection reads `space` as `did`. Idempotent per
    /// connection; prunes registrations whose connection has closed.
    pub(crate) async fn register(
        &self,
        space: &str,
        did: &str,
        outbound: super::realtime::OutboundSender,
        detach: mpsc::Sender<String>,
    ) {
        let key = (space.to_owned(), did.to_owned());
        let mut inner = self.inner.write().await;
        let entry = inner.entry(key).or_default();
        entry.retain(|conn| !conn.outbound.is_closed());
        if !entry.iter().any(|conn| conn.detach.same_channel(&detach)) {
            entry.push(RegisteredConnection { outbound, detach });
        }
    }

    /// Detach `space` from every connection subscribed as `did`. Returns the
    /// number of connections affected.
    pub(crate) async fn kick_member(&self, space: &str, did: &str) -> usize {
        let key = (space.to_owned(), did.to_owned());
        let connections = {
            let mut inner = self.inner.write().await;
            inner.remove(&key).unwrap_or_default()
        };
        let mut detached = 0;
        for conn in connections {
            if conn.detach.send(space.to_owned()).await.is_ok() {
                detached += 1;
            }
        }
        detached
    }

    /// Remove every registration belonging to the given connection (its
    /// detach channel identifies it). Called on connection teardown so the
    /// registry does not grow without bound.
    pub(crate) async fn unregister_connection(&self, detach: &mpsc::Sender<String>) {
        let mut inner = self.inner.write().await;
        let keys = inner.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if let Some(entry) = inner.get_mut(&key) {
                entry.retain(|conn| !conn.detach.same_channel(detach));
                if entry.is_empty() {
                    inner.remove(&key);
                }
            }
        }
    }
}
