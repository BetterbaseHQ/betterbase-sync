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

/// Registry key: (space_id, member_did).
type RegistryKey = (String, String);
/// A connection's registration: its registry key plus its detach channel.
type ConnectionEntry = (RegistryKey, mpsc::Sender<String>);

#[derive(Default)]
pub(crate) struct SessionRegistry {
    /// Registry key -> registered connections.
    inner: RwLock<HashMap<RegistryKey, Vec<RegisteredConnection>>>,
    /// Reverse index: connection id -> its entries, so teardown is O(spaces
    /// per connection) instead of a full-registry scan.
    by_connection: RwLock<HashMap<String, Vec<ConnectionEntry>>>,
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

    /// Record that the connection owning `detach` reads `space` as `did`.
    /// Idempotent per connection; prunes registrations whose connection has
    /// closed.
    pub(crate) async fn register(
        &self,
        space: &str,
        did: &str,
        outbound: super::realtime::OutboundSender,
        detach: mpsc::Sender<String>,
        connection_id: &str,
    ) {
        let key = (space.to_owned(), did.to_owned());
        let mut inner = self.inner.write().await;
        {
            let entry = inner.entry(key.clone()).or_default();
            entry.retain(|conn| !conn.outbound.is_closed());
            if !entry.iter().any(|conn| conn.detach.same_channel(&detach)) {
                entry.push(RegisteredConnection {
                    outbound,
                    detach: detach.clone(),
                });
            }
        }
        if inner
            .get(&key)
            .is_some_and(|list| list.iter().any(|conn| conn.detach.same_channel(&detach)))
        {
            let mut by_connection = self.by_connection.write().await;
            let keys = by_connection.entry(connection_id.to_owned()).or_default();
            if !keys.iter().any(|(k, _)| *k == key) {
                keys.push((key, detach));
            }
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

    /// Remove every registration belonging to the given connection. Called
    /// on connection teardown so the registry does not grow without bound.
    pub(crate) async fn unregister_connection(&self, connection_id: &str) {
        let entries = {
            let mut by_connection = self.by_connection.write().await;
            by_connection.remove(connection_id).unwrap_or_default()
        };
        if entries.is_empty() {
            return;
        }
        let mut inner = self.inner.write().await;
        for (key, detach) in entries {
            if let Some(list) = inner.get_mut(&key) {
                // Remove only THIS connection's registration — the key may be
                // shared with other connections of the same member.
                list.retain(|conn| !conn.detach.same_channel(&detach));
                if list.is_empty() {
                    inner.remove(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Arc<SessionRegistry> {
        SessionRegistry::new()
    }

    #[tokio::test]
    async fn kick_detaches_only_the_targeted_member_and_space() {
        let reg = registry();
        let (victim_tx, mut victim_rx) = mpsc::channel::<String>(4);
        let (other_tx, mut other_rx) = mpsc::channel::<String>(4);
        let (outbound_victim, _rx) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);
        let (outbound_other, _rx2) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);

        reg.register(
            "space-a",
            "did:victim",
            outbound_victim,
            victim_tx,
            "conn-victim",
        )
        .await;
        reg.register(
            "space-a",
            "did:other",
            outbound_other,
            other_tx,
            "conn-other",
        )
        .await;

        let detached = reg.kick_member("space-a", "did:victim").await;
        assert_eq!(detached, 1);
        assert_eq!(victim_rx.recv().await, Some("space-a".to_owned()));
        // The other member's connection is untouched.
        assert!(other_rx.try_recv().is_err());

        // The victim's entry is gone; a second kick finds nothing.
        assert_eq!(reg.kick_member("space-a", "did:victim").await, 0);
    }

    #[tokio::test]
    async fn unregister_connection_removes_only_that_connections_entries() {
        let reg = registry();
        // Two connections of the same member, plus another member.
        let (tx1, mut rx1) = mpsc::channel::<String>(4);
        let (tx2, _rx2) = mpsc::channel::<String>(4);
        let (tx3, mut rx3) = mpsc::channel::<String>(4);
        let (out1, _) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);
        let (out2, _) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);
        let (out3, _) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);

        reg.register("space-a", "did:member", out1, tx1, "conn-1")
            .await;
        reg.register("space-b", "did:member", out2, tx2, "conn-1")
            .await;
        reg.register("space-a", "did:member", out3, tx3, "conn-2")
            .await;

        reg.unregister_connection("conn-1").await;

        // conn-1's registrations are gone; conn-2 still receives kicks.
        let detached = reg.kick_member("space-a", "did:member").await;
        assert_eq!(detached, 1);
        assert!(rx1.try_recv().is_err());
        assert_eq!(rx3.recv().await, Some("space-a".to_owned()));
        // conn-1's space-b entry is gone too.
        assert_eq!(reg.kick_member("space-b", "did:member").await, 0);
    }

    #[tokio::test]
    async fn register_is_idempotent_per_connection() {
        let reg = registry();
        let (tx, mut rx) = mpsc::channel::<String>(4);
        let (out, _) = mpsc::channel::<super::super::realtime::OutboundFrame>(4);

        reg.register("space-a", "did:m", out.clone(), tx.clone(), "conn-1")
            .await;
        reg.register("space-a", "did:m", out, tx, "conn-1").await;

        let detached = reg.kick_member("space-a", "did:m").await;
        assert_eq!(detached, 1, "duplicate registration must not accumulate");
        assert_eq!(rx.recv().await, Some("space-a".to_owned()));
    }
}
