use std::collections::HashMap;
use std::time::Instant;

use hmac::{Hmac, Mac};
use less_sync_core::protocol::WsPresencePeer;
use sha2::Sha256;
use tokio::sync::RwLock;

pub(crate) const MAX_PRESENCE_DATA_BYTES: usize = 1024;
pub(crate) const MAX_EVENT_DATA_BYTES: usize = 4096;
/// Maximum number of presence entries per space.
const MAX_PRESENCE_PER_SPACE: usize = 100;
/// How long before a presence entry is considered stale.
const PRESENCE_STALE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
/// How often the cleanup loop should run (scheduled by crates/app).
const _PRESENCE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

struct PresenceEntry {
    data: Vec<u8>,
    last_seen: Instant,
}

pub struct PresenceRegistry {
    peer_secret: [u8; 32],
    spaces: RwLock<HashMap<String, HashMap<String, PresenceEntry>>>,
}

impl PresenceRegistry {
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            peer_secret: secret,
            spaces: RwLock::new(HashMap::new()),
        }
    }

    /// Derive a per-space pseudonym for a connection ID using
    /// HMAC-SHA256(secret, connID + "\0" + spaceID), truncated to 16 bytes (32 hex chars).
    /// Prevents cross-space identity correlation.
    pub fn peer_pseudonym(&self, conn_id: &str, space_id: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.peer_secret).expect("HMAC accepts any key size");
        mac.update(conn_id.as_bytes());
        mac.update(b"\0");
        mac.update(space_id.as_bytes());
        let result = mac.finalize().into_bytes();
        hex::encode(&result[..16])
    }
}

impl PresenceRegistry {
    /// Returns all current presence entries for a space, using pseudonymized peer IDs.
    pub(crate) async fn peers(&self, space_id: &str, exclude_peer: &str) -> Vec<WsPresencePeer> {
        let state = self.spaces.read().await;
        let Some(space_presence) = state.get(space_id) else {
            return Vec::new();
        };

        space_presence
            .iter()
            .filter_map(|(peer, entry)| {
                if peer == exclude_peer {
                    None
                } else {
                    Some(WsPresencePeer {
                        peer: self.peer_pseudonym(peer, space_id),
                        data: entry.data.clone(),
                    })
                }
            })
            .collect()
    }

    /// Stores a presence entry. Enforces per-space limit for new entries.
    /// Returns true if the entry was stored, false if rejected (at capacity).
    pub(crate) async fn set(&self, space_id: &str, peer: &str, data: Vec<u8>) -> bool {
        let mut state = self.spaces.write().await;
        let space_presence = state.entry(space_id.to_owned()).or_default();

        // Enforce per-space limit (only for new entries)
        if !space_presence.contains_key(peer) && space_presence.len() >= MAX_PRESENCE_PER_SPACE {
            return false;
        }

        space_presence.insert(
            peer.to_owned(),
            PresenceEntry {
                data,
                last_seen: Instant::now(),
            },
        );
        true
    }

    pub(crate) async fn clear(&self, space_id: &str, peer: &str) -> bool {
        let mut state = self.spaces.write().await;
        let Some(space_presence) = state.get_mut(space_id) else {
            return false;
        };

        let removed = space_presence.remove(peer).is_some();
        if space_presence.is_empty() {
            state.remove(space_id);
        }

        removed
    }

    pub(crate) async fn clear_peer(&self, peer: &str) -> Vec<String> {
        let mut state = self.spaces.write().await;
        let mut cleared_spaces = Vec::new();

        for (space_id, space_presence) in state.iter_mut() {
            if space_presence.remove(peer).is_some() {
                cleared_spaces.push(space_id.clone());
            }
        }

        state.retain(|_, entries| !entries.is_empty());
        cleared_spaces.sort_unstable();

        cleared_spaces
    }

    /// Remove stale presence entries and return (space_id, conn_id) pairs for leave broadcasts.
    async fn cleanup_stale(&self) -> Vec<(String, String)> {
        let cutoff = Instant::now() - PRESENCE_STALE_TIMEOUT;
        let mut state = self.spaces.write().await;
        let mut stale = Vec::new();

        for (space_id, space_presence) in state.iter_mut() {
            let stale_peers: Vec<String> = space_presence
                .iter()
                .filter(|(_, entry)| entry.last_seen < cutoff)
                .map(|(peer, _)| peer.clone())
                .collect();
            for peer in stale_peers {
                space_presence.remove(&peer);
                stale.push((space_id.clone(), peer));
            }
        }

        state.retain(|_, entries| !entries.is_empty());
        stale
    }

    /// Remove stale presence entries. Returns (space_id, pseudonymized_peer_id) pairs
    /// that should be broadcast as presence.leave notifications.
    pub async fn cleanup_stale_entries(&self) -> Vec<(String, String)> {
        let stale = self.cleanup_stale().await;
        stale
            .into_iter()
            .map(|(space_id, conn_id)| {
                let pseudonym = self.peer_pseudonym(&conn_id, &space_id);
                (space_id, pseudonym)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{PresenceRegistry, MAX_PRESENCE_PER_SPACE};

    #[tokio::test]
    async fn set_and_peers_excludes_requesting_peer() {
        let registry = PresenceRegistry::new();
        registry.set("space-1", "peer-a", vec![1, 2, 3]).await;
        registry.set("space-1", "peer-b", vec![4, 5, 6]).await;

        let peers = registry.peers("space-1", "peer-a").await;
        assert_eq!(peers.len(), 1);
        // Peer ID should be a pseudonym (32 hex chars), not the raw connection ID
        assert_ne!(peers[0].peer, "peer-b");
        assert_eq!(peers[0].peer.len(), 32);
        assert_eq!(peers[0].data, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn peers_returns_pseudonyms_not_raw_ids() {
        let registry = PresenceRegistry::new();
        registry.set("space-1", "conn-a", vec![1]).await;
        registry.set("space-2", "conn-a", vec![2]).await;

        let peers_s1 = registry.peers("space-1", "other").await;
        let peers_s2 = registry.peers("space-2", "other").await;
        assert_eq!(peers_s1.len(), 1);
        assert_eq!(peers_s2.len(), 1);
        // Same connection in different spaces should produce different pseudonyms
        assert_ne!(peers_s1[0].peer, peers_s2[0].peer);
        // Pseudonym should match what peer_pseudonym() returns
        assert_eq!(
            peers_s1[0].peer,
            registry.peer_pseudonym("conn-a", "space-1")
        );
    }

    #[tokio::test]
    async fn clear_removes_space_when_last_peer_leaves() {
        let registry = PresenceRegistry::new();
        registry.set("space-1", "peer-a", vec![1]).await;

        assert!(registry.clear("space-1", "peer-a").await);
        assert!(registry.peers("space-1", "peer-b").await.is_empty());
    }

    #[tokio::test]
    async fn clear_peer_returns_all_spaces_with_presence() {
        let registry = PresenceRegistry::new();
        registry.set("space-b", "peer-a", vec![1]).await;
        registry.set("space-a", "peer-a", vec![2]).await;
        registry.set("space-c", "peer-b", vec![3]).await;

        let cleared = registry.clear_peer("peer-a").await;
        assert_eq!(cleared, vec!["space-a".to_owned(), "space-b".to_owned()]);
        assert!(registry.peers("space-a", "peer-b").await.is_empty());
        assert!(registry.peers("space-b", "peer-b").await.is_empty());
        assert_eq!(registry.peers("space-c", "peer-a").await.len(), 1);
    }

    #[tokio::test]
    async fn set_enforces_per_space_limit() {
        let registry = PresenceRegistry::new();
        // Fill up to the limit
        for i in 0..MAX_PRESENCE_PER_SPACE {
            registry.set("space-1", &format!("peer-{i}"), vec![1]).await;
        }
        let peers = registry.peers("space-1", "nobody").await;
        assert_eq!(peers.len(), MAX_PRESENCE_PER_SPACE);

        // One more should be rejected
        registry.set("space-1", "peer-overflow", vec![2]).await;
        let peers = registry.peers("space-1", "nobody").await;
        assert_eq!(peers.len(), MAX_PRESENCE_PER_SPACE);

        // But updating an existing entry should succeed
        registry.set("space-1", "peer-0", vec![99]).await;
        let peers = registry.peers("space-1", "nobody").await;
        assert_eq!(peers.len(), MAX_PRESENCE_PER_SPACE);
    }

    #[tokio::test]
    async fn cleanup_stale_removes_old_entries() {
        let registry = PresenceRegistry::new();
        registry.set("space-1", "peer-a", vec![1]).await;

        // Manually age the entry
        {
            let mut state = registry.spaces.write().await;
            if let Some(space) = state.get_mut("space-1") {
                if let Some(entry) = space.get_mut("peer-a") {
                    entry.last_seen =
                        std::time::Instant::now() - std::time::Duration::from_secs(60);
                }
            }
        }

        let stale = registry.cleanup_stale().await;
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], ("space-1".to_owned(), "peer-a".to_owned()));
        assert!(registry.peers("space-1", "nobody").await.is_empty());
    }

    #[tokio::test]
    async fn peer_pseudonym_is_deterministic() {
        let registry = PresenceRegistry::new();
        let p1 = registry.peer_pseudonym("conn-1", "space-1");
        let p2 = registry.peer_pseudonym("conn-1", "space-1");
        assert_eq!(p1, p2);
    }

    #[tokio::test]
    async fn peer_pseudonym_differs_across_spaces() {
        let registry = PresenceRegistry::new();
        let p1 = registry.peer_pseudonym("conn-1", "space-1");
        let p2 = registry.peer_pseudonym("conn-1", "space-2");
        assert_ne!(p1, p2);
    }
}
