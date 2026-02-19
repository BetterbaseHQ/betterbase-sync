use std::collections::HashMap;

use less_sync_core::protocol::WsPresencePeer;
use tokio::sync::RwLock;

pub(crate) const MAX_PRESENCE_DATA_BYTES: usize = 1024;
pub(crate) const MAX_EVENT_DATA_BYTES: usize = 4096;

#[derive(Default)]
pub(crate) struct PresenceRegistry {
    spaces: RwLock<HashMap<String, HashMap<String, Vec<u8>>>>,
}

impl PresenceRegistry {
    pub(crate) async fn peers(&self, space_id: &str, exclude_peer: &str) -> Vec<WsPresencePeer> {
        let state = self.spaces.read().await;
        let Some(space_presence) = state.get(space_id) else {
            return Vec::new();
        };

        space_presence
            .iter()
            .filter_map(|(peer, data)| {
                if peer == exclude_peer {
                    None
                } else {
                    Some(WsPresencePeer {
                        peer: peer.clone(),
                        data: data.clone(),
                    })
                }
            })
            .collect()
    }

    pub(crate) async fn set(&self, space_id: &str, peer: &str, data: Vec<u8>) {
        let mut state = self.spaces.write().await;
        state
            .entry(space_id.to_owned())
            .or_default()
            .insert(peer.to_owned(), data);
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
}

#[cfg(test)]
mod tests {
    use super::PresenceRegistry;

    #[tokio::test]
    async fn set_and_peers_excludes_requesting_peer() {
        let registry = PresenceRegistry::default();
        registry.set("space-1", "peer-a", vec![1, 2, 3]).await;
        registry.set("space-1", "peer-b", vec![4, 5, 6]).await;

        let peers = registry.peers("space-1", "peer-a").await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer, "peer-b");
        assert_eq!(peers[0].data, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn clear_removes_space_when_last_peer_leaves() {
        let registry = PresenceRegistry::default();
        registry.set("space-1", "peer-a", vec![1]).await;

        assert!(registry.clear("space-1", "peer-a").await);
        assert!(registry.peers("space-1", "peer-b").await.is_empty());
    }

    #[tokio::test]
    async fn clear_peer_returns_all_spaces_with_presence() {
        let registry = PresenceRegistry::default();
        registry.set("space-b", "peer-a", vec![1]).await;
        registry.set("space-a", "peer-a", vec![2]).await;
        registry.set("space-c", "peer-b", vec![3]).await;

        let cleared = registry.clear_peer("peer-a").await;
        assert_eq!(cleared, vec!["space-a".to_owned(), "space-b".to_owned()]);
        assert!(registry.peers("space-a", "peer-b").await.is_empty());
        assert!(registry.peers("space-b", "peer-b").await.is_empty());
        assert_eq!(registry.peers("space-c", "peer-a").await.len(), 1);
    }
}
