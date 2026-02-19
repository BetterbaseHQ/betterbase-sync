use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub const MAX_SUBSCRIBE_SPACES: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederationQuotaLimits {
    pub max_spaces: usize,
    pub max_records_per_hour: u64,
    pub max_bytes_per_hour: u64,
    pub max_invitations_per_hour: u64,
    pub max_connections: usize,
}

impl Default for FederationQuotaLimits {
    fn default() -> Self {
        Self {
            max_spaces: 1_000,
            max_records_per_hour: 10_000,
            max_bytes_per_hour: 500 * 1024 * 1024,
            max_invitations_per_hour: 100,
            max_connections: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPeerStatus {
    pub domain: String,
    pub connections: usize,
    pub spaces: usize,
    pub records_this_hour: u64,
    pub bytes_this_hour: u64,
    pub invitations_this_hour: u64,
}

#[derive(Debug)]
pub struct FederationQuotaTracker {
    limits: FederationQuotaLimits,
    peers: Mutex<HashMap<String, PeerUsage>>,
}

impl FederationQuotaTracker {
    #[must_use]
    pub fn new(limits: FederationQuotaLimits) -> Self {
        Self {
            limits,
            peers: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn limits(&self) -> FederationQuotaLimits {
        self.limits
    }

    pub async fn try_add_connection(&self, domain: &str) -> bool {
        let mut peers = self.peers.lock().await;
        let usage = peers.entry(domain.to_owned()).or_default();
        if usage.connections >= self.limits.max_connections {
            return false;
        }
        usage.connections = usage.connections.saturating_add(1);
        true
    }

    pub async fn remove_connection(&self, domain: &str) {
        let mut peers = self.peers.lock().await;
        if let Some(usage) = peers.get_mut(domain) {
            usage.connections = usage.connections.saturating_sub(1);
        }
    }

    pub async fn try_add_spaces(&self, domain: &str, count: usize) -> bool {
        if count == 0 {
            return true;
        }

        let mut peers = self.peers.lock().await;
        let usage = peers.entry(domain.to_owned()).or_default();
        if usage.spaces.saturating_add(count) > self.limits.max_spaces {
            return false;
        }
        usage.spaces = usage.spaces.saturating_add(count);
        true
    }

    pub async fn remove_spaces(&self, domain: &str, count: usize) {
        if count == 0 {
            return;
        }

        let mut peers = self.peers.lock().await;
        if let Some(usage) = peers.get_mut(domain) {
            usage.spaces = usage.spaces.saturating_sub(count);
        }
    }

    pub async fn check_and_record_push(&self, domain: &str, records: usize, bytes: u64) -> bool {
        let mut peers = self.peers.lock().await;
        let usage = peers.entry(domain.to_owned()).or_default();
        usage.records.roll_if_needed();
        usage.bytes.roll_if_needed();

        if usage.records.count.saturating_add(records as u64) > self.limits.max_records_per_hour {
            return false;
        }
        if usage.bytes.count.saturating_add(bytes) > self.limits.max_bytes_per_hour {
            return false;
        }

        usage.records.count = usage.records.count.saturating_add(records as u64);
        usage.bytes.count = usage.bytes.count.saturating_add(bytes);
        true
    }

    pub async fn check_and_record_invitation(&self, domain: &str) -> bool {
        let mut peers = self.peers.lock().await;
        let usage = peers.entry(domain.to_owned()).or_default();
        usage.invitations.roll_if_needed();

        if usage.invitations.count.saturating_add(1) > self.limits.max_invitations_per_hour {
            return false;
        }

        usage.invitations.count = usage.invitations.count.saturating_add(1);
        true
    }

    pub async fn peer_status(&self, domain: &str) -> FederationPeerStatus {
        let mut peers = self.peers.lock().await;
        let usage = peers.entry(domain.to_owned()).or_default();
        usage.records.roll_if_needed();
        usage.bytes.roll_if_needed();
        usage.invitations.roll_if_needed();
        FederationPeerStatus {
            domain: domain.to_owned(),
            connections: usage.connections,
            spaces: usage.spaces,
            records_this_hour: usage.records.count,
            bytes_this_hour: usage.bytes.count,
            invitations_this_hour: usage.invitations.count,
        }
    }
}

#[derive(Debug, Clone)]
struct PeerUsage {
    connections: usize,
    spaces: usize,
    records: RollingHourCounter,
    bytes: RollingHourCounter,
    invitations: RollingHourCounter,
}

impl Default for PeerUsage {
    fn default() -> Self {
        Self {
            connections: 0,
            spaces: 0,
            records: RollingHourCounter::new(),
            bytes: RollingHourCounter::new(),
            invitations: RollingHourCounter::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct RollingHourCounter {
    count: u64,
    window_started: Instant,
}

impl RollingHourCounter {
    fn new() -> Self {
        Self {
            count: 0,
            window_started: Instant::now(),
        }
    }

    fn roll_if_needed(&mut self) {
        if self.window_started.elapsed() >= Duration::from_secs(60 * 60) {
            self.count = 0;
            self.window_started = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FederationQuotaLimits, FederationQuotaTracker};

    #[tokio::test]
    async fn connection_limit_is_enforced() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_connections: 1,
            ..FederationQuotaLimits::default()
        });

        assert!(tracker.try_add_connection("peer.example.com").await);
        assert!(!tracker.try_add_connection("peer.example.com").await);
        tracker.remove_connection("peer.example.com").await;
        assert!(tracker.try_add_connection("peer.example.com").await);
    }

    #[tokio::test]
    async fn space_limit_is_enforced() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_spaces: 2,
            ..FederationQuotaLimits::default()
        });

        assert!(tracker.try_add_spaces("peer.example.com", 2).await);
        assert!(!tracker.try_add_spaces("peer.example.com", 1).await);
        tracker.remove_spaces("peer.example.com", 1).await;
        assert!(tracker.try_add_spaces("peer.example.com", 1).await);
    }

    #[tokio::test]
    async fn push_limit_is_enforced() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_records_per_hour: 2,
            max_bytes_per_hour: 10,
            ..FederationQuotaLimits::default()
        });

        assert!(
            tracker
                .check_and_record_push("peer.example.com", 1, 5)
                .await
        );
        assert!(
            tracker
                .check_and_record_push("peer.example.com", 1, 5)
                .await
        );
        assert!(
            !tracker
                .check_and_record_push("peer.example.com", 1, 1)
                .await
        );
    }

    #[tokio::test]
    async fn invitation_limit_is_enforced() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_invitations_per_hour: 2,
            ..FederationQuotaLimits::default()
        });

        assert!(
            tracker
                .check_and_record_invitation("peer.example.com")
                .await
        );
        assert!(
            tracker
                .check_and_record_invitation("peer.example.com")
                .await
        );
        assert!(
            !tracker
                .check_and_record_invitation("peer.example.com")
                .await
        );
    }
}
