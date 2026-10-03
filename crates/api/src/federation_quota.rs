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

    pub async fn all_peer_status(&self) -> Vec<FederationPeerStatus> {
        let mut peers = self.peers.lock().await;
        let mut statuses = Vec::with_capacity(peers.len());
        for (domain, usage) in peers.iter_mut() {
            usage.records.roll_if_needed();
            usage.bytes.roll_if_needed();
            usage.invitations.roll_if_needed();
            statuses.push(FederationPeerStatus {
                domain: domain.clone(),
                connections: usage.connections,
                spaces: usage.spaces,
                records_this_hour: usage.records.count,
                bytes_this_hour: usage.bytes.count,
                invitations_this_hour: usage.invitations.count,
            });
        }
        statuses
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
    async fn zero_limits_reject_work_but_allow_empty_operations() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_connections: 0,
            max_spaces: 0,
            max_records_per_hour: 0,
            max_bytes_per_hour: 0,
            max_invitations_per_hour: 0,
        });
        assert!(!tracker.try_add_connection("peer").await);
        assert!(!tracker.try_add_spaces("peer", 1).await);
        assert!(!tracker.check_and_record_push("peer", 1, 0).await);
        assert!(!tracker.check_and_record_push("peer", 0, 1).await);
        assert!(!tracker.check_and_record_invitation("peer").await);
        assert!(tracker.try_add_spaces("peer", 0).await);
        assert!(tracker.check_and_record_push("peer", 0, 0).await);
        let status = tracker.peer_status("peer").await;
        assert_eq!((status.connections, status.spaces), (0, 0));
        assert_eq!(
            (
                status.records_this_hour,
                status.bytes_this_hour,
                status.invitations_this_hour
            ),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn rejected_push_does_not_consume_either_quota() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_records_per_hour: 2,
            max_bytes_per_hour: 10,
            ..FederationQuotaLimits::default()
        });
        assert!(!tracker.check_and_record_push("peer", 1, 11).await);
        assert!(!tracker.check_and_record_push("peer", 3, 1).await);
        let status = tracker.peer_status("peer").await;
        assert_eq!((status.records_this_hour, status.bytes_this_hour), (0, 0));
        assert!(tracker.check_and_record_push("peer", 2, 10).await);
        assert!(!tracker.check_and_record_push("peer", 1, 0).await);
        assert!(!tracker.check_and_record_push("peer", 0, 1).await);
        let status = tracker.peer_status("peer").await;
        assert_eq!((status.records_this_hour, status.bytes_this_hour), (2, 10));
        assert!(tracker.check_and_record_push("other", 2, 10).await);
    }

    #[tokio::test]
    async fn expired_windows_reset_usage_but_preserve_connections_and_spaces() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits {
            max_records_per_hour: 1,
            max_bytes_per_hour: 1,
            max_invitations_per_hour: 1,
            ..FederationQuotaLimits::default()
        });
        assert!(tracker.try_add_connection("peer").await);
        assert!(tracker.try_add_spaces("peer", 1).await);
        assert!(tracker.check_and_record_push("peer", 1, 1).await);
        assert!(tracker.check_and_record_invitation("peer").await);
        {
            let mut peers = tracker.peers.lock().await;
            let usage = peers.get_mut("peer").expect("tracked peer");
            let expired = std::time::Instant::now() - std::time::Duration::from_secs(3601);
            usage.records.window_started = expired;
            usage.bytes.window_started = expired;
            usage.invitations.window_started = expired;
        }
        assert!(tracker.check_and_record_push("peer", 1, 1).await);
        assert!(tracker.check_and_record_invitation("peer").await);
        let status = tracker.peer_status("peer").await;
        assert_eq!((status.connections, status.spaces), (1, 1));
        assert_eq!((status.records_this_hour, status.bytes_this_hour), (1, 1));
        assert_eq!(status.invitations_this_hour, 1);
        assert!(!tracker.check_and_record_invitation("peer").await);
    }

    #[tokio::test]
    async fn concurrent_connection_attempts_cannot_exceed_limit() {
        let tracker = std::sync::Arc::new(FederationQuotaTracker::new(FederationQuotaLimits {
            max_connections: 3,
            ..FederationQuotaLimits::default()
        }));
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let tracker = tracker.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                tracker.try_add_connection("peer").await
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.expect("connection task"));
        }
        assert_eq!(accepted, 3);
        assert_eq!(tracker.peer_status("peer").await.connections, 3);
    }

    #[tokio::test]
    async fn removing_more_than_usage_does_not_underflow() {
        let tracker = FederationQuotaTracker::new(FederationQuotaLimits::default());
        tracker.remove_connection("unknown").await;
        tracker.remove_spaces("unknown", usize::MAX).await;
        assert!(tracker.all_peer_status().await.is_empty());
        assert!(tracker.try_add_connection("peer").await);
        assert!(tracker.try_add_spaces("peer", 1).await);
        tracker.remove_connection("peer").await;
        tracker.remove_connection("peer").await;
        tracker.remove_spaces("peer", usize::MAX).await;
        let status = tracker.peer_status("peer").await;
        assert_eq!((status.connections, status.spaces), (0, 0));
    }

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
