use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::broker::{BrokerConfig, BrokerError, Subscriber, SubscriberId};

pub struct MultiBroker {
    config: BrokerConfig,
    next_subscriber_id: AtomicU64,
    state: RwLock<BrokerState>,
}

impl MultiBroker {
    #[must_use]
    pub fn new(config: BrokerConfig) -> Self {
        Self {
            config,
            next_subscriber_id: AtomicU64::new(1),
            state: RwLock::new(BrokerState {
                subscribers: HashMap::new(),
                subscriber_mailbox: HashMap::new(),
                subscriber_spaces: HashMap::new(),
                space_index: HashMap::new(),
                mailbox_index: HashMap::new(),
                connection_count: HashMap::new(),
                enforce_mailbox_connection_limit: true,
            }),
        }
    }

    pub async fn set_mailbox_connection_limit_enabled(&self, enabled: bool) {
        let mut state = self.state.write().await;
        state.enforce_mailbox_connection_limit = enabled;
    }

    pub async fn connection_count(&self, mailbox_id: &str) -> usize {
        let state = self.state.read().await;
        state.connection_count.get(mailbox_id).copied().unwrap_or(0)
    }

    pub async fn register_subscriber(
        &self,
        subscriber: Arc<dyn Subscriber>,
        space_ids: &[String],
    ) -> Result<SubscriberId, BrokerError> {
        let mailbox_id = subscriber.mailbox_id().to_owned();
        let mut state = self.state.write().await;
        let current_connections = state
            .connection_count
            .get(&mailbox_id)
            .copied()
            .unwrap_or(0);
        if state.enforce_mailbox_connection_limit
            && current_connections >= self.config.max_connections_per_mailbox
        {
            return Err(BrokerError::TooManyConnections);
        }

        let subscriber_id = SubscriberId(self.next_subscriber_id.fetch_add(1, Ordering::Relaxed));
        state
            .connection_count
            .insert(mailbox_id.clone(), current_connections + 1);
        state.subscribers.insert(subscriber_id, subscriber);
        state
            .subscriber_mailbox
            .insert(subscriber_id, mailbox_id.clone());
        state
            .mailbox_index
            .entry(mailbox_id)
            .or_default()
            .insert(subscriber_id);

        let space_set = space_ids
            .iter()
            .map(ToOwned::to_owned)
            .collect::<HashSet<_>>();
        state
            .subscriber_spaces
            .insert(subscriber_id, space_set.clone());
        for space_id in space_set {
            state
                .space_index
                .entry(space_id)
                .or_default()
                .insert(subscriber_id);
        }

        Ok(subscriber_id)
    }

    pub async fn unregister_subscriber(
        &self,
        subscriber_id: SubscriberId,
    ) -> Result<(), BrokerError> {
        let mut state = self.state.write().await;
        if state.remove_subscriber(subscriber_id) {
            Ok(())
        } else {
            Err(BrokerError::SubscriberNotFound)
        }
    }

    pub async fn add_spaces(
        &self,
        subscriber_id: SubscriberId,
        space_ids: &[String],
    ) -> Result<(), BrokerError> {
        let mut state = self.state.write().await;
        if !state.subscribers.contains_key(&subscriber_id) {
            return Err(BrokerError::SubscriberNotFound);
        }
        let added_spaces = space_ids.iter().map(ToOwned::to_owned).collect::<Vec<_>>();
        {
            let spaces = state.subscriber_spaces.entry(subscriber_id).or_default();
            for space_id in &added_spaces {
                spaces.insert(space_id.clone());
            }
        }
        for space_id in added_spaces {
            state
                .space_index
                .entry(space_id)
                .or_default()
                .insert(subscriber_id);
        }
        Ok(())
    }

    pub async fn remove_spaces(
        &self,
        subscriber_id: SubscriberId,
        space_ids: &[String],
    ) -> Result<(), BrokerError> {
        let mut state = self.state.write().await;
        if !state.subscribers.contains_key(&subscriber_id) {
            return Err(BrokerError::SubscriberNotFound);
        }
        let removed_spaces = space_ids.iter().map(ToOwned::to_owned).collect::<Vec<_>>();
        if let Some(current_spaces) = state.subscriber_spaces.get_mut(&subscriber_id) {
            for space_id in &removed_spaces {
                current_spaces.remove(space_id);
            }
        }
        for space_id in removed_spaces {
            if let Some(watchers) = state.space_index.get_mut(&space_id) {
                watchers.remove(&subscriber_id);
                if watchers.is_empty() {
                    state.space_index.remove(&space_id);
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast_space(&self, space_id: &str, exclude_id: &str, payload: &[u8]) -> usize {
        let recipients = {
            let state = self.state.read().await;
            state
                .space_index
                .get(space_id)
                .map(|watchers| {
                    watchers
                        .iter()
                        .filter_map(|subscriber_id| {
                            state
                                .subscribers
                                .get(subscriber_id)
                                .map(|subscriber| (*subscriber_id, Arc::clone(subscriber)))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

        if recipients.is_empty() {
            return 0;
        }

        let shared_payload = Arc::<[u8]>::from(payload.to_vec());
        let mut delivered_count = 0;
        let mut stale_subscribers = Vec::new();

        for (subscriber_id, subscriber) in recipients {
            if subscriber.is_closed() {
                stale_subscribers.push(subscriber_id);
                continue;
            }
            if subscriber.exclude_id() == exclude_id {
                continue;
            }
            if subscriber.send(Arc::clone(&shared_payload)) {
                delivered_count += 1;
            } else {
                stale_subscribers.push(subscriber_id);
            }
        }

        if !stale_subscribers.is_empty() {
            let mut state = self.state.write().await;
            for subscriber_id in stale_subscribers {
                let _ = state.remove_subscriber(subscriber_id);
            }
        }

        delivered_count
    }
}

struct BrokerState {
    subscribers: HashMap<SubscriberId, Arc<dyn Subscriber>>,
    subscriber_mailbox: HashMap<SubscriberId, String>,
    subscriber_spaces: HashMap<SubscriberId, HashSet<String>>,
    space_index: HashMap<String, HashSet<SubscriberId>>,
    mailbox_index: HashMap<String, HashSet<SubscriberId>>,
    connection_count: HashMap<String, usize>,
    enforce_mailbox_connection_limit: bool,
}

impl BrokerState {
    fn remove_subscriber(&mut self, subscriber_id: SubscriberId) -> bool {
        if self.subscribers.remove(&subscriber_id).is_none() {
            return false;
        }

        if let Some(spaces) = self.subscriber_spaces.remove(&subscriber_id) {
            for space_id in spaces {
                if let Some(watchers) = self.space_index.get_mut(&space_id) {
                    watchers.remove(&subscriber_id);
                    if watchers.is_empty() {
                        self.space_index.remove(&space_id);
                    }
                }
            }
        }

        if let Some(mailbox_id) = self.subscriber_mailbox.remove(&subscriber_id) {
            if let Some(subscribers) = self.mailbox_index.get_mut(&mailbox_id) {
                subscribers.remove(&subscriber_id);
                if subscribers.is_empty() {
                    self.mailbox_index.remove(&mailbox_id);
                }
            }

            if let Some(count) = self.connection_count.get_mut(&mailbox_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.connection_count.remove(&mailbox_id);
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::MultiBroker;
    use crate::broker::{BrokerConfig, BrokerError, Subscriber};

    struct MockSubscriber {
        mailbox_id: String,
        exclude_id: String,
        closed: AtomicBool,
        send_ok: AtomicBool,
        inbox: Mutex<Vec<Vec<u8>>>,
    }

    impl MockSubscriber {
        fn new(mailbox_id: &str, exclude_id: &str) -> Self {
            Self {
                mailbox_id: mailbox_id.to_owned(),
                exclude_id: exclude_id.to_owned(),
                closed: AtomicBool::new(false),
                send_ok: AtomicBool::new(true),
                inbox: Mutex::new(Vec::new()),
            }
        }

        fn received_count(&self) -> usize {
            self.inbox.lock().expect("lock inbox").len()
        }

        fn set_closed(&self, value: bool) {
            self.closed.store(value, Ordering::Relaxed);
        }

        fn set_send_ok(&self, value: bool) {
            self.send_ok.store(value, Ordering::Relaxed);
        }
    }

    impl Subscriber for MockSubscriber {
        fn send(&self, payload: Arc<[u8]>) -> bool {
            if !self.send_ok.load(Ordering::Relaxed) {
                return false;
            }
            self.inbox
                .lock()
                .expect("lock inbox")
                .push(payload.to_vec());
            true
        }

        fn exclude_id(&self) -> &str {
            &self.exclude_id
        }

        fn mailbox_id(&self) -> &str {
            &self.mailbox_id
        }

        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn register_enforces_mailbox_limit() {
        let broker = MultiBroker::new(BrokerConfig {
            max_connections_per_mailbox: 1,
        });
        let first = Arc::new(MockSubscriber::new("mailbox-a", "conn-a"));
        let second = Arc::new(MockSubscriber::new("mailbox-a", "conn-b"));

        let _first_id = broker
            .register_subscriber(first, &[String::from("space-a")])
            .await
            .expect("register first subscriber");
        let error = broker
            .register_subscriber(second.clone(), &[String::from("space-a")])
            .await
            .expect_err("second subscriber should exceed limit");
        assert_eq!(error, BrokerError::TooManyConnections);
        assert_eq!(broker.connection_count("mailbox-a").await, 1);

        broker.set_mailbox_connection_limit_enabled(false).await;
        broker
            .register_subscriber(second, &[String::from("space-a")])
            .await
            .expect("register with limits disabled");
        assert_eq!(broker.connection_count("mailbox-a").await, 2);
    }

    #[tokio::test]
    async fn broadcast_targets_space_and_respects_exclude_id() {
        let broker = MultiBroker::new(BrokerConfig::default());
        let sub_a = Arc::new(MockSubscriber::new("mailbox-a", "conn-a"));
        let sub_b = Arc::new(MockSubscriber::new("mailbox-a", "conn-b"));
        let sub_c = Arc::new(MockSubscriber::new("mailbox-b", "conn-c"));

        broker
            .register_subscriber(sub_a.clone(), &[String::from("space-a")])
            .await
            .expect("register a");
        broker
            .register_subscriber(sub_b.clone(), &[String::from("space-a")])
            .await
            .expect("register b");
        broker
            .register_subscriber(sub_c.clone(), &[String::from("space-b")])
            .await
            .expect("register c");

        let delivered = broker.broadcast_space("space-a", "conn-a", b"event").await;
        assert_eq!(delivered, 1);
        assert_eq!(sub_a.received_count(), 0);
        assert_eq!(sub_b.received_count(), 1);
        assert_eq!(sub_c.received_count(), 0);
    }

    #[tokio::test]
    async fn add_and_remove_spaces_update_fanout() {
        let broker = MultiBroker::new(BrokerConfig::default());
        let subscriber = Arc::new(MockSubscriber::new("mailbox-a", "conn-a"));
        let subscriber_id = broker
            .register_subscriber(subscriber.clone(), &[])
            .await
            .expect("register subscriber");

        let none = broker.broadcast_space("space-a", "", b"event").await;
        assert_eq!(none, 0);
        assert_eq!(subscriber.received_count(), 0);

        broker
            .add_spaces(subscriber_id, &[String::from("space-a")])
            .await
            .expect("add space");
        let one = broker.broadcast_space("space-a", "", b"event").await;
        assert_eq!(one, 1);
        assert_eq!(subscriber.received_count(), 1);

        broker
            .remove_spaces(subscriber_id, &[String::from("space-a")])
            .await
            .expect("remove space");
        let removed = broker.broadcast_space("space-a", "", b"event").await;
        assert_eq!(removed, 0);
        assert_eq!(subscriber.received_count(), 1);
    }

    #[tokio::test]
    async fn broadcast_evicts_closed_or_slow_subscribers() {
        let broker = MultiBroker::new(BrokerConfig {
            max_connections_per_mailbox: 2,
        });
        let closed = Arc::new(MockSubscriber::new("mailbox-a", "conn-a"));
        let slow = Arc::new(MockSubscriber::new("mailbox-a", "conn-b"));
        closed.set_closed(true);
        slow.set_send_ok(false);

        broker
            .register_subscriber(closed, &[String::from("space-a")])
            .await
            .expect("register closed");
        broker
            .register_subscriber(slow, &[String::from("space-a")])
            .await
            .expect("register slow");

        let delivered = broker.broadcast_space("space-a", "", b"event").await;
        assert_eq!(delivered, 0);
        assert_eq!(broker.connection_count("mailbox-a").await, 0);
    }

    #[tokio::test]
    async fn unregister_cleans_indexes_and_rejects_unknown_subscriber() {
        let broker = MultiBroker::new(BrokerConfig::default());
        let subscriber = Arc::new(MockSubscriber::new("mailbox-a", "conn-a"));
        let subscriber_id = broker
            .register_subscriber(subscriber.clone(), &[String::from("space-a")])
            .await
            .expect("register subscriber");

        broker
            .unregister_subscriber(subscriber_id)
            .await
            .expect("unregister subscriber");
        assert_eq!(broker.connection_count("mailbox-a").await, 0);
        assert_eq!(broker.broadcast_space("space-a", "", b"event").await, 0);

        let error = broker
            .unregister_subscriber(subscriber_id)
            .await
            .expect_err("double unregister should fail");
        assert_eq!(error, BrokerError::SubscriberNotFound);
    }
}
