use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use betterbase_sync_auth::AuthContext;
use betterbase_sync_core::protocol::{
    WsEventData, WsFileData, WsMembershipData, WsPresenceData, WsPresenceLeaveData, WsRevokedData,
    WsSyncData, WsSyncRecord, CLOSE_TOO_MANY_CONNECTIONS, RPC_NOTIFICATION,
};
use betterbase_sync_realtime::broker::{BrokerError, MultiBroker, Subscriber, SubscriberId};
use betterbase_sync_realtime::ws::CloseDirective;
use serde::Serialize;
use std::collections::HashSet;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, Notify};

const OUTBOUND_CHANNEL_SIZE: usize = 64;

pub(crate) type OutboundSender = mpsc::Sender<OutboundFrame>;
pub(crate) type OutboundReceiver = mpsc::Receiver<OutboundFrame>;

#[derive(Debug)]
pub(crate) enum OutboundFrame {
    Binary(Arc<[u8]>),
    Close(CloseDirective),
}

#[derive(Default)]
pub(super) struct ConnectionState {
    closed: AtomicBool,
    slow_consumer: Notify,
}

impl ConnectionState {
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub(super) async fn slow_consumer(&self) {
        self.slow_consumer.notified().await;
    }
}

#[derive(Clone)]
pub(crate) struct RealtimeSession {
    broker: Arc<MultiBroker>,
    subscriber_id: SubscriberId,
    exclude_id: String,
    subscribed_spaces: Arc<RwLock<HashSet<String>>>,
    /// Sends a "detach this space" command to the connection's main loop
    /// (revocation teardown — AUD-024 — removes subscriptions without
    /// closing the connection the member still uses for other spaces).
    detach_tx: mpsc::Sender<String>,
}

impl RealtimeSession {
    pub(crate) async fn add_spaces(&self, spaces: &[String]) -> usize {
        if spaces.is_empty() {
            return 0;
        }

        let mut added = Vec::new();
        {
            let mut subscribed = self.subscribed_spaces.write().await;
            for space_id in spaces {
                if subscribed.insert(space_id.clone()) {
                    added.push(space_id.clone());
                }
            }
        }

        if !added.is_empty() {
            let _ = self.broker.add_spaces(self.subscriber_id, &added).await;
        }
        added.len()
    }

    pub(crate) async fn remove_spaces(&self, spaces: &[String]) -> usize {
        if spaces.is_empty() {
            return 0;
        }

        let mut removed = Vec::new();
        {
            let mut subscribed = self.subscribed_spaces.write().await;
            for space_id in spaces {
                if subscribed.remove(space_id) {
                    removed.push(space_id.clone());
                }
            }
        }

        if !removed.is_empty() {
            let _ = self
                .broker
                .remove_spaces(self.subscriber_id, &removed)
                .await;
        }
        removed.len()
    }

    pub(crate) async fn is_subscribed(&self, space_id: &str) -> bool {
        let subscribed = self.subscribed_spaces.read().await;
        subscribed.contains(space_id)
    }

    pub(crate) async fn subscribed_space_count(&self) -> usize {
        let subscribed = self.subscribed_spaces.read().await;
        subscribed.len()
    }

    pub(crate) fn peer_id(&self) -> &str {
        &self.exclude_id
    }

    /// This connection's registry identity (used for teardown cleanup).
    pub(crate) fn connection_id(&self) -> &str {
        &self.exclude_id
    }

    /// Clone of the detach-command sender (registry use, AUD-024).
    pub(crate) fn detach_sender(&self) -> mpsc::Sender<String> {
        self.detach_tx.clone()
    }

    pub(crate) async fn broadcast_sync(
        &self,
        space_id: &str,
        cursor: i64,
        records: &[WsSyncRecord],
    ) {
        if records.is_empty() {
            return;
        }

        self.broadcast_notification(
            space_id,
            "sync",
            WsSyncData {
                space: space_id.to_owned(),
                prev: cursor.saturating_sub(1),
                cursor,
                epoch: 0,
                rewrap_epoch: None,
                records: records.to_vec(),
            },
        )
        .await;
    }

    pub(crate) async fn broadcast_presence(&self, space_id: &str, peer: &str, data: Vec<u8>) {
        self.broadcast_notification(
            space_id,
            "presence",
            WsPresenceData {
                space: space_id.to_owned(),
                peer: peer.to_owned(),
                data,
            },
        )
        .await;
    }

    pub(crate) async fn broadcast_presence_leave(&self, space_id: &str, peer: &str) {
        self.broadcast_notification(
            space_id,
            "presence.leave",
            WsPresenceLeaveData {
                space: space_id.to_owned(),
                peer: peer.to_owned(),
            },
        )
        .await;
    }

    pub(crate) async fn broadcast_event(&self, space_id: &str, peer: &str, data: Vec<u8>) {
        self.broadcast_notification(
            space_id,
            "event",
            WsEventData {
                space: space_id.to_owned(),
                peer: peer.to_owned(),
                data,
            },
        )
        .await;
    }

    /// Broadcast an invitation notification to all subscribers for the given mailbox.
    /// A random delay (1-5s) is applied to mitigate timing correlation.
    pub(crate) fn broadcast_invitation(&self, mailbox_id: &str) {
        let broker = Arc::clone(&self.broker);
        let mailbox_id = mailbox_id.to_owned();
        tokio::spawn(async move {
            // Random delay 1-5 seconds to mitigate timing correlation
            let delay_ms = {
                use rand::RngExt;
                1000 + (rand::rng().random::<u32>() % 4000) // 1000-4999ms
            };
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;

            let frame = RpcNotificationFrame {
                frame_type: RPC_NOTIFICATION,
                method: "invitation",
                params: std::collections::HashMap::<String, String>::new(),
            };
            let encoded = match minicbor_serde::to_vec(&frame) {
                Ok(encoded) => encoded,
                Err(_) => return,
            };
            let _ = broker.broadcast_mailbox(&mailbox_id, &encoded).await;
        });
    }

    pub(crate) async fn broadcast_membership(&self, space_id: &str, data: &WsMembershipData) {
        self.broadcast_notification(space_id, "membership", data)
            .await;
    }

    pub(crate) async fn broadcast_file(&self, space_id: &str, data: &WsFileData) {
        self.broadcast_notification(space_id, "file", data).await;
    }

    /// Broadcast a revocation notification to all watchers of a space.
    pub(crate) async fn broadcast_revocation(&self, space_id: &str, reason: &str) {
        self.broadcast_notification(
            space_id,
            "revoked",
            WsRevokedData {
                space: space_id.to_owned(),
                reason: reason.to_owned(),
            },
        )
        .await;
    }

    pub(crate) async fn unregister(&self) {
        let _ = self.broker.unregister_subscriber(self.subscriber_id).await;
    }

    pub(crate) async fn broadcast_notification<T>(&self, space_id: &str, method: &str, params: T)
    where
        T: Serialize,
    {
        let frame = RpcNotificationFrame {
            frame_type: RPC_NOTIFICATION,
            method,
            params,
        };
        let encoded = match minicbor_serde::to_vec(&frame) {
            Ok(encoded) => encoded,
            Err(_) => return,
        };
        self.broker
            .broadcast_space(space_id, &self.exclude_id, &encoded)
            .await;
    }
}

pub(crate) fn outbound_channel() -> (OutboundSender, OutboundReceiver) {
    mpsc::channel(OUTBOUND_CHANNEL_SIZE)
}

pub(crate) async fn send_close(outbound: &OutboundSender, close: CloseDirective) {
    let _ = outbound.send(OutboundFrame::Close(close)).await;
}

pub(crate) async fn send_binary(outbound: &OutboundSender, payload: Vec<u8>) {
    let _ = outbound
        .send(OutboundFrame::Binary(Arc::<[u8]>::from(payload)))
        .await;
}

pub(crate) async fn register_session(
    broker: Option<Arc<MultiBroker>>,
    auth: &AuthContext,
    connection_id: &str,
    outbound: OutboundSender,
    state: Arc<ConnectionState>,
    detach_tx: mpsc::Sender<String>,
) -> Result<Option<RealtimeSession>, CloseDirective> {
    let Some(broker) = broker else {
        return Ok(None);
    };

    let subscriber = Arc::new(ConnectionSubscriber {
        mailbox_id: if auth.mailbox_id.is_empty() {
            auth.client_id.clone()
        } else {
            auth.mailbox_id.clone()
        },
        exclude_id: connection_id.to_owned(),
        outbound,
        state,
    });
    let subscriber_id = broker
        .register_subscriber(subscriber, &[])
        .await
        .map_err(map_register_error)?;

    Ok(Some(RealtimeSession {
        broker,
        subscriber_id,
        exclude_id: connection_id.to_owned(),
        subscribed_spaces: Arc::new(RwLock::new(HashSet::new())),
        detach_tx,
    }))
}

fn map_register_error(error: BrokerError) -> CloseDirective {
    match error {
        BrokerError::TooManyConnections => CloseDirective {
            code: CLOSE_TOO_MANY_CONNECTIONS,
            reason: "too many connections",
        },
        BrokerError::SubscriberNotFound => CloseDirective {
            code: CLOSE_TOO_MANY_CONNECTIONS,
            reason: "failed to register connection",
        },
    }
}

struct ConnectionSubscriber {
    mailbox_id: String,
    exclude_id: String,
    outbound: OutboundSender,
    state: Arc<ConnectionState>,
}

impl Subscriber for ConnectionSubscriber {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        if self.is_closed() {
            return false;
        }
        match self.outbound.try_send(OutboundFrame::Binary(payload)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // A missed notification invalidates this connection's sync
                // state. Signal outside the full queue so the writer can
                // close it and the client can reconnect and pull its cursor.
                self.state.close();
                self.state.slow_consumer.notify_one();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    fn exclude_id(&self) -> &str {
        &self.exclude_id
    }

    fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Relaxed) || self.outbound.is_closed()
    }
}

#[derive(Debug, Serialize)]
struct RpcNotificationFrame<'a, T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "method")]
    method: &'a str,
    #[serde(rename = "params")]
    params: T,
}

/// Broadcast a notification to all watchers of a space from outside a WebSocket session
/// (e.g., from an HTTP handler). No sender is excluded.
pub(crate) async fn broadcast_to_space<T: Serialize>(
    broker: &MultiBroker,
    space_id: &str,
    method: &str,
    params: T,
) {
    let frame = RpcNotificationFrame {
        frame_type: RPC_NOTIFICATION,
        method,
        params,
    };
    let Ok(encoded) = minicbor_serde::to_vec(&frame) else {
        tracing::error!(method, "failed to serialize broadcast notification frame");
        return;
    };
    broker.broadcast_space(space_id, "", &encoded).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ws::Message;
    use betterbase_sync_core::protocol::CLOSE_SLOW_CONSUMER;
    use betterbase_sync_realtime::broker::BrokerConfig;
    use std::convert::Infallible;
    use std::time::Duration;

    #[tokio::test]
    async fn full_queue_closes_slow_consumer_without_disrupting_other_subscribers() {
        let broker = MultiBroker::new(BrokerConfig::default());
        let (slow_tx, slow_rx) = outbound_channel();
        let state = Arc::new(ConnectionState::default());
        let slow = Arc::new(ConnectionSubscriber {
            mailbox_id: "slow".to_owned(),
            exclude_id: "slow".to_owned(),
            outbound: slow_tx.clone(),
            state: Arc::clone(&state),
        });
        let (fast_tx, mut fast_rx) = outbound_channel();
        let fast = Arc::new(ConnectionSubscriber {
            mailbox_id: "fast".to_owned(),
            exclude_id: "fast".to_owned(),
            outbound: fast_tx,
            state: Arc::new(ConnectionState::default()),
        });
        broker
            .register_subscriber(slow.clone(), &["space".to_owned()])
            .await
            .expect("register slow subscriber");
        broker
            .register_subscriber(fast, &["space".to_owned()])
            .await
            .expect("register fast subscriber");

        for _ in 0..OUTBOUND_CHANNEL_SIZE {
            assert_eq!(broker.broadcast_space("space", "", b"update").await, 2);
            fast_rx
                .recv()
                .await
                .expect("fast subscriber receives update");
        }
        assert_eq!(broker.broadcast_space("space", "", b"overflow").await, 1);
        assert!(slow.is_closed());
        assert_eq!(broker.connection_count("slow").await, 0);
        assert_eq!(broker.connection_count("fast").await, 1);
        fast_rx
            .recv()
            .await
            .expect("fast subscriber receives overflow update");

        let messages = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Box::pin(futures_util::sink::unfold(
            Arc::clone(&messages),
            |messages, message| async move {
                messages.lock().expect("messages lock").push(message);
                Ok::<_, Infallible>(messages)
            },
        ));
        tokio::time::timeout(
            Duration::from_secs(1),
            super::super::writer::write_frames(sink, slow_rx, state, Duration::from_secs(1)),
        )
        .await
        .expect("writer closes despite full queue");
        assert!(slow_tx.is_closed());
        let messages = messages.lock().expect("messages lock");
        assert_eq!(messages.len(), 1, "close takes priority over queued data");
        assert!(matches!(
            &messages[0],
            Message::Close(Some(close)) if close.code == CLOSE_SLOW_CONSUMER as u16
        ));
    }
}
