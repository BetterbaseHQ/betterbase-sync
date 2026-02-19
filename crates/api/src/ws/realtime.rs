use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    WsEventData, WsPresenceData, WsPresenceLeaveData, WsSyncData, WsSyncRecord,
    CLOSE_TOO_MANY_CONNECTIONS, RPC_NOTIFICATION,
};
use less_sync_realtime::broker::{BrokerError, MultiBroker, Subscriber, SubscriberId};
use less_sync_realtime::ws::CloseDirective;
use serde::Serialize;
use std::collections::HashSet;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

const OUTBOUND_CHANNEL_SIZE: usize = 64;

pub(crate) type OutboundSender = mpsc::Sender<OutboundFrame>;
pub(crate) type OutboundReceiver = mpsc::Receiver<OutboundFrame>;

#[derive(Debug)]
pub(crate) enum OutboundFrame {
    Binary(Arc<[u8]>),
    Close(CloseDirective),
}

#[derive(Clone)]
pub(crate) struct RealtimeSession {
    broker: Arc<MultiBroker>,
    subscriber_id: SubscriberId,
    exclude_id: String,
    subscribed_spaces: Arc<RwLock<HashSet<String>>>,
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
                key_generation: 0,
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

    pub(crate) async fn unregister(&self) {
        let _ = self.broker.unregister_subscriber(self.subscriber_id).await;
    }

    async fn broadcast_notification<T>(&self, space_id: &str, method: &str, params: T)
    where
        T: Serialize,
    {
        let frame = RpcNotificationFrame {
            frame_type: RPC_NOTIFICATION,
            method,
            params,
        };
        let encoded = match serde_cbor::to_vec(&frame) {
            Ok(encoded) => encoded,
            Err(_) => return,
        };
        let _ = self
            .broker
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
    closed: Arc<AtomicBool>,
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
        closed,
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
    closed: Arc<AtomicBool>,
}

impl Subscriber for ConnectionSubscriber {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        self.outbound
            .try_send(OutboundFrame::Binary(payload))
            .is_ok()
    }

    fn exclude_id(&self) -> &str {
        &self.exclude_id
    }

    fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.outbound.is_closed()
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
