use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message};
use betterbase_sync_core::protocol::CLOSE_SLOW_CONSUMER;
use futures_util::{Sink, SinkExt};

use super::realtime::{ConnectionState, OutboundFrame, OutboundReceiver};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const CBOR_NULL: &[u8] = &[0xF6];

pub(super) async fn write_frames<S>(
    mut socket: S,
    mut outbound: OutboundReceiver,
    state: Arc<ConnectionState>,
    write_timeout: Duration,
) where
    S: Sink<Message> + Unpin,
{
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await; // The first tick fires immediately.
    loop {
        let message = tokio::select! {
            // A close caused by lost notifications takes priority over queued
            // data, and does not need a free slot in the outbound channel.
            biased;
            _ = state.slow_consumer() => {
                Message::Close(Some(CloseFrame {
                    code: CLOSE_SLOW_CONSUMER as u16,
                    reason: "slow consumer".into(),
                }))
            }
            frame = outbound.recv() => {
                match frame {
                    Some(OutboundFrame::Binary(payload)) => {
                        Message::Binary(payload.to_vec().into())
                    }
                    Some(OutboundFrame::Close(close)) => Message::Close(Some(CloseFrame {
                        code: close.code as u16,
                        reason: close.reason.into(),
                    })),
                    None => break,
                }
            }
            _ = keepalive.tick() => Message::Binary(CBOR_NULL.to_vec().into()),
        };
        let closing = matches!(message, Message::Close(_));
        // Bound every write, including close and keepalive frames. If a write
        // stalls, drop the transport: sending a close on it could stall too.
        if !matches!(
            tokio::time::timeout(write_timeout, socket.send(message)).await,
            Ok(Ok(()))
        ) || closing
        {
            break;
        }
    }
    state.close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::realtime::outbound_channel;
    use betterbase_sync_realtime::ws::CloseDirective;
    use std::convert::Infallible;

    #[tokio::test]
    async fn stalled_writes_release_the_outbound_channel() {
        for frame in [
            OutboundFrame::Binary(Arc::from(&b"data"[..])),
            OutboundFrame::Close(CloseDirective::protocol_error("closing")),
        ] {
            let (outbound, receiver) = outbound_channel();
            outbound.send(frame).await.expect("queue frame");
            let sink = Box::pin(futures_util::sink::unfold((), |(), _message| async {
                std::future::pending::<Result<(), Infallible>>().await
            }));
            tokio::time::timeout(
                Duration::from_secs(1),
                write_frames(
                    sink,
                    receiver,
                    Arc::new(ConnectionState::default()),
                    Duration::from_millis(10),
                ),
            )
            .await
            .expect("stalled write must time out");
            assert!(outbound.is_closed(), "connection cleanup can now proceed");
        }
    }
}
