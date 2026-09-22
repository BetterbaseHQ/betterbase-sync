use betterbase_sync_core::protocol::{RpcError, RPC_CHUNK, RPC_NOTIFICATION, RPC_RESPONSE};

use super::FederationPeerError;

#[derive(Debug, serde::Serialize)]
pub(super) struct OutboundRequestFrame<'a, T>
where
    T: serde::Serialize,
{
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    pub(super) id: &'a str,
    pub(super) method: &'a str,
    pub(super) params: &'a T,
}

#[derive(Debug)]
pub(super) enum InboundFrame {
    Response(InboundResponseFrame),
    Chunk(InboundChunkFrame),
    Notification(InboundNotificationFrame),
    Other,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct InboundResponseFrame {
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    pub(super) id: String,
    #[serde(default)]
    pub(super) result: Option<betterbase_sync_core::protocol::CborValue>,
    #[serde(default)]
    pub(super) error: Option<RpcError>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct InboundChunkFrame {
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) data: betterbase_sync_core::protocol::CborValue,
}

/// A notification pushed by the peer outside any request/response exchange.
/// `space` is extracted from `params` (every federation notification shape —
/// sync/membership/file/revoked — carries it there) for the subscription gate.
#[derive(Debug, serde::Deserialize)]
pub(super) struct InboundNotificationFrame {
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    #[serde(rename = "method")]
    pub(super) method: String,
    #[serde(default = "null_params", deserialize_with = "default_cbor_value")]
    pub(super) params: betterbase_sync_core::protocol::CborValue,
    #[serde(skip)]
    pub(super) space: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct FrameTag {
    #[serde(rename = "type")]
    frame_type: i32,
}

#[derive(Debug, serde::Deserialize)]
struct SpaceEnvelope {
    #[serde(default)]
    space: Option<String>,
}

fn default_cbor_value<'de, D>(
    deserializer: D,
) -> Result<betterbase_sync_core::protocol::CborValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Option::<betterbase_sync_core::protocol::CborValue>::deserialize(deserializer)
        .map(|value| value.unwrap_or(betterbase_sync_core::protocol::CborValue::Null))
}

fn null_params() -> betterbase_sync_core::protocol::CborValue {
    betterbase_sync_core::protocol::CborValue::Null
}

/// Extract the target space from a notification payload (it lives inside
/// `params` for every federation notification shape).
pub(super) fn notification_space(
    params: &betterbase_sync_core::protocol::CborValue,
) -> Option<String> {
    let encoded = minicbor_serde::to_vec(params).ok()?;
    minicbor_serde::from_slice::<SpaceEnvelope>(&encoded)
        .ok()
        .and_then(|envelope| envelope.space)
}

pub(super) fn encode_request_frame<T>(
    request_id: &str,
    method: &str,
    params: &T,
) -> Result<Vec<u8>, FederationPeerError>
where
    T: serde::Serialize,
{
    minicbor_serde::to_vec(&OutboundRequestFrame {
        frame_type: betterbase_sync_core::protocol::RPC_REQUEST,
        id: request_id,
        method,
        params,
    })
    .map_err(|error| FederationPeerError::Encode(error.to_string()))
}

pub(super) fn decode_inbound_frame(payload: &[u8]) -> Result<InboundFrame, FederationPeerError> {
    let tag: FrameTag = minicbor_serde::from_slice(payload)
        .map_err(|error| FederationPeerError::Decode(error.to_string()))?;

    match tag.frame_type {
        RPC_RESPONSE => {
            let response: InboundResponseFrame = minicbor_serde::from_slice(payload)
                .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
            Ok(InboundFrame::Response(response))
        }
        RPC_CHUNK => {
            let chunk: InboundChunkFrame = minicbor_serde::from_slice(payload)
                .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
            Ok(InboundFrame::Chunk(chunk))
        }
        RPC_NOTIFICATION => {
            let mut notification: InboundNotificationFrame = minicbor_serde::from_slice(payload)
                .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
            // The space lives inside params for every federation
            // notification shape (sync/membership/file/revoked).
            if let Ok(encoded_params) = minicbor_serde::to_vec(&notification.params) {
                if let Ok(envelope) = minicbor_serde::from_slice::<SpaceEnvelope>(&encoded_params) {
                    notification.space = envelope.space;
                }
            }
            Ok(InboundFrame::Notification(notification))
        }
        _ => Ok(InboundFrame::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_inbound_frame, InboundFrame};

    #[test]
    fn decodes_notification_with_params_space() {
        // Serialized the way serde would produce it: space inside params.
        #[derive(serde::Serialize)]
        struct Frame {
            #[serde(rename = "type")]
            frame_type: i32,
            method: &'static str,
            params: SpaceParams,
        }
        #[derive(serde::Serialize)]
        struct SpaceParams {
            space: &'static str,
            cursor: i64,
        }
        let encoded = minicbor_serde::to_vec(&Frame {
            frame_type: betterbase_sync_core::protocol::RPC_NOTIFICATION,
            method: "sync",
            params: SpaceParams {
                space: "space-1",
                cursor: 3,
            },
        })
        .expect("encode notification");

        let decoded = decode_inbound_frame(&encoded).expect("decode notification");
        match decoded {
            InboundFrame::Notification(notification) => {
                assert_eq!(notification.method, "sync");
                assert_eq!(notification.space.as_deref(), Some("space-1"));
            }
            other => panic!("expected notification frame, got {other:?}"),
        }
    }
}
