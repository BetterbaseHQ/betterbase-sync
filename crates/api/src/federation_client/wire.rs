use less_sync_core::protocol::{RpcError, RPC_CHUNK, RPC_RESPONSE};

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
    Other,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct InboundResponseFrame {
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    pub(super) id: String,
    #[serde(default)]
    pub(super) result: Option<serde_cbor::Value>,
    #[serde(default)]
    pub(super) error: Option<RpcError>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct InboundChunkFrame {
    #[serde(rename = "type")]
    pub(super) frame_type: i32,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) data: serde_cbor::Value,
}

#[derive(Debug, serde::Deserialize)]
struct FrameTag {
    #[serde(rename = "type")]
    frame_type: i32,
}

pub(super) fn encode_request_frame<T>(
    request_id: &str,
    method: &str,
    params: &T,
) -> Result<Vec<u8>, FederationPeerError>
where
    T: serde::Serialize,
{
    serde_cbor::to_vec(&OutboundRequestFrame {
        frame_type: less_sync_core::protocol::RPC_REQUEST,
        id: request_id,
        method,
        params,
    })
    .map_err(|error| FederationPeerError::Encode(error.to_string()))
}

pub(super) fn decode_inbound_frame(payload: &[u8]) -> Result<InboundFrame, FederationPeerError> {
    let tag: FrameTag = serde_cbor::from_slice(payload)
        .map_err(|error| FederationPeerError::Decode(error.to_string()))?;

    match tag.frame_type {
        RPC_RESPONSE => {
            let response: InboundResponseFrame = serde_cbor::from_slice(payload)
                .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
            Ok(InboundFrame::Response(response))
        }
        RPC_CHUNK => {
            let chunk: InboundChunkFrame = serde_cbor::from_slice(payload)
                .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
            Ok(InboundFrame::Chunk(chunk))
        }
        _ => Ok(InboundFrame::Other),
    }
}
