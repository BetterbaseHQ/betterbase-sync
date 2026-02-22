use super::super::realtime::{send_binary, OutboundSender};
use super::{RpcChunkFrame, RpcErrorFrame, RpcErrorPayload, RpcResultFrame, RESPONSE_FRAME_TYPE};
use betterbase_sync_core::protocol::{ERR_CODE_METHOD_NOT_FOUND, RPC_CHUNK};
use serde::Serialize;

pub(super) async fn send_method_not_found_response(
    outbound: &OutboundSender,
    id: &str,
    method: &str,
) {
    send_error_response(
        outbound,
        id,
        ERR_CODE_METHOD_NOT_FOUND,
        format!("unknown method: {method}"),
    )
    .await;
}

pub(super) async fn send_result_response<T>(outbound: &OutboundSender, id: &str, result: &T)
where
    T: Serialize,
{
    let frame = RpcResultFrame {
        frame_type: RESPONSE_FRAME_TYPE,
        id,
        result,
    };
    let encoded = match minicbor_serde::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    send_binary(outbound, encoded).await;
}

pub(super) async fn send_chunk_response<T>(
    outbound: &OutboundSender,
    id: &str,
    name: &str,
    data: &T,
) where
    T: Serialize,
{
    let frame = RpcChunkFrame {
        frame_type: RPC_CHUNK,
        id,
        name,
        data,
    };
    let encoded = match minicbor_serde::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    send_binary(outbound, encoded).await;
}

pub(super) async fn send_error_response(
    outbound: &OutboundSender,
    id: &str,
    code: &'static str,
    message: String,
) {
    let frame = RpcErrorFrame {
        frame_type: RESPONSE_FRAME_TYPE,
        id,
        error: RpcErrorPayload { code, message },
    };
    let encoded = match minicbor_serde::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    send_binary(outbound, encoded).await;
}
