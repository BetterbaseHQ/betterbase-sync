use serde::Deserialize;

use super::close_codes::CloseDirective;
use less_sync_core::protocol::{RPC_CHUNK, RPC_NOTIFICATION, RPC_REQUEST, RPC_RESPONSE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Keepalive,
    Request { id: String, method: String },
    Notification { method: String },
    Response,
    Chunk,
    UnknownType,
}

#[derive(Debug, Deserialize)]
struct DecodedFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id", default)]
    id: String,
    #[serde(rename = "method", default)]
    method: String,
}

pub fn parse_client_binary_frame(payload: &[u8]) -> Result<ClientFrame, CloseDirective> {
    if payload.is_empty() {
        return Err(CloseDirective::protocol_error("empty binary frame"));
    }

    if payload == [0xF6] {
        return Ok(ClientFrame::Keepalive);
    }

    let frame: DecodedFrame = minicbor_serde::from_slice(payload)
        .map_err(|_| CloseDirective::protocol_error("invalid cbor frame"))?;

    match frame.frame_type {
        RPC_REQUEST => Ok(ClientFrame::Request {
            id: frame.id,
            method: frame.method,
        }),
        RPC_NOTIFICATION => Ok(ClientFrame::Notification {
            method: frame.method,
        }),
        RPC_RESPONSE => Ok(ClientFrame::Response),
        RPC_CHUNK => Ok(ClientFrame::Chunk),
        _ => Ok(ClientFrame::UnknownType),
    }
}

pub fn validate_client_binary_frame(payload: &[u8]) -> Result<(), CloseDirective> {
    let _ = parse_client_binary_frame(payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use less_sync_core::protocol::CLOSE_PROTOCOL_ERROR;
    use less_sync_core::protocol::{RPC_CHUNK, RPC_NOTIFICATION, RPC_REQUEST, RPC_RESPONSE};

    use super::{parse_client_binary_frame, validate_client_binary_frame, ClientFrame};

    #[test]
    fn rejects_empty_binary_frame() {
        let error =
            validate_client_binary_frame(&[]).expect_err("empty binary frame must be rejected");
        assert_eq!(error.code, CLOSE_PROTOCOL_ERROR);
    }

    #[test]
    fn rejects_invalid_cbor() {
        let error = validate_client_binary_frame(&[0xFF, 0xFF, 0xFF])
            .expect_err("invalid CBOR must be rejected");
        assert_eq!(error.code, CLOSE_PROTOCOL_ERROR);
    }

    #[test]
    fn rejects_truncated_cbor() {
        let error =
            validate_client_binary_frame(&[0xA5]).expect_err("truncated CBOR must be rejected");
        assert_eq!(error.code, CLOSE_PROTOCOL_ERROR);
    }

    #[test]
    fn allows_unknown_frame_types() {
        let frame = minicbor_serde::to_vec(serde_json::json!({
            "type": 99,
            "method": "noop",
            "id": "req-1"
        }))
        .expect("encode frame");
        validate_client_binary_frame(&frame).expect("unknown frame type should not close");
    }

    #[test]
    fn allows_keepalive_null() {
        validate_client_binary_frame(&[0xF6]).expect("CBOR null keepalive should be accepted");
    }

    #[test]
    fn parses_request_frame() {
        let frame = minicbor_serde::to_vec(serde_json::json!({
            "type": RPC_REQUEST,
            "id": "req-1",
            "method": "subscribe",
            "params": {}
        }))
        .expect("encode");
        let parsed = parse_client_binary_frame(&frame).expect("parse");
        assert_eq!(
            parsed,
            ClientFrame::Request {
                id: "req-1".to_owned(),
                method: "subscribe".to_owned()
            }
        );
    }

    #[test]
    fn parses_notification_frame() {
        let frame = minicbor_serde::to_vec(serde_json::json!({
            "type": RPC_NOTIFICATION,
            "method": "presence.set",
            "params": {}
        }))
        .expect("encode");
        let parsed = parse_client_binary_frame(&frame).expect("parse");
        assert_eq!(
            parsed,
            ClientFrame::Notification {
                method: "presence.set".to_owned()
            }
        );
    }

    #[test]
    fn parses_response_and_chunk_frames() {
        let response = minicbor_serde::to_vec(serde_json::json!({
            "type": RPC_RESPONSE,
            "id": "r-1",
            "result": {}
        }))
        .expect("encode response");
        assert_eq!(
            parse_client_binary_frame(&response).expect("parse response"),
            ClientFrame::Response
        );

        let chunk = minicbor_serde::to_vec(serde_json::json!({
            "type": RPC_CHUNK,
            "id": "c-1",
            "name": "pull.record",
            "data": {}
        }))
        .expect("encode chunk");
        assert_eq!(
            parse_client_binary_frame(&chunk).expect("parse chunk"),
            ClientFrame::Chunk
        );
    }
}
