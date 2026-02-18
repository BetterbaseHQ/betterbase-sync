use serde::Deserialize;

use super::close_codes::CloseDirective;

#[derive(Debug, Deserialize)]
struct FrameTypeOnly {
    #[serde(rename = "type")]
    frame_type: i32,
}

pub fn validate_client_binary_frame(payload: &[u8]) -> Result<(), CloseDirective> {
    if payload.is_empty() {
        return Err(CloseDirective::protocol_error("empty binary frame"));
    }

    if payload == [0xF6] {
        return Ok(());
    }

    let frame: FrameTypeOnly = serde_cbor::from_slice(payload)
        .map_err(|_| CloseDirective::protocol_error("invalid cbor frame"))?;

    let _ = frame.frame_type;
    Ok(())
}

#[cfg(test)]
mod tests {
    use less_sync_core::protocol::CLOSE_PROTOCOL_ERROR;

    use super::validate_client_binary_frame;

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
        let frame = serde_cbor::to_vec(&serde_json::json!({
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
}
