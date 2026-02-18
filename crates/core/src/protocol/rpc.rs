use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

// RPC frame type discriminators for the less-rpc-v1 subprotocol.
pub const RPC_REQUEST: i32 = 0;
pub const RPC_RESPONSE: i32 = 1;
pub const RPC_NOTIFICATION: i32 = 2;
pub const RPC_CHUNK: i32 = 3;
pub const RPC_STREAM: i32 = RPC_CHUNK; // Alias for backward compatibility

// RPC error codes (generic, transport-level).
pub const ERR_CODE_INVALID_PARAMS: &str = "invalid_params";
pub const ERR_CODE_BAD_REQUEST: &str = "bad_request";
pub const ERR_CODE_FORBIDDEN: &str = "forbidden";
pub const ERR_CODE_NOT_FOUND: &str = "not_found";
pub const ERR_CODE_CONFLICT: &str = "conflict";
pub const ERR_CODE_RATE_LIMITED: &str = "rate_limited";
pub const ERR_CODE_PAYLOAD_TOO_LARGE: &str = "payload_too_large";
pub const ERR_CODE_METHOD_NOT_FOUND: &str = "method_not_found";
pub const ERR_CODE_INTERNAL: &str = "internal";

/// RPCError represents an error in an RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    #[serde(rename = "code")]
    pub code: String,
    #[serde(rename = "message")]
    pub message: String,
}

impl Display for RpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_error_roundtrip() {
        let err = RpcError {
            code: "conflict".to_string(),
            message: "sequence mismatch".to_string(),
        };
        let encoded = serde_cbor::to_vec(&err).expect("encode");
        let decoded: RpcError = serde_cbor::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.code, "conflict");
        assert_eq!(decoded.message, "sequence mismatch");
    }

    #[test]
    fn rpc_error_string() {
        let err = RpcError {
            code: "not_found".to_string(),
            message: "space does not exist".to_string(),
        };
        assert_eq!(err.to_string(), "not_found: space does not exist");
    }
}
