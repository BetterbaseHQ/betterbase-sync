use less_sync_core::protocol::{CLOSE_AUTH_FAILED, CLOSE_PROTOCOL_ERROR};

pub const WS_SUBPROTOCOL: &str = "less-rpc-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseDirective {
    pub code: i32,
    pub reason: &'static str,
}

impl CloseDirective {
    #[must_use]
    pub const fn auth_failed(reason: &'static str) -> Self {
        Self {
            code: CLOSE_AUTH_FAILED,
            reason,
        }
    }

    #[must_use]
    pub const fn protocol_error(reason: &'static str) -> Self {
        Self {
            code: CLOSE_PROTOCOL_ERROR,
            reason,
        }
    }
}
