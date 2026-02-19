use less_sync_auth::{AuthContext, AuthError, TokenValidator};
use less_sync_core::protocol::RPC_NOTIFICATION;
use serde::Deserialize;

use super::close_codes::CloseDirective;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstMessage {
    Binary(Vec<u8>),
    NonBinary,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeError {
    pub close: CloseDirective,
}

impl HandshakeError {
    fn auth_failed(reason: &'static str) -> Self {
        Self {
            close: CloseDirective::auth_failed(reason),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthFrame {
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "method")]
    method: String,
    #[serde(rename = "params")]
    params: AuthFrameParams,
}

#[derive(Debug, Deserialize)]
struct AuthFrameParams {
    #[serde(rename = "token")]
    token: String,
}

pub async fn authenticate_first_message(
    validator: &(dyn TokenValidator + Send + Sync),
    first_message: FirstMessage,
) -> Result<AuthContext, HandshakeError> {
    let payload = match first_message {
        FirstMessage::Binary(payload) => payload,
        FirstMessage::NonBinary => {
            return Err(HandshakeError::auth_failed("expected binary auth frame"));
        }
        FirstMessage::Closed => {
            return Err(HandshakeError::auth_failed("connection closed before auth"));
        }
    };

    let token = parse_auth_token(&payload)?;
    let context = validator
        .validate_token(&token)
        .await
        .map_err(map_auth_error)?;
    if !has_scope(&context.scope, "sync") {
        return Err(HandshakeError::auth_failed("sync scope required"));
    }

    Ok(context)
}

fn parse_auth_token(payload: &[u8]) -> Result<String, HandshakeError> {
    if payload.is_empty() {
        return Err(HandshakeError::auth_failed("empty auth frame"));
    }

    let frame: AuthFrame = serde_cbor::from_slice(payload)
        .map_err(|_| HandshakeError::auth_failed("invalid auth frame"))?;
    if frame.frame_type != RPC_NOTIFICATION || frame.method != "auth" {
        return Err(HandshakeError::auth_failed(
            "first frame must be an auth notification",
        ));
    }
    if frame.params.token.is_empty() {
        return Err(HandshakeError::auth_failed("empty auth token"));
    }
    Ok(frame.params.token)
}

fn map_auth_error(error: AuthError) -> HandshakeError {
    match error {
        AuthError::MissingToken => HandshakeError::auth_failed("missing auth token"),
        AuthError::InvalidToken => HandshakeError::auth_failed("invalid auth token"),
        AuthError::ExpiredToken => HandshakeError::auth_failed("expired auth token"),
        AuthError::UntrustedIssuer => HandshakeError::auth_failed("untrusted auth issuer"),
    }
}

fn has_scope(scope: &str, required: &str) -> bool {
    scope.split_whitespace().any(|token| token == required)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    struct StubValidator {
        context: Option<AuthContext>,
    }

    #[async_trait]
    impl TokenValidator for StubValidator {
        async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
            if token != "valid-token" {
                return Err(AuthError::InvalidToken);
            }
            self.context.clone().ok_or(AuthError::InvalidToken)
        }
    }

    #[tokio::test]
    async fn authenticates_first_auth_notification() {
        let validator = StubValidator {
            context: Some(AuthContext {
                issuer: "https://accounts.less.so".to_owned(),
                user_id: "user-1".to_owned(),
                client_id: "client-1".to_owned(),
                personal_space_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                did: "did:key:zDnaStub".to_owned(),
                mailbox_id: "mailbox-1".to_owned(),
                scope: "sync".to_owned(),
            }),
        };
        let frame = serde_cbor::to_vec(&serde_json::json!({
            "type": RPC_NOTIFICATION,
            "method": "auth",
            "params": { "token": "valid-token" }
        }))
        .expect("encode frame");

        let context = authenticate_first_message(&validator, FirstMessage::Binary(frame))
            .await
            .expect("auth should pass");
        assert_eq!(context.user_id, "user-1");
    }

    #[tokio::test]
    async fn rejects_non_binary_first_message() {
        let validator = StubValidator { context: None };
        let error = authenticate_first_message(&validator, FirstMessage::NonBinary)
            .await
            .expect_err("non-binary first message must fail");
        assert_eq!(
            error.close.code,
            less_sync_core::protocol::CLOSE_AUTH_FAILED
        );
    }

    #[tokio::test]
    async fn rejects_non_auth_first_frame() {
        let validator = StubValidator {
            context: Some(AuthContext {
                issuer: "https://accounts.less.so".to_owned(),
                user_id: "user-1".to_owned(),
                client_id: "client-1".to_owned(),
                personal_space_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                did: "did:key:zDnaStub".to_owned(),
                mailbox_id: "mailbox-1".to_owned(),
                scope: "sync".to_owned(),
            }),
        };
        let frame = serde_cbor::to_vec(&serde_json::json!({
            "type": 0,
            "method": "subscribe",
            "id": "req-1",
            "params": {}
        }))
        .expect("encode frame");

        let error = authenticate_first_message(&validator, FirstMessage::Binary(frame))
            .await
            .expect_err("non-auth first frame must fail");
        assert_eq!(
            error.close.code,
            less_sync_core::protocol::CLOSE_AUTH_FAILED
        );
    }

    #[tokio::test]
    async fn rejects_tokens_without_sync_scope() {
        let validator = StubValidator {
            context: Some(AuthContext {
                issuer: "https://accounts.less.so".to_owned(),
                user_id: "user-1".to_owned(),
                client_id: "client-1".to_owned(),
                personal_space_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                did: "did:key:zDnaStub".to_owned(),
                mailbox_id: "mailbox-1".to_owned(),
                scope: "files".to_owned(),
            }),
        };
        let frame = serde_cbor::to_vec(&serde_json::json!({
            "type": RPC_NOTIFICATION,
            "method": "auth",
            "params": { "token": "valid-token" }
        }))
        .expect("encode frame");

        let error = authenticate_first_message(&validator, FirstMessage::Binary(frame))
            .await
            .expect_err("missing sync scope must fail");
        assert_eq!(error.close.reason, "sync scope required");
    }
}
