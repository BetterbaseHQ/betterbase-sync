#![forbid(unsafe_code)]

use async_trait::async_trait;

pub mod did_key;
pub mod permission;
pub mod session;

pub use did_key::{compress_public_key, decode_did_key, encode_did_key, DidKeyError};
pub use permission::{parse_permission, ParsePermissionError, Permission};
pub use session::{
    SessionClaims, SessionError, SessionManager, SESSION_TOKEN_LENGTH, SESSION_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
}

#[async_trait]
pub trait TokenValidator: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError>;
}
