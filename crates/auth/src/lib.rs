#![forbid(unsafe_code)]

use async_trait::async_trait;

pub mod did_key;
pub mod federation_token;
pub mod http_signature;
pub mod jwt;
pub mod permission;
pub mod session;
pub mod ucan;

pub use did_key::{compress_public_key, decode_did_key, encode_did_key, DidKeyError};
pub use federation_token::{
    canonicalize_domain, create_fst, derive_fst_key, verify_fst, verify_fst_dual_key,
    FederationSubscribeClaims, FederationTokenError, FST_MAX_EXPIRY, FST_TOKEN_LEN, FST_VERSION,
};
pub use http_signature::{
    extract_domain_from_key_id, extract_kid_from_key_id, sign_http_request, verify_http_signature,
    verify_http_signature_with_max_age, HttpSignatureError, HttpSignatureParams,
    DEFAULT_SIGNATURE_MAX_AGE,
};
pub use jwt::{
    normalize_issuer, parse_jwk, Claims, JwksClient, JwksError, JwtValidationError, MultiValidator,
    MultiValidatorConfig, TokenInfo, JWK, JWKS, MAX_JWKS_SIZE,
};
pub use permission::{parse_permission, ParsePermissionError, Permission};
pub use session::{
    SessionClaims, SessionError, SessionManager, SESSION_TOKEN_LENGTH, SESSION_VERSION,
};
pub use ucan::{
    compute_ucan_cid, parse_ucan, validate_chain, AudienceClaim, ParsedUcan, RevocationCheck,
    UcanClaims, UcanError, ValidateChainParams, MAX_CHAIN_DEPTH, MAX_TOKENS_PER_CHAIN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization token")]
    MissingToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("token has expired")]
    ExpiredToken,
    #[error("untrusted token issuer")]
    UntrustedIssuer,
}

#[async_trait]
pub trait TokenValidator: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError>;
}
