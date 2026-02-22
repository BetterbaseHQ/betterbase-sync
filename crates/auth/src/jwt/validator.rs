#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::{Deserialize, Serialize};

use super::jwks::JwksClient;
use crate::{AuthContext, AuthError, TokenValidator};

const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Default)]
pub struct MultiValidatorConfig {
    pub trusted_issuers: HashMap<String, String>,
    pub audiences: Vec<String>,
    pub refresh_ttl: Duration,
}

pub struct MultiValidator {
    issuers: HashMap<String, Arc<JwksClient>>,
    audiences: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub personal_space_id: String,
    #[serde(default)]
    pub did: String,
    #[serde(default)]
    pub mailbox_id: String,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub aud: Option<AudienceClaim>,
    #[serde(default)]
    pub exp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub issuer: String,
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
    pub personal_space_id: String,
    pub did: String,
    pub mailbox_id: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum JwtValidationError {
    #[error("missing authorization token")]
    MissingToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("token has expired")]
    ExpiredToken,
    #[error("untrusted token issuer")]
    UntrustedIssuer,
}

impl MultiValidator {
    #[must_use]
    pub fn new(config: MultiValidatorConfig) -> Self {
        let refresh_ttl = if config.refresh_ttl.is_zero() {
            DEFAULT_REFRESH_TTL
        } else {
            config.refresh_ttl
        };

        let issuers = config
            .trusted_issuers
            .into_iter()
            .map(|(issuer, jwks_url)| {
                (
                    normalize_issuer(&issuer),
                    Arc::new(JwksClient::new(jwks_url, refresh_ttl)),
                )
            })
            .collect();

        Self {
            issuers,
            audiences: config.audiences,
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<TokenInfo, JwtValidationError> {
        if token.is_empty() {
            return Err(JwtValidationError::MissingToken);
        }

        let header = decode_header(token).map_err(|_| JwtValidationError::InvalidToken)?;
        if header.alg != Algorithm::ES256 {
            return Err(JwtValidationError::InvalidToken);
        }
        let kid = header.kid.ok_or(JwtValidationError::InvalidToken)?;

        let unverified_issuer = extract_unverified_issuer(token)?;
        let selected_issuer = normalize_issuer(&unverified_issuer);
        let jwks_client = self
            .issuers
            .get(&selected_issuer)
            .ok_or(JwtValidationError::UntrustedIssuer)?;
        let decoding_key = jwks_client
            .get_key(&kid)
            .await
            .map_err(|_| JwtValidationError::InvalidToken)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        let token_data =
            decode::<Claims>(token, &decoding_key, &validation).map_err(map_decode_error)?;
        let claims = token_data.claims;

        if let Some(exp) = claims.exp {
            let now = unix_now().map_err(|_| JwtValidationError::InvalidToken)?;
            if now > exp {
                return Err(JwtValidationError::ExpiredToken);
            }
        }

        if normalize_issuer(&claims.iss) != selected_issuer {
            return Err(JwtValidationError::UntrustedIssuer);
        }

        if !self.audiences.is_empty() && !audience_matches(claims.aud.as_ref(), &self.audiences) {
            return Err(JwtValidationError::InvalidToken);
        }

        if claims.sub.is_empty() || claims.client_id.is_empty() {
            return Err(JwtValidationError::InvalidToken);
        }

        Ok(TokenInfo {
            issuer: claims.iss,
            user_id: claims.sub,
            client_id: claims.client_id,
            scope: claims.scope,
            jti: claims.jti,
            personal_space_id: claims.personal_space_id,
            did: claims.did,
            mailbox_id: claims.mailbox_id,
        })
    }
}

#[async_trait]
impl TokenValidator for MultiValidator {
    async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
        let token_info = MultiValidator::validate_token(self, token)
            .await
            .map_err(AuthError::from)?;
        Ok(AuthContext {
            issuer: token_info.issuer,
            user_id: token_info.user_id,
            client_id: token_info.client_id,
            personal_space_id: token_info.personal_space_id,
            did: token_info.did,
            mailbox_id: token_info.mailbox_id,
            scope: token_info.scope,
        })
    }
}

impl From<JwtValidationError> for AuthError {
    fn from(value: JwtValidationError) -> Self {
        match value {
            JwtValidationError::MissingToken => AuthError::MissingToken,
            JwtValidationError::InvalidToken => AuthError::InvalidToken,
            JwtValidationError::ExpiredToken => AuthError::ExpiredToken,
            JwtValidationError::UntrustedIssuer => AuthError::UntrustedIssuer,
        }
    }
}

pub fn normalize_issuer(issuer: &str) -> String {
    issuer.trim_end_matches('/').to_owned()
}

fn map_decode_error(error: jsonwebtoken::errors::Error) -> JwtValidationError {
    if matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::ExpiredSignature
    ) {
        JwtValidationError::ExpiredToken
    } else {
        JwtValidationError::InvalidToken
    }
}

fn extract_unverified_issuer(token: &str) -> Result<String, JwtValidationError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or(JwtValidationError::InvalidToken)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| JwtValidationError::InvalidToken)?;
    let claims: UnverifiedClaims =
        serde_json::from_slice(&payload).map_err(|_| JwtValidationError::InvalidToken)?;
    let issuer = claims.iss.ok_or(JwtValidationError::UntrustedIssuer)?;
    Ok(issuer)
}

fn audience_matches(audience: Option<&AudienceClaim>, expected: &[String]) -> bool {
    match audience {
        Some(AudienceClaim::One(value)) => expected.iter().any(|candidate| candidate == value),
        Some(AudienceClaim::Many(values)) => values
            .iter()
            .any(|value| expected.iter().any(|candidate| candidate == value)),
        None => false,
    }
}

fn unix_now() -> Result<u64, std::time::SystemTimeError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[derive(Debug, Deserialize)]
struct UnverifiedClaims {
    iss: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::{routing::get, Json, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{Algorithm, Header};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::rand_core::OsRng;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::{Claims, JwtValidationError, MultiValidator, MultiValidatorConfig};
    use crate::jwt::{parse_jwk, JwksClient, JWK, JWKS};

    struct TestKeyPair {
        private: SigningKey,
        kid: String,
    }

    impl TestKeyPair {
        fn new(kid: &str) -> Self {
            Self {
                private: SigningKey::random(&mut OsRng),
                kid: kid.to_owned(),
            }
        }

        fn jwk(&self) -> JWK {
            let public = self.private.verifying_key().to_encoded_point(false);
            let public_bytes = public.as_bytes();
            let x = &public_bytes[1..33];
            let y = &public_bytes[33..65];
            JWK {
                kty: "EC".to_owned(),
                crv: "P-256".to_owned(),
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
                kid: self.kid.clone(),
                alg: "ES256".to_owned(),
                use_: "sig".to_owned(),
            }
        }

        fn sign_token(&self, claims: &Claims) -> Result<String, JwtValidationError> {
            sign_es256_token(claims, &self.kid, &self.private)
        }
    }

    struct TestServer {
        url: String,
        stop: Option<oneshot::Sender<()>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    async fn mock_jwks_server(keys: Vec<JWK>) -> TestServer {
        let keys = Arc::new(keys);
        let app = Router::new().route(
            "/",
            get({
                let keys = Arc::clone(&keys);
                move || {
                    let keys = Arc::clone(&keys);
                    async move {
                        Json(JWKS {
                            keys: (*keys).clone(),
                        })
                    }
                }
            }),
        );

        spawn_server(app).await
    }

    async fn mock_jwks_server_first_success_then_error(keys: Vec<JWK>) -> TestServer {
        #[derive(Clone)]
        struct AppState {
            calls: Arc<AtomicUsize>,
            keys: Arc<Vec<JWK>>,
        }

        async fn handler(State(state): State<AppState>) -> impl IntoResponse {
            let call = state.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                (
                    StatusCode::OK,
                    Json(JWKS {
                        keys: (*state.keys).clone(),
                    }),
                )
                    .into_response()
            } else {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }

        let state = AppState {
            calls: Arc::new(AtomicUsize::new(0)),
            keys: Arc::new(keys),
        };
        let app = Router::new().route("/", get(handler)).with_state(state);
        spawn_server(app).await
    }

    async fn mock_server_error() -> TestServer {
        let app = Router::new().route("/", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
        spawn_server(app).await
    }

    async fn spawn_server(app: Router) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });

        TestServer {
            url: format!("http://{addr}"),
            stop: Some(tx),
        }
    }

    fn new_single_issuer_validator(
        issuer: &str,
        jwks_url: &str,
        opts: impl FnOnce(&mut MultiValidatorConfig),
    ) -> MultiValidator {
        let mut config = MultiValidatorConfig {
            trusted_issuers: HashMap::from([(issuer.to_owned(), jwks_url.to_owned())]),
            audiences: Vec::new(),
            refresh_ttl: Duration::ZERO,
        };
        opts(&mut config);
        MultiValidator::new(config)
    }

    fn test_claims(issuer: &str, subject: &str, client_id: &str) -> Claims {
        Claims {
            scope: String::new(),
            client_id: client_id.to_owned(),
            personal_space_id: String::new(),
            did: String::new(),
            mailbox_id: String::new(),
            iss: issuer.to_owned(),
            sub: subject.to_owned(),
            jti: String::new(),
            aud: None,
            exp: Some(unix_now() + 60 * 60),
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_secs()
    }

    fn sign_es256_token(
        claims: &Claims,
        kid: &str,
        key: &SigningKey,
    ) -> Result<String, JwtValidationError> {
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some(kid.to_owned()),
            typ: Some("JWT".to_owned()),
            ..Header::default()
        };
        let header = serde_json::to_vec(&header).map_err(|_| JwtValidationError::InvalidToken)?;
        let claims = serde_json::to_vec(claims).map_err(|_| JwtValidationError::InvalidToken)?;
        let header = URL_SAFE_NO_PAD.encode(header);
        let claims = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = key.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{signature}"))
    }

    #[tokio::test]
    async fn validate_token_valid() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let token = key
            .sign_token(&test_claims(
                "https://accounts.example.com",
                "user-123",
                "test-client-id",
            ))
            .expect("sign token");
        let token_info = validator
            .validate_token(&token)
            .await
            .expect("validate token");
        assert_eq!(token_info.user_id, "user-123");
    }

    #[tokio::test]
    async fn validate_token_expired() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let mut claims = test_claims("https://accounts.example.com", "user-123", "test-client-id");
        claims.exp = Some(unix_now().saturating_sub(60 * 60));
        let token = key.sign_token(&claims).expect("sign token");
        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected expiration");
        assert_eq!(error, JwtValidationError::ExpiredToken);
    }

    #[tokio::test]
    async fn validate_token_untrusted_issuer() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let token = key
            .sign_token(&test_claims(
                "https://evil.example.com",
                "user-123",
                "test-client-id",
            ))
            .expect("sign token");
        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected untrusted issuer");
        assert_eq!(error, JwtValidationError::UntrustedIssuer);
    }

    #[tokio::test]
    async fn validate_token_missing_token() {
        let validator = new_single_issuer_validator(
            "https://accounts.example.com",
            "http://localhost:9999",
            |_| {},
        );

        let error = validator
            .validate_token("")
            .await
            .expect_err("expected missing token");
        assert_eq!(error, JwtValidationError::MissingToken);
    }

    #[tokio::test]
    async fn validate_token_invalid_audience() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |config| {
                config.audiences = vec!["betterbase-sync".to_owned()]
            });

        let mut claims = test_claims("https://accounts.example.com", "user-123", "test-client-id");
        claims.aud = Some(super::AudienceClaim::Many(vec!["other-service".to_owned()]));
        let token = key.sign_token(&claims).expect("sign token");

        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected invalid audience");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn validate_token_valid_audience() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |config| {
                config.audiences = vec!["betterbase-sync".to_owned(), "other-allowed".to_owned()]
            });

        let mut claims = test_claims("https://accounts.example.com", "user-123", "test-client-id");
        claims.aud = Some(super::AudienceClaim::One("betterbase-sync".to_owned()));
        let token = key.sign_token(&claims).expect("sign token");

        let token_info = validator
            .validate_token(&token)
            .await
            .expect("validate token");
        assert_eq!(token_info.user_id, "user-123");
    }

    #[tokio::test]
    async fn validate_token_key_rotation() {
        let key1 = TestKeyPair::new("key-1");
        let key2 = TestKeyPair::new("key-2");
        let server = mock_jwks_server(vec![key1.jwk(), key2.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |config| {
                config.refresh_ttl = Duration::from_secs(60)
            });

        let token1 = key1
            .sign_token(&test_claims(
                "https://accounts.example.com",
                "user-1",
                "test-client-id",
            ))
            .expect("token1");
        let token2 = key2
            .sign_token(&test_claims(
                "https://accounts.example.com",
                "user-2",
                "test-client-id",
            ))
            .expect("token2");

        assert_eq!(
            validator
                .validate_token(&token1)
                .await
                .expect("validate token1")
                .user_id,
            "user-1"
        );
        assert_eq!(
            validator
                .validate_token(&token2)
                .await
                .expect("validate token2")
                .user_id,
            "user-2"
        );
    }

    #[tokio::test]
    async fn validate_token_missing_subject() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let mut claims = test_claims("https://accounts.example.com", "", "test-client-id");
        claims.sub = String::new();
        let token = key.sign_token(&claims).expect("sign token");
        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected missing subject rejection");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn validate_token_unknown_key() {
        let key1 = TestKeyPair::new("key-1");
        let key2 = TestKeyPair::new("key-unknown");

        let server = mock_jwks_server(vec![key1.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let token = key2
            .sign_token(&test_claims(
                "https://accounts.example.com",
                "user-123",
                "test-client-id",
            ))
            .expect("sign token");
        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected unknown key rejection");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn validate_token_wrong_algorithm() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(key.kid.clone());
        let token = jsonwebtoken::encode(
            &header,
            &test_claims("https://accounts.example.com", "user-123", "test-client-id"),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .expect("encode hs256 token");

        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected algorithm rejection");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn validate_token_missing_kid() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let header = Header::new(Algorithm::ES256);
        let claims = test_claims("https://accounts.example.com", "user-123", "test-client-id");
        let token = {
            let header = serde_json::to_vec(&header).expect("header");
            let claims = serde_json::to_vec(&claims).expect("claims");
            let header = URL_SAFE_NO_PAD.encode(header);
            let claims = URL_SAFE_NO_PAD.encode(claims);
            let signing_input = format!("{header}.{claims}");
            let sig: Signature = key.private.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        };

        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected missing kid rejection");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn jwks_server_error() {
        let server = mock_server_error().await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |_| {});

        let error = validator
            .validate_token("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJzdWIiOiJ1c2VyIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5leGFtcGxlLmNvbSJ9.sig")
            .await
            .expect_err("expected jwks error");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }

    #[tokio::test]
    async fn jwks_cache_fallback_on_error() {
        let key = TestKeyPair::new("test-key-1");
        let server = mock_jwks_server_first_success_then_error(vec![key.jwk()]).await;
        let validator =
            new_single_issuer_validator("https://accounts.example.com", &server.url, |config| {
                config.refresh_ttl = Duration::from_millis(10)
            });

        let token = key
            .sign_token(&test_claims(
                "https://accounts.example.com",
                "user-123",
                "test-client-id",
            ))
            .expect("sign token");

        let info = validator
            .validate_token(&token)
            .await
            .expect("first validate");
        assert_eq!(info.user_id, "user-123");

        sleep(Duration::from_millis(20)).await;

        let info = validator
            .validate_token(&token)
            .await
            .expect("cached key should still validate");
        assert_eq!(info.user_id, "user-123");
    }

    #[test]
    fn parse_jwk_invalid_key_type() {
        let jwk = JWK {
            kty: "RSA".to_owned(),
            crv: "P-256".to_owned(),
            x: "test".to_owned(),
            y: "test".to_owned(),
            kid: "test".to_owned(),
            alg: "ES256".to_owned(),
            use_: "sig".to_owned(),
        };

        assert!(parse_jwk(&jwk).is_err());
    }

    #[test]
    fn parse_jwk_invalid_curve() {
        let jwk = JWK {
            kty: "EC".to_owned(),
            crv: "P-384".to_owned(),
            x: "test".to_owned(),
            y: "test".to_owned(),
            kid: "test".to_owned(),
            alg: "ES256".to_owned(),
            use_: "sig".to_owned(),
        };

        assert!(parse_jwk(&jwk).is_err());
    }

    #[test]
    fn parse_jwk_invalid_base64() {
        let mut jwk = JWK {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "!!!invalid-base64!!!".to_owned(),
            y: "test".to_owned(),
            kid: "test".to_owned(),
            alg: "ES256".to_owned(),
            use_: "sig".to_owned(),
        };

        assert!(parse_jwk(&jwk).is_err());

        jwk.x = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        jwk.y = "!!!invalid-base64!!!".to_owned();
        assert!(parse_jwk(&jwk).is_err());
    }

    #[test]
    fn parse_jwk_point_not_on_curve() {
        let jwk = JWK {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            y: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            kid: "test".to_owned(),
            alg: "ES256".to_owned(),
            use_: "sig".to_owned(),
        };

        let error = parse_jwk(&jwk).expect_err("expected point-not-on-curve error");
        let message = error.to_string();
        assert!(message.contains("not on curve"), "{message}");
    }

    #[test]
    fn jwks_client_set_http_client() {
        let mut client = JwksClient::new("http://example.com", Duration::from_secs(60));
        let custom = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        client.set_http_client(custom);
    }

    #[tokio::test]
    async fn validate_token_multiple_issuers() {
        let key_a = TestKeyPair::new("key-issuer-a");
        let key_b = TestKeyPair::new("key-issuer-b");

        let server_a = mock_jwks_server(vec![key_a.jwk()]).await;
        let server_b = mock_jwks_server(vec![key_b.jwk()]).await;
        let validator = MultiValidator::new(MultiValidatorConfig {
            trusted_issuers: HashMap::from([
                (
                    "https://issuer-a.example.com".to_owned(),
                    server_a.url.clone(),
                ),
                (
                    "https://issuer-b.example.com".to_owned(),
                    server_b.url.clone(),
                ),
            ]),
            audiences: Vec::new(),
            refresh_ttl: Duration::ZERO,
        });

        let token_a = key_a
            .sign_token(&test_claims(
                "https://issuer-a.example.com",
                "user-from-a",
                "client-a",
            ))
            .expect("token a");
        let token_b = key_b
            .sign_token(&test_claims(
                "https://issuer-b.example.com",
                "user-from-b",
                "client-b",
            ))
            .expect("token b");

        let info_a = validator
            .validate_token(&token_a)
            .await
            .expect("validate a");
        assert_eq!(info_a.user_id, "user-from-a");
        assert_eq!(info_a.issuer, "https://issuer-a.example.com");

        let info_b = validator
            .validate_token(&token_b)
            .await
            .expect("validate b");
        assert_eq!(info_b.user_id, "user-from-b");
        assert_eq!(info_b.issuer, "https://issuer-b.example.com");
    }

    #[tokio::test]
    async fn validate_token_cross_issuer_key_confusion() {
        let key_a = TestKeyPair::new("key-a");
        let key_b = TestKeyPair::new("key-b");

        let server_a = mock_jwks_server(vec![key_a.jwk()]).await;
        let server_b = mock_jwks_server(vec![key_b.jwk()]).await;
        let validator = MultiValidator::new(MultiValidatorConfig {
            trusted_issuers: HashMap::from([
                (
                    "https://issuer-a.example.com".to_owned(),
                    server_a.url.clone(),
                ),
                (
                    "https://issuer-b.example.com".to_owned(),
                    server_b.url.clone(),
                ),
            ]),
            audiences: Vec::new(),
            refresh_ttl: Duration::ZERO,
        });

        let token = key_b
            .sign_token(&test_claims(
                "https://issuer-a.example.com",
                "user-x",
                "client-x",
            ))
            .expect("token");

        let error = validator
            .validate_token(&token)
            .await
            .expect_err("expected cross-issuer rejection");
        assert_eq!(error, JwtValidationError::InvalidToken);
    }
}
