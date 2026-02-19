use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::http::{Request, StatusCode};
use ed25519_dalek::VerifyingKey;
use less_sync_auth::{
    canonicalize_domain, extract_domain_from_key_id, verify_http_signature_with_max_age,
    AuthContext, DEFAULT_SIGNATURE_MAX_AGE,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederationAuthError {
    pub status: StatusCode,
    pub message: &'static str,
}

pub trait FederationAuthenticator: Send + Sync {
    fn authenticate_request(
        &self,
        request: &Request<()>,
    ) -> Result<AuthContext, FederationAuthError>;
}

pub struct HttpSignatureFederationAuthenticator {
    trusted_domains: HashSet<String>,
    keys_by_id: HashMap<String, VerifyingKey>,
    signature_max_age: Duration,
}

impl HttpSignatureFederationAuthenticator {
    #[must_use]
    pub fn new(
        trusted_domains: impl IntoIterator<Item = String>,
        keys_by_id: HashMap<String, VerifyingKey>,
    ) -> Self {
        Self {
            trusted_domains: trusted_domains
                .into_iter()
                .map(|domain| canonicalize_domain(&domain))
                .collect(),
            keys_by_id,
            signature_max_age: DEFAULT_SIGNATURE_MAX_AGE,
        }
    }

    #[must_use]
    pub fn with_signature_max_age(mut self, signature_max_age: Duration) -> Self {
        self.signature_max_age = signature_max_age;
        self
    }
}

impl FederationAuthenticator for HttpSignatureFederationAuthenticator {
    fn authenticate_request(
        &self,
        request: &Request<()>,
    ) -> Result<AuthContext, FederationAuthError> {
        let params = verify_http_signature_with_max_age(
            request,
            self.signature_max_age,
            |key_id| match self.keys_by_id.get(key_id) {
                Some(key) => Ok(*key),
                None => Err(less_sync_auth::HttpSignatureError::KeyLookupFailed(
                    "unknown key id".to_owned(),
                )),
            },
        )
        .map_err(|_| FederationAuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "signature verification failed",
        })?;

        let peer_domain =
            extract_domain_from_key_id(&params.key_id).map_err(|_| FederationAuthError {
                status: StatusCode::BAD_REQUEST,
                message: "invalid keyid",
            })?;
        let peer_domain = canonicalize_domain(&peer_domain);
        if !self.trusted_domains.contains(&peer_domain) {
            return Err(FederationAuthError {
                status: StatusCode::FORBIDDEN,
                message: "untrusted peer",
            });
        }

        Ok(federation_auth_context(&peer_domain))
    }
}

#[must_use]
pub(crate) fn federation_personal_space_id(peer_domain: &str) -> Uuid {
    let canonical = canonicalize_domain(peer_domain);
    Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        format!("federation:{canonical}").as_bytes(),
    )
}

fn federation_auth_context(peer_domain: &str) -> AuthContext {
    let canonical = canonicalize_domain(peer_domain);
    let personal_space_id = federation_personal_space_id(&canonical);
    AuthContext {
        issuer: format!("https://{canonical}"),
        user_id: format!("federation:{canonical}"),
        client_id: format!("federation:{canonical}"),
        personal_space_id: personal_space_id.to_string(),
        did: format!("did:web:{canonical}"),
        mailbox_id: format!("federation:{canonical}"),
        scope: "sync".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HOST;
    use axum::http::Method;
    use ed25519_dalek::SigningKey;
    use less_sync_auth::sign_http_request;
    use p256::elliptic_curve::rand_core::OsRng;

    fn signed_request(signing_key: &SigningKey, key_id: &str) -> Request<()> {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("ws://sync.example.com/api/v1/federation/ws")
            .body(())
            .expect("request");
        request.insert_header(HOST, "sync.example.com");
        sign_http_request(&mut request, signing_key, key_id);
        request
    }

    trait RequestExt {
        fn insert_header(&mut self, name: axum::http::header::HeaderName, value: &str);
    }

    impl RequestExt for Request<()> {
        fn insert_header(&mut self, name: axum::http::header::HeaderName, value: &str) {
            self.headers_mut().insert(
                name,
                axum::http::HeaderValue::from_str(value).expect("header"),
            );
        }
    }

    #[test]
    fn authenticate_request_accepts_trusted_signed_peer() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let authenticator = HttpSignatureFederationAuthenticator::new(
            vec!["peer.example.com".to_owned()],
            HashMap::from([(key_id.to_owned(), signing_key.verifying_key())]),
        );

        let request = signed_request(&signing_key, key_id);
        let auth = authenticator
            .authenticate_request(&request)
            .expect("federation auth should pass");

        assert_eq!(auth.scope, "sync");
        assert_eq!(auth.user_id, "federation:peer.example.com");
        assert_eq!(
            auth.personal_space_id,
            federation_personal_space_id("peer.example.com").to_string()
        );
    }

    #[test]
    fn authenticate_request_rejects_missing_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let authenticator = HttpSignatureFederationAuthenticator::new(
            vec!["peer.example.com".to_owned()],
            HashMap::from([(key_id.to_owned(), signing_key.verifying_key())]),
        );

        let mut request = Request::builder()
            .method(Method::GET)
            .uri("ws://sync.example.com/api/v1/federation/ws")
            .body(())
            .expect("request");
        request.insert_header(HOST, "sync.example.com");

        let error = authenticator
            .authenticate_request(&request)
            .expect_err("unsigned request should fail");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn authenticate_request_rejects_untrusted_peer() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let authenticator = HttpSignatureFederationAuthenticator::new(
            vec!["trusted.example.com".to_owned()],
            HashMap::from([(key_id.to_owned(), signing_key.verifying_key())]),
        );

        let request = signed_request(&signing_key, key_id);
        let error = authenticator
            .authenticate_request(&request)
            .expect_err("untrusted peer should fail");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn authenticate_request_rejects_invalid_keyid_shape() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_id = "invalid-key-id";
        let authenticator = HttpSignatureFederationAuthenticator::new(
            vec!["peer.example.com".to_owned()],
            HashMap::from([(key_id.to_owned(), signing_key.verifying_key())]),
        );

        let request = signed_request(&signing_key, key_id);
        let error = authenticator
            .authenticate_request(&request)
            .expect_err("invalid keyid should fail");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
