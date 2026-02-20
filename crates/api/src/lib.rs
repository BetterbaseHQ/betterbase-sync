#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::{self, Next};
use axum::routing::{get, put};
use axum::{
    extract::State, http::StatusCode, response::IntoResponse, response::Response, Json, Router,
};
use less_sync_auth::{AuthError, TokenValidator};
use less_sync_core::protocol::ErrorResponse;
use less_sync_realtime::broker::MultiBroker;
use less_sync_storage::{Storage, StorageError};
use object_store::ObjectStore;
use serde::Serialize;

mod federation;
mod federation_client;
mod federation_http;
mod federation_quota;
mod files;
mod ws;

const DEFAULT_WS_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UCAN_HEADER_SIZE: usize = 64 * 1024;

pub use federation::{
    FederationAuthError, FederationAuthenticator, FederationJwk, FederationJwks,
    FederationTokenKeys, HttpSignatureFederationAuthenticator,
};
pub use federation_client::{FederationForwarder, FederationPeerError, FederationPeerManager};
pub use federation_quota::{FederationPeerStatus, FederationQuotaLimits, FederationQuotaTracker};
pub use files::ObjectStoreFileBlobStorage;
pub use ws::PresenceRegistry;

#[async_trait]
pub trait HealthCheck: Send + Sync {
    async fn ping(&self) -> Result<(), StorageError>;
}

#[async_trait]
impl<T> HealthCheck for T
where
    T: Storage + Send + Sync,
{
    async fn ping(&self) -> Result<(), StorageError> {
        Storage::ping(self).await
    }
}

#[derive(Clone)]
pub struct ApiState {
    health: Arc<dyn HealthCheck>,
    websocket: Option<WebSocketState>,
    federation_authenticator: Option<Arc<dyn FederationAuthenticator>>,
    federation_forwarder: Option<Arc<dyn FederationForwarder>>,
    federation_token_keys: Option<FederationTokenKeys>,
    federation_jwks: FederationJwks,
    federation_trusted_domains: Vec<String>,
    federation_quota_tracker: Arc<FederationQuotaTracker>,
    sync_storage: Option<Arc<dyn ws::SyncStorage>>,
    file_sync_storage: Option<Arc<dyn files::FileSyncStorage>>,
    file_blob_storage: Option<Arc<dyn files::FileBlobStorage>>,
    realtime_broker: Option<Arc<MultiBroker>>,
    presence_registry: Option<Arc<ws::PresenceRegistry>>,
    identity_hash_key: Option<Arc<[u8]>>,
}

#[derive(Clone)]
pub(crate) struct WebSocketState {
    pub validator: Arc<dyn TokenValidator + Send + Sync>,
    pub auth_timeout: Duration,
}

impl ApiState {
    #[must_use]
    pub fn new(health: Arc<dyn HealthCheck>) -> Self {
        Self {
            health,
            websocket: None,
            federation_authenticator: None,
            federation_forwarder: None,
            federation_token_keys: None,
            federation_jwks: FederationJwks::default(),
            federation_trusted_domains: Vec::new(),
            federation_quota_tracker: Arc::new(FederationQuotaTracker::new(
                FederationQuotaLimits::default(),
            )),
            sync_storage: None,
            file_sync_storage: None,
            file_blob_storage: None,
            realtime_broker: None,
            presence_registry: None,
            identity_hash_key: None,
        }
    }

    #[must_use]
    pub fn with_websocket(self, validator: Arc<dyn TokenValidator + Send + Sync>) -> Self {
        self.with_websocket_timeout(validator, DEFAULT_WS_AUTH_TIMEOUT)
    }

    #[must_use]
    pub fn with_websocket_timeout(
        mut self,
        validator: Arc<dyn TokenValidator + Send + Sync>,
        auth_timeout: Duration,
    ) -> Self {
        self.websocket = Some(WebSocketState {
            validator,
            auth_timeout,
        });
        self
    }

    pub(crate) fn websocket(&self) -> Option<WebSocketState> {
        self.websocket.clone()
    }

    #[must_use]
    pub fn with_federation_authenticator(
        mut self,
        authenticator: Arc<dyn FederationAuthenticator>,
    ) -> Self {
        self.federation_authenticator = Some(authenticator);
        self
    }

    pub(crate) fn federation_authenticator(&self) -> Option<Arc<dyn FederationAuthenticator>> {
        self.federation_authenticator.clone()
    }

    #[must_use]
    pub fn with_federation_forwarder(mut self, forwarder: Arc<dyn FederationForwarder>) -> Self {
        self.federation_forwarder = Some(forwarder);
        self
    }

    pub(crate) fn federation_forwarder(&self) -> Option<Arc<dyn FederationForwarder>> {
        self.federation_forwarder.clone()
    }

    #[must_use]
    pub fn with_federation_token_keys(mut self, keys: FederationTokenKeys) -> Self {
        self.federation_token_keys = Some(keys);
        self
    }

    pub(crate) fn federation_token_keys(&self) -> Option<FederationTokenKeys> {
        self.federation_token_keys.clone()
    }

    #[must_use]
    pub fn with_federation_jwks(mut self, jwks: FederationJwks) -> Self {
        self.federation_jwks = jwks;
        self
    }

    pub(crate) fn federation_jwks(&self) -> FederationJwks {
        self.federation_jwks.clone()
    }

    #[must_use]
    pub fn with_federation_trusted_domains(mut self, domains: Vec<String>) -> Self {
        let mut domains = domains
            .into_iter()
            .map(|domain| less_sync_auth::canonicalize_domain(&domain))
            .collect::<Vec<_>>();
        domains.sort_unstable();
        domains.dedup();
        self.federation_trusted_domains = domains;
        self
    }

    pub(crate) fn federation_trusted_domains(&self) -> Vec<String> {
        self.federation_trusted_domains.clone()
    }

    #[must_use]
    pub fn with_federation_quota_limits(mut self, limits: FederationQuotaLimits) -> Self {
        self.federation_quota_tracker = Arc::new(FederationQuotaTracker::new(limits));
        self
    }

    pub(crate) fn federation_quota_tracker(&self) -> Arc<FederationQuotaTracker> {
        Arc::clone(&self.federation_quota_tracker)
    }

    #[must_use]
    pub fn with_sync_storage<T>(self, storage: Arc<T>) -> Self
    where
        T: Storage + Send + Sync + 'static,
    {
        let ws_storage: Arc<dyn ws::SyncStorage> = storage.clone();
        let file_sync_storage: Arc<dyn files::FileSyncStorage> = storage;
        self.with_sync_storage_adapter(ws_storage)
            .with_file_sync_storage_adapter(file_sync_storage)
    }

    pub(crate) fn with_sync_storage_adapter(mut self, storage: Arc<dyn ws::SyncStorage>) -> Self {
        self.sync_storage = Some(storage);
        self
    }

    pub(crate) fn sync_storage(&self) -> Option<Arc<dyn ws::SyncStorage>> {
        self.sync_storage.clone()
    }

    pub(crate) fn with_file_sync_storage_adapter(
        mut self,
        storage: Arc<dyn files::FileSyncStorage>,
    ) -> Self {
        self.file_sync_storage = Some(storage);
        self
    }

    pub(crate) fn file_sync_storage(&self) -> Option<Arc<dyn files::FileSyncStorage>> {
        self.file_sync_storage.clone()
    }

    #[must_use]
    pub fn with_object_store_file_storage(self, storage: Arc<ObjectStoreFileBlobStorage>) -> Self {
        let storage: Arc<dyn files::FileBlobStorage> = storage;
        self.with_file_blob_storage_adapter(storage)
    }

    #[must_use]
    pub fn with_file_object_store(self, store: Arc<dyn ObjectStore>) -> Self {
        self.with_object_store_file_storage(Arc::new(ObjectStoreFileBlobStorage::new(store)))
    }

    pub(crate) fn with_file_blob_storage_adapter(
        mut self,
        storage: Arc<dyn files::FileBlobStorage>,
    ) -> Self {
        self.file_blob_storage = Some(storage);
        self
    }

    pub(crate) fn file_blob_storage(&self) -> Option<Arc<dyn files::FileBlobStorage>> {
        self.file_blob_storage.clone()
    }

    #[must_use]
    pub fn with_realtime_broker(mut self, broker: Arc<MultiBroker>) -> Self {
        self.realtime_broker = Some(broker);
        self.presence_registry = Some(Arc::new(ws::PresenceRegistry::new()));
        self
    }

    pub fn realtime_broker(&self) -> Option<Arc<MultiBroker>> {
        self.realtime_broker.clone()
    }

    pub fn presence_registry(&self) -> Option<Arc<ws::PresenceRegistry>> {
        self.presence_registry.clone()
    }

    #[must_use]
    pub fn with_identity_hash_key(mut self, key: Vec<u8>) -> Self {
        self.identity_hash_key = Some(Arc::from(key));
        self
    }

    pub(crate) fn identity_hash_key(&self) -> Option<Arc<[u8]>> {
        self.identity_hash_key.clone()
    }
}

pub fn router(state: ApiState) -> Router {
    let middleware_state = state.clone();
    let files_enabled = state.file_sync_storage().is_some() && state.file_blob_storage().is_some();
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(federation_http::jwks))
        .route("/api/v1/ws", get(ws::websocket_upgrade))
        .route(
            "/api/v1/federation/ws",
            get(ws::federation_websocket_upgrade),
        )
        .route(
            "/api/v1/federation/trusted",
            get(federation_http::trusted_peers),
        )
        .route(
            "/api/v1/federation/status/{domain}",
            get(federation_http::peer_status),
        );

    if files_enabled {
        app = app.route(
            "/api/v1/spaces/{space_id}/files/{id}",
            put(files::put_file)
                .get(files::get_file)
                .head(files::head_file),
        );
    }

    app.with_state(state)
        .layer(middleware::from_fn_with_state(
            middleware_state,
            auth_middleware,
        ))
        .layer(middleware::from_fn(cors_and_protocol_middleware))
}

#[derive(Debug, Serialize)]
struct HealthFederation {
    enabled: bool,
    peer_count: usize,
    connections: usize,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation: Option<HealthFederation>,
}

async fn health(State(state): State<ApiState>) -> impl IntoResponse {
    match state.health.ping().await {
        Ok(()) => {
            let federation = if state.federation_authenticator().is_some() {
                let peers = state.federation_quota_tracker().all_peer_status().await;
                let connections = peers
                    .iter()
                    .map(|peer| peer.connections)
                    .fold(0_usize, usize::saturating_add);
                Some(HealthFederation {
                    enabled: true,
                    peer_count: state.federation_trusted_domains().len(),
                    connections,
                })
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(HealthResponse {
                    status: "healthy",
                    error: None,
                    federation,
                }),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy",
                error: Some("database unavailable"),
                federation: None,
            }),
        )
            .into_response(),
    }
}

async fn auth_middleware(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    if is_public_path(request.uri().path()) {
        return next.run(request).await;
    }

    let Some(validator) = state.auth_validator() else {
        return auth_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth validator is not configured",
        );
    };

    let Some(header) = request.headers().get(AUTHORIZATION) else {
        return auth_error_response(StatusCode::UNAUTHORIZED, "missing authorization");
    };
    let Ok(header_value) = header.to_str() else {
        return auth_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid authorization header format",
        );
    };
    let Some(token) = header_value.strip_prefix("Bearer ") else {
        return auth_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid authorization header format",
        );
    };

    match validator.validate_token(token).await {
        Ok(context) => {
            if request
                .headers()
                .get("X-UCAN")
                .is_some_and(|value| value.as_bytes().len() > MAX_UCAN_HEADER_SIZE)
            {
                return auth_error_response(StatusCode::UNAUTHORIZED, "X-UCAN header too large");
            }
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(AuthError::MissingToken) => {
            auth_error_response(StatusCode::UNAUTHORIZED, "missing authorization token")
        }
        Err(AuthError::ExpiredToken) => {
            auth_error_response(StatusCode::UNAUTHORIZED, "token has expired")
        }
        Err(AuthError::UntrustedIssuer) => {
            auth_error_response(StatusCode::UNAUTHORIZED, "untrusted token issuer")
        }
        Err(AuthError::InvalidToken) => {
            auth_error_response(StatusCode::UNAUTHORIZED, "invalid token")
        }
    }
}

fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/api/v1/ws" | "/.well-known/jwks.json" | "/api/v1/federation/ws"
    )
}

fn auth_error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_owned(),
        }),
    )
        .into_response()
}

async fn cors_and_protocol_middleware(request: Request, next: Next) -> Response {
    if request.method() == axum::http::Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_common_headers(response.headers_mut());
        return response;
    }

    let mut response = next.run(request).await;
    apply_common_headers(response.headers_mut());
    response
}

fn apply_common_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        "X-Protocol-Version",
        axum::http::HeaderValue::from_static("1"),
    );
    headers.insert(
        "Access-Control-Allow-Origin",
        axum::http::HeaderValue::from_static("*"),
    );
    headers.insert(
        "Access-Control-Allow-Methods",
        axum::http::HeaderValue::from_static("GET, PUT, HEAD, POST, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        axum::http::HeaderValue::from_static(
            "Content-Type, Content-Length, Authorization, X-UCAN, X-Wrapped-DEK, X-Record-ID",
        ),
    );
    headers.insert(
        "Access-Control-Expose-Headers",
        axum::http::HeaderValue::from_static("X-Wrapped-DEK"),
    );
    headers.insert(
        "Access-Control-Max-Age",
        axum::http::HeaderValue::from_static("86400"),
    );
}

impl ApiState {
    fn auth_validator(&self) -> Option<Arc<dyn TokenValidator + Send + Sync>> {
        self.websocket
            .as_ref()
            .map(|state| Arc::clone(&state.validator))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::http::StatusCode;
    use http::header::HeaderName;
    use http::header::HeaderValue;
    use http::header::ACCESS_CONTROL_ALLOW_METHODS;
    use http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
    use http::header::CACHE_CONTROL;
    use serde::Deserialize;
    use tower::util::ServiceExt;

    use http::header::AUTHORIZATION;
    use less_sync_auth::{AuthContext, AuthError, TokenValidator};

    use super::{
        router, ApiState, FederationAuthError, FederationAuthenticator, FederationJwks,
        FederationQuotaLimits, HealthCheck, MAX_UCAN_HEADER_SIZE,
    };

    struct StubHealth {
        healthy: bool,
    }

    struct StubValidator;
    struct StubFederationAuthenticator;

    #[async_trait]
    impl TokenValidator for StubValidator {
        async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
            if token == "valid-token" {
                Ok(AuthContext {
                    issuer: "https://accounts.less.so".to_owned(),
                    user_id: "user-1".to_owned(),
                    client_id: "client-1".to_owned(),
                    personal_space_id: "8e4f907f-cdb8-45a4-bb92-6d9c4f6e8b17".to_owned(),
                    did: "did:key:z6Mkexample".to_owned(),
                    mailbox_id: "mailbox-1".to_owned(),
                    scope: "sync".to_owned(),
                })
            } else {
                Err(AuthError::InvalidToken)
            }
        }
    }

    #[async_trait]
    impl HealthCheck for StubHealth {
        async fn ping(&self) -> Result<(), less_sync_storage::StorageError> {
            if self.healthy {
                Ok(())
            } else {
                Err(less_sync_storage::StorageError::Unavailable)
            }
        }
    }

    impl FederationAuthenticator for StubFederationAuthenticator {
        fn authenticate_request(
            &self,
            _request: &axum::http::Request<()>,
        ) -> Result<AuthContext, FederationAuthError> {
            Err(FederationAuthError {
                status: StatusCode::UNAUTHORIZED,
                message: "signature verification failed",
            })
        }
    }

    #[tokio::test]
    async fn health_returns_ok_when_backend_is_healthy() {
        let app = router(ApiState::new(Arc::new(StubHealth { healthy: true })));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: HealthRouteResponse = serde_json::from_slice(&body).expect("decode body");
        assert_eq!(payload.status, "healthy");
        assert!(payload.error.is_none());
    }

    #[tokio::test]
    async fn health_returns_unavailable_when_backend_ping_fails() {
        let app = router(ApiState::new(Arc::new(StubHealth { healthy: false })));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: HealthRouteResponse = serde_json::from_slice(&body).expect("decode body");
        assert_eq!(payload.status, "unhealthy");
        assert_eq!(payload.error.as_deref(), Some("database unavailable"));
    }

    #[tokio::test]
    async fn health_includes_federation_summary_when_enabled() {
        let state = ApiState::new(Arc::new(StubHealth { healthy: true }))
            .with_websocket(Arc::new(StubValidator))
            .with_federation_authenticator(Arc::new(StubFederationAuthenticator))
            .with_federation_trusted_domains(vec![
                "peer.example.com".to_owned(),
                "other.example.com".to_owned(),
            ]);
        let tracker = state.federation_quota_tracker();
        assert!(tracker.try_add_connection("peer.example.com").await);
        assert!(tracker.try_add_connection("peer.example.com").await);
        assert!(tracker.try_add_connection("other.example.com").await);

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: HealthRouteResponse = serde_json::from_slice(&body).expect("decode body");
        let federation = payload.federation.expect("federation summary");
        assert_eq!(federation.peer_count, 2);
        assert_eq!(federation.connections, 3);
    }

    #[tokio::test]
    async fn api_routes_require_authorization_header() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invitations")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_routes_reject_invalid_authorization_token() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invitations")
                    .header(AUTHORIZATION, "Bearer invalid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_routes_accept_valid_authorization_token() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invitations")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn federation_jwks_route_is_public() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_federation_jwks(FederationJwks::default()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=3600, stale-while-revalidate=86400")
        );
    }

    #[tokio::test]
    async fn federation_trusted_route_requires_authorization() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/trusted")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn federation_trusted_route_returns_configured_domains() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator))
                .with_federation_authenticator(Arc::new(StubFederationAuthenticator))
                .with_federation_trusted_domains(vec![
                    "Peer.Example.com".to_owned(),
                    "other.example.com".to_owned(),
                ]),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/trusted")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: TrustedPeersResponse = serde_json::from_slice(&body).expect("decode body");
        assert_eq!(
            payload.domains,
            vec![
                "other.example.com".to_owned(),
                "peer.example.com".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn federation_trusted_route_returns_not_found_when_federation_disabled() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/trusted")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn federation_status_route_returns_quota_usage() {
        let state = ApiState::new(Arc::new(StubHealth { healthy: true }))
            .with_websocket(Arc::new(StubValidator))
            .with_federation_authenticator(Arc::new(StubFederationAuthenticator))
            .with_federation_trusted_domains(vec!["peer.example.com".to_owned()])
            .with_federation_quota_limits(FederationQuotaLimits {
                max_connections: 10,
                max_spaces: 10,
                max_records_per_hour: 10,
                max_bytes_per_hour: 1024,
                max_invitations_per_hour: 10,
            });
        let tracker = state.federation_quota_tracker();
        assert!(tracker.try_add_connection("peer.example.com").await);
        assert!(tracker.try_add_spaces("peer.example.com", 2).await);
        assert!(
            tracker
                .check_and_record_push("peer.example.com", 3, 128)
                .await
        );
        assert!(
            tracker
                .check_and_record_invitation("peer.example.com")
                .await
        );

        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/status/Peer.Example.com")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: super::FederationPeerStatus =
            serde_json::from_slice(&body).expect("decode body");
        assert_eq!(payload.domain, "peer.example.com");
        assert_eq!(payload.connections, 1);
        assert_eq!(payload.spaces, 2);
        assert_eq!(payload.records_this_hour, 3);
        assert_eq!(payload.bytes_this_hour, 128);
        assert_eq!(payload.invitations_this_hour, 1);
    }

    #[tokio::test]
    async fn federation_status_route_rejects_untrusted_peer() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator))
                .with_federation_trusted_domains(vec!["peer.example.com".to_owned()]),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/status/other.example.com")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn federation_status_route_returns_not_found_when_federation_disabled() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/status/peer.example.com")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn preflight_options_returns_no_content_and_cors_headers() {
        let app = router(ApiState::new(Arc::new(StubHealth { healthy: true })));
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/ws")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_METHODS)
                .and_then(|value| value.to_str().ok()),
            Some("GET, PUT, HEAD, POST, OPTIONS")
        );
    }

    #[tokio::test]
    async fn all_responses_include_protocol_version_header() {
        let app = router(ApiState::new(Arc::new(StubHealth { healthy: true })));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(
            response
                .headers()
                .get("X-Protocol-Version")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn auth_middleware_rejects_oversized_ucan_header() {
        let app = router(
            ApiState::new(Arc::new(StubHealth { healthy: true }))
                .with_websocket(Arc::new(StubValidator)),
        );
        let oversized_ucan = "a".repeat(MAX_UCAN_HEADER_SIZE + 1);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/federation/trusted")
                    .header(AUTHORIZATION, "Bearer valid-token")
                    .header(
                        HeaderName::from_static("x-ucan"),
                        HeaderValue::from_str(&oversized_ucan).expect("build x-ucan"),
                    )
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let payload: ErrorBody = serde_json::from_slice(&body).expect("decode body");
        assert_eq!(payload.error, "X-UCAN header too large");
    }

    #[derive(Debug, Deserialize)]
    struct TrustedPeersResponse {
        domains: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct HealthRouteResponse {
        status: String,
        error: Option<String>,
        federation: Option<HealthFederationResponse>,
    }

    #[derive(Debug, Deserialize)]
    struct HealthFederationResponse {
        peer_count: usize,
        connections: usize,
    }

    #[derive(Debug, Deserialize)]
    struct ErrorBody {
        error: String,
    }
}
