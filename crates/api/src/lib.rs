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

mod federation;
mod federation_client;
mod federation_http;
mod federation_quota;
mod files;
mod ws;

const DEFAULT_WS_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

pub use federation::{
    FederationAuthError, FederationAuthenticator, FederationJwk, FederationJwks,
    FederationTokenKeys, HttpSignatureFederationAuthenticator,
};
pub use federation_client::{FederationPeerError, FederationPeerManager};
pub use federation_quota::{FederationPeerStatus, FederationQuotaLimits, FederationQuotaTracker};
pub use files::ObjectStoreFileBlobStorage;

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
    federation_token_keys: Option<FederationTokenKeys>,
    federation_jwks: FederationJwks,
    federation_trusted_domains: Vec<String>,
    federation_quota_tracker: Arc<FederationQuotaTracker>,
    sync_storage: Option<Arc<dyn ws::SyncStorage>>,
    file_sync_storage: Option<Arc<dyn files::FileSyncStorage>>,
    file_blob_storage: Option<Arc<dyn files::FileBlobStorage>>,
    realtime_broker: Option<Arc<MultiBroker>>,
    presence_registry: Option<Arc<ws::PresenceRegistry>>,
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
        self.presence_registry = Some(Arc::new(ws::PresenceRegistry::default()));
        self
    }

    pub(crate) fn realtime_broker(&self) -> Option<Arc<MultiBroker>> {
        self.realtime_broker.clone()
    }

    pub(crate) fn presence_registry(&self) -> Option<Arc<ws::PresenceRegistry>> {
        self.presence_registry.clone()
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

    app.with_state(state).layer(middleware::from_fn_with_state(
        middleware_state,
        auth_middleware,
    ))
}

async fn health(State(state): State<ApiState>) -> StatusCode {
    match state.health.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
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
    use http::header::CACHE_CONTROL;
    use serde::Deserialize;
    use tower::util::ServiceExt;

    use http::header::AUTHORIZATION;
    use less_sync_auth::{AuthContext, AuthError, TokenValidator};

    use super::{router, ApiState, FederationJwks, FederationQuotaLimits, HealthCheck};

    struct StubHealth {
        healthy: bool,
    }

    struct StubValidator;

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
    async fn federation_status_route_returns_quota_usage() {
        let state = ApiState::new(Arc::new(StubHealth { healthy: true }))
            .with_websocket(Arc::new(StubValidator))
            .with_federation_trusted_domains(vec!["peer.example.com".to_owned()])
            .with_federation_quota_limits(FederationQuotaLimits {
                max_connections: 10,
                max_spaces: 10,
                max_records_per_hour: 10,
                max_bytes_per_hour: 1024,
            });
        let tracker = state.federation_quota_tracker();
        assert!(tracker.try_add_connection("peer.example.com").await);
        assert!(tracker.try_add_spaces("peer.example.com", 2).await);
        assert!(
            tracker
                .check_and_record_push("peer.example.com", 3, 128)
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

    #[derive(Debug, Deserialize)]
    struct TrustedPeersResponse {
        domains: Vec<String>,
    }
}
