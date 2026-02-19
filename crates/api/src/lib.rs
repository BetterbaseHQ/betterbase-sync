#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::{self, Next};
use axum::routing::get;
use axum::{
    extract::State, http::StatusCode, response::IntoResponse, response::Response, Json, Router,
};
use less_sync_auth::{AuthError, TokenValidator};
use less_sync_core::protocol::ErrorResponse;
use less_sync_realtime::broker::MultiBroker;
use less_sync_storage::{Storage, StorageError};

mod ws;

const DEFAULT_WS_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

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
    sync_storage: Option<Arc<dyn ws::SyncStorage>>,
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
            sync_storage: None,
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
    pub fn with_sync_storage<T>(self, storage: Arc<T>) -> Self
    where
        T: Storage + Send + Sync + 'static,
    {
        let storage: Arc<dyn ws::SyncStorage> = storage;
        self.with_sync_storage_adapter(storage)
    }

    pub(crate) fn with_sync_storage_adapter(mut self, storage: Arc<dyn ws::SyncStorage>) -> Self {
        self.sync_storage = Some(storage);
        self
    }

    pub(crate) fn sync_storage(&self) -> Option<Arc<dyn ws::SyncStorage>> {
        self.sync_storage.clone()
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
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/ws", get(ws::websocket_upgrade))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
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
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use tower::util::ServiceExt;

    use http::header::AUTHORIZATION;
    use less_sync_auth::{AuthContext, AuthError, TokenValidator};

    use super::{router, ApiState, HealthCheck};

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
}
