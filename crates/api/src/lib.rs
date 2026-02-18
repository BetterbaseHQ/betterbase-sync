#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::get;
use axum::{extract::State, http::StatusCode, Router};
use less_sync_auth::TokenValidator;
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
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/ws", get(ws::websocket_upgrade))
        .with_state(state)
}

async fn health(State(state): State<ApiState>) -> StatusCode {
    match state.health.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
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

    use super::{router, ApiState, HealthCheck};

    struct StubHealth {
        healthy: bool,
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
}
