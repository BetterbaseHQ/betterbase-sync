#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::get;
use axum::{extract::State, http::StatusCode, Router};
use less_sync_storage::{Storage, StorageError};

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
}

impl ApiState {
    #[must_use]
    pub fn new(health: Arc<dyn HealthCheck>) -> Self {
        Self { health }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
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
        assert_eq!(response.status(), axum::http::StatusCode::OK);
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
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
