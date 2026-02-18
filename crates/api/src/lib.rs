#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::routing::get;
use axum::{extract::State, http::StatusCode, Router};
use less_sync_storage::Storage;

#[derive(Clone)]
pub struct ApiState {
    storage: Arc<dyn Storage>,
}

impl ApiState {
    #[must_use]
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(state)
}

async fn health(State(state): State<ApiState>) -> StatusCode {
    match state.storage.ping().await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
