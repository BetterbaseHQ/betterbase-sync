#![forbid(unsafe_code)]

use axum::routing::get;
use axum::Router;

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}
