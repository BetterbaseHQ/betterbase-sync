use axum::extract::{Path, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use less_sync_auth::canonicalize_domain;
use serde::Serialize;

use crate::{ApiState, FederationPeerStatus};

pub(crate) async fn jwks(State(state): State<ApiState>) -> impl IntoResponse {
    let mut response = Json(state.federation_jwks()).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );
    response
}

pub(crate) async fn trusted_peers(
    State(state): State<ApiState>,
) -> Result<Json<FederationTrustedPeers>, StatusCode> {
    if state.federation_authenticator().is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(FederationTrustedPeers {
        domains: state.federation_trusted_domains(),
    }))
}

pub(crate) async fn peer_status(
    Path(domain): Path<String>,
    State(state): State<ApiState>,
) -> Result<Json<FederationPeerStatus>, StatusCode> {
    if state.federation_authenticator().is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let canonical_domain = canonicalize_domain(&domain);
    let trusted_domains = state.federation_trusted_domains();
    if !trusted_domains.is_empty()
        && !trusted_domains
            .iter()
            .any(|entry| entry == &canonical_domain)
    {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(
        state
            .federation_quota_tracker()
            .peer_status(&canonical_domain)
            .await,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FederationTrustedPeers {
    pub domains: Vec<String>,
}
