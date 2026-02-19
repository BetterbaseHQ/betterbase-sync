use axum::extract::{Path, State};
use axum::Json;
use less_sync_auth::canonicalize_domain;
use serde::Serialize;

use crate::{ApiState, FederationJwks, FederationPeerStatus};

pub(crate) async fn jwks(State(state): State<ApiState>) -> Json<FederationJwks> {
    Json(state.federation_jwks())
}

pub(crate) async fn trusted_peers(State(state): State<ApiState>) -> Json<FederationTrustedPeers> {
    Json(FederationTrustedPeers {
        domains: state.federation_trusted_domains(),
    })
}

pub(crate) async fn peer_status(
    Path(domain): Path<String>,
    State(state): State<ApiState>,
) -> Json<FederationPeerStatus> {
    let canonical_domain = canonicalize_domain(&domain);
    Json(
        state
            .federation_quota_tracker()
            .peer_status(&canonical_domain)
            .await,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FederationTrustedPeers {
    pub domains: Vec<String>,
}
