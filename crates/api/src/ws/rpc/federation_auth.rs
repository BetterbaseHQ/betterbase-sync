use std::time::{Duration, SystemTime, UNIX_EPOCH};

use less_sync_auth::{parse_ucan, validate_chain, AudienceClaim, Permission, ValidateChainParams};
use less_sync_storage::StorageError;
use uuid::Uuid;

use crate::ws::authz;
use crate::ws::SyncStorage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MissingRootPublicKey {
    NotFound,
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HomeServerPolicy {
    AllowAny,
    RequireLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthFailure {
    Forbidden,
    NotFound,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct SpaceState {
    pub cursor: i64,
    pub key_generation: i32,
    pub rewrap_epoch: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuthorizedSpace {
    pub state: SpaceState,
    pub expiry_cap: Option<SystemTime>,
}

pub(super) async fn authorize_federation_ucan(
    sync_storage: &dyn SyncStorage,
    space_id: Uuid,
    ucan: &str,
    required_permission: Permission,
    missing_root_policy: MissingRootPublicKey,
    home_server_policy: HomeServerPolicy,
) -> Result<AuthorizedSpace, AuthFailure> {
    if ucan.is_empty() {
        return Err(AuthFailure::Forbidden);
    }

    let space = sync_storage
        .get_space(space_id)
        .await
        .map_err(|error| match error {
            StorageError::SpaceNotFound => AuthFailure::NotFound,
            _ => AuthFailure::Internal,
        })?;
    if matches!(home_server_policy, HomeServerPolicy::RequireLocal) && space.home_server.is_some() {
        return Err(AuthFailure::Forbidden);
    }
    let root_public_key = match space.root_public_key {
        Some(root_public_key) => root_public_key,
        None => {
            return Err(match missing_root_policy {
                MissingRootPublicKey::NotFound => AuthFailure::NotFound,
                MissingRootPublicKey::Forbidden => AuthFailure::Forbidden,
            });
        }
    };

    let parsed = parse_ucan(ucan).map_err(|_| AuthFailure::Forbidden)?;
    let expected_audience = first_ucan_audience(&parsed).ok_or(AuthFailure::Forbidden)?;

    authz::ensure_chain_not_revoked(sync_storage, space_id, ucan)
        .await
        .map_err(|_| AuthFailure::Forbidden)?;
    validate_chain(ValidateChainParams {
        token: ucan,
        expected_audience,
        required_permission,
        space_id: &space_id.to_string(),
        root_public_key: &root_public_key,
        is_revoked: None,
        now: None,
    })
    .map_err(|_| AuthFailure::Forbidden)?;

    Ok(AuthorizedSpace {
        state: SpaceState {
            cursor: space.cursor,
            key_generation: space.key_generation,
            rewrap_epoch: space.rewrap_epoch,
        },
        expiry_cap: ucan_expiry_cap(&parsed),
    })
}

fn first_ucan_audience(parsed: &less_sync_auth::ParsedUcan) -> Option<&str> {
    match parsed.claims.aud.as_ref() {
        Some(AudienceClaim::One(value)) => Some(value),
        Some(AudienceClaim::Many(values)) => values.first().map(String::as_str),
        None => None,
    }
}

fn ucan_expiry_cap(parsed: &less_sync_auth::ParsedUcan) -> Option<SystemTime> {
    parsed
        .claims
        .exp
        .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
}
