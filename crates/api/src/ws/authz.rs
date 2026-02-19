use less_sync_auth::{validate_chain, AuthContext, Permission, ValidateChainParams};
use uuid::Uuid;

use super::storage::SubscribedSpaceState;
use super::SyncStorage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpaceAuthzError {
    Forbidden,
    Internal,
}

pub(crate) async fn authorize_read_space(
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    space_id: Uuid,
    ucan: &str,
) -> Result<SubscribedSpaceState, SpaceAuthzError> {
    authorize_space(sync_storage, auth, space_id, ucan, Permission::Read).await
}

pub(crate) async fn authorize_write_space(
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    space_id: Uuid,
    ucan: &str,
) -> Result<SubscribedSpaceState, SpaceAuthzError> {
    authorize_space(sync_storage, auth, space_id, ucan, Permission::Write).await
}

async fn authorize_space(
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    space_id: Uuid,
    ucan: &str,
    required_permission: Permission,
) -> Result<SubscribedSpaceState, SpaceAuthzError> {
    if is_personal_space(auth, space_id) {
        return sync_storage
            .get_or_create_space(space_id, &auth.client_id)
            .await
            .map_err(|_| SpaceAuthzError::Internal);
    }

    let space = sync_storage
        .get_space(space_id)
        .await
        .map_err(|_| SpaceAuthzError::Forbidden)?;
    let root_public_key = match space.root_public_key {
        Some(root_public_key) => root_public_key,
        None => return Err(SpaceAuthzError::Forbidden),
    };

    if ucan.is_empty() || auth.did.is_empty() {
        return Err(SpaceAuthzError::Forbidden);
    }

    validate_chain(ValidateChainParams {
        token: ucan,
        expected_audience: &auth.did,
        required_permission,
        space_id: &space_id.to_string(),
        root_public_key: &root_public_key,
        is_revoked: None,
        now: None,
    })
    .map_err(|_| SpaceAuthzError::Forbidden)?;

    Ok(SubscribedSpaceState {
        cursor: space.cursor,
        key_generation: space.key_generation,
        rewrap_epoch: space.rewrap_epoch,
    })
}

fn is_personal_space(auth: &AuthContext, space_id: Uuid) -> bool {
    Uuid::parse_str(&auth.personal_space_id)
        .ok()
        .is_some_and(|personal_space_id| personal_space_id == space_id)
}
