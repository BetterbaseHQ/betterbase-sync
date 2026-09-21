//! Epoch key shares for fresh-key rotation (AUD-024 / D-005).
//!
//! `epochKeys.put` (admin) stores per-member wrapped copies of a fresh epoch
//! key before any DEK rewrap. `epochKeys.get` (member) fetches the caller's
//! own share. The server stores opaque wrapped blobs only — the same trust
//! model as invitations.

use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use betterbase_sync_auth::AuthContext;
use betterbase_sync_core::protocol::{
    EpochKeyShareEntry, EpochKeysGetParams, EpochKeysGetResult, EpochKeysPutParams,
    EpochKeysPutResult, ERR_CODE_BAD_REQUEST, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use betterbase_sync_storage::{EpochKeyShare, StorageError};
use uuid::Uuid;

/// Max shares per rotation.
const MAX_SHARES: usize = 1000;
/// Max wrapped-key blob (ECDH JWE compact serialization stays well below).
const MAX_WRAPPED_KEY_LEN: usize = 2048;

pub(super) async fn handle_put_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<EpochKeysPutParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid epochKeys.put params".to_owned(),
            )
            .await;
            return;
        }
    };

    let space_id = match Uuid::parse_str(&params.space) {
        Ok(space_id) => space_id,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid space id".to_owned(),
            )
            .await;
            return;
        }
    };

    // Only administrators distribute rotation keys.
    match authz::authorize_admin_space(sync_storage, auth, space_id, &params.ucan).await {
        Ok(_) => {}
        Err(SpaceAuthzError::Forbidden) => {
            send_error_response(outbound, id, ERR_CODE_FORBIDDEN, "forbidden".to_owned()).await;
            return;
        }
        Err(SpaceAuthzError::Internal) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    }

    if params.keys.is_empty() || params.keys.len() > MAX_SHARES {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "keys must contain 1..=1000 shares".to_owned(),
        )
        .await;
        return;
    }
    let mut shares = Vec::with_capacity(params.keys.len());
    for EpochKeyShareEntry {
        member_did,
        wrapped_key,
    } in &params.keys
    {
        if member_did.is_empty()
            || wrapped_key.is_empty()
            || wrapped_key.len() > MAX_WRAPPED_KEY_LEN
        {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid epoch key share".to_owned(),
            )
            .await;
            return;
        }
        shares.push(EpochKeyShare {
            member_did: member_did.clone(),
            wrapped_key: wrapped_key.clone(),
        });
    }

    let count = shares.len() as i32;
    match sync_storage
        .put_epoch_key_shares(space_id, params.epoch, &shares)
        .await
    {
        Ok(()) => {
            send_result_response(outbound, id, &EpochKeysPutResult { count }).await;
        }
        Err(StorageError::SpaceNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_NOT_FOUND,
                "space not found".to_owned(),
            )
            .await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
}

pub(super) async fn handle_get_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<EpochKeysGetParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid epochKeys.get params".to_owned(),
            )
            .await;
            return;
        }
    };

    let space_id = match Uuid::parse_str(&params.space) {
        Ok(space_id) => space_id,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid space id".to_owned(),
            )
            .await;
            return;
        }
    };

    match authz::authorize_read_space(sync_storage, auth, space_id, &params.ucan).await {
        Ok(_) => {}
        Err(SpaceAuthzError::Forbidden) => {
            send_error_response(outbound, id, ERR_CODE_FORBIDDEN, "forbidden".to_owned()).await;
            return;
        }
        Err(SpaceAuthzError::Internal) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    }

    // A member may only fetch their own share.
    match sync_storage
        .get_epoch_key_share(space_id, params.epoch, &auth.did)
        .await
    {
        Ok(wrapped_key) => {
            send_result_response(outbound, id, &EpochKeysGetResult { wrapped_key }).await;
        }
        Err(StorageError::EpochKeyShareNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_NOT_FOUND,
                "no key share for this member".to_owned(),
            )
            .await;
        }
        Err(StorageError::SpaceNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_NOT_FOUND,
                "space not found".to_owned(),
            )
            .await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
}
