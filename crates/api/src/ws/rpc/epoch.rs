use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    EpochBeginParams, EpochBeginResult, EpochCompleteParams, EpochConflictResult,
    ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use less_sync_storage::{AdvanceEpochOptions, StorageError};
use uuid::Uuid;

#[derive(Debug, serde::Serialize)]
struct EmptyResult {}

pub(super) async fn handle_begin_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<EpochBeginParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid epoch begin params".to_owned(),
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

    match authz::authorize_write_space(sync_storage, auth, space_id, &params.ucan).await {
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

    let options = AdvanceEpochOptions {
        set_min_key_generation: params.set_min_key_generation,
    };
    match sync_storage
        .advance_epoch(space_id, params.epoch, Some(&options))
        .await
    {
        Ok(result) => {
            send_result_response(
                outbound,
                id,
                &EpochBeginResult {
                    epoch: result.epoch,
                },
            )
            .await;
        }
        Err(StorageError::EpochConflict(conflict)) => {
            send_result_response(
                outbound,
                id,
                &EpochConflictResult {
                    error: ERR_CODE_CONFLICT.to_owned(),
                    current_epoch: conflict.current_epoch,
                    rewrap_epoch: conflict.rewrap_epoch,
                },
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

pub(super) async fn handle_complete_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<EpochCompleteParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid epoch complete params".to_owned(),
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

    match authz::authorize_write_space(sync_storage, auth, space_id, &params.ucan).await {
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

    match sync_storage.complete_rewrap(space_id, params.epoch).await {
        Ok(()) => send_result_response(outbound, id, &EmptyResult {}).await,
        Err(StorageError::EpochMismatch) => {
            send_error_response(outbound, id, ERR_CODE_CONFLICT, "epoch mismatch".to_owned()).await;
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
