use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    DekRecord as WsDekRecord, DeksGetParams, DeksGetResult, DeksRewrapParams, DeksRewrapResult,
    FileDekRecord as WsFileDekRecord, FileDeksGetParams, FileDeksGetResult, FileDeksRewrapParams,
    FileDeksRewrapResult, ERR_CODE_BAD_REQUEST, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use less_sync_storage::{DekRecord, FileDekRecord, StorageError};
use uuid::Uuid;

pub(super) async fn handle_get_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<DeksGetParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid deks get params".to_owned(),
            )
            .await;
            return;
        }
    };
    let space_id = match parse_space_id(outbound, id, &params.space).await {
        Some(space_id) => space_id,
        None => return,
    };

    if !authorize_read(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    match sync_storage.get_deks(space_id, params.since).await {
        Ok(deks) => {
            let deks = deks
                .into_iter()
                .map(|dek| WsDekRecord {
                    id: dek.id,
                    dek: dek.wrapped_dek,
                    seq: dek.cursor,
                })
                .collect();
            send_result_response(outbound, id, &DeksGetResult { deks }).await;
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

pub(super) async fn handle_rewrap_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<DeksRewrapParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid deks rewrap params".to_owned(),
            )
            .await;
            return;
        }
    };
    let space_id = match parse_space_id(outbound, id, &params.space).await {
        Some(space_id) => space_id,
        None => return,
    };

    if !authorize_write(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    let deks = params
        .deks
        .into_iter()
        .map(|dek| DekRecord {
            id: dek.id,
            wrapped_dek: dek.dek,
            cursor: 0,
        })
        .collect::<Vec<_>>();
    let success = sync_storage.rewrap_deks(space_id, &deks).await.is_ok();
    send_result_response(
        outbound,
        id,
        &DeksRewrapResult {
            ok: success,
            count: if success { deks.len() as i32 } else { 0 },
        },
    )
    .await;
}

pub(super) async fn handle_file_get_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<FileDeksGetParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid file deks get params".to_owned(),
            )
            .await;
            return;
        }
    };
    let space_id = match parse_space_id(outbound, id, &params.space).await {
        Some(space_id) => space_id,
        None => return,
    };

    if !authorize_read(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    match sync_storage.get_file_deks(space_id, params.since).await {
        Ok(deks) => {
            let deks = deks
                .into_iter()
                .map(|dek| WsFileDekRecord {
                    id: dek.id.to_string(),
                    dek: dek.wrapped_dek,
                    cursor: dek.cursor,
                })
                .collect();
            send_result_response(outbound, id, &FileDeksGetResult { deks }).await;
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

pub(super) async fn handle_file_rewrap_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<FileDeksRewrapParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid file deks rewrap params".to_owned(),
            )
            .await;
            return;
        }
    };
    let space_id = match parse_space_id(outbound, id, &params.space).await {
        Some(space_id) => space_id,
        None => return,
    };

    if !authorize_write(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    let mut valid = true;
    let deks = params
        .deks
        .into_iter()
        .filter_map(|dek| match Uuid::parse_str(&dek.id) {
            Ok(file_id) => Some(FileDekRecord {
                id: file_id,
                wrapped_dek: dek.dek,
                cursor: 0,
            }),
            Err(_) => {
                valid = false;
                None
            }
        })
        .collect::<Vec<_>>();
    if !valid {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "invalid file id".to_owned(),
        )
        .await;
        return;
    }

    let success = sync_storage.rewrap_file_deks(space_id, &deks).await.is_ok();
    send_result_response(
        outbound,
        id,
        &FileDeksRewrapResult {
            ok: success,
            count: if success { deks.len() as i32 } else { 0 },
        },
    )
    .await;
}

async fn parse_space_id(outbound: &OutboundSender, id: &str, space: &str) -> Option<Uuid> {
    match Uuid::parse_str(space) {
        Ok(space_id) => Some(space_id),
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid space id".to_owned(),
            )
            .await;
            None
        }
    }
}

async fn authorize_read(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    space_id: Uuid,
    ucan: &str,
) -> bool {
    match authz::authorize_read_space(sync_storage, auth, space_id, ucan).await {
        Ok(_) => true,
        Err(SpaceAuthzError::Forbidden) => {
            send_error_response(outbound, id, ERR_CODE_FORBIDDEN, "forbidden".to_owned()).await;
            false
        }
        Err(SpaceAuthzError::Internal) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            false
        }
    }
}

async fn authorize_write(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    space_id: Uuid,
    ucan: &str,
) -> bool {
    match authz::authorize_write_space(sync_storage, auth, space_id, ucan).await {
        Ok(_) => true,
        Err(SpaceAuthzError::Forbidden) => {
            send_error_response(outbound, id, ERR_CODE_FORBIDDEN, "forbidden".to_owned()).await;
            false
        }
        Err(SpaceAuthzError::Internal) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            false
        }
    }
}
