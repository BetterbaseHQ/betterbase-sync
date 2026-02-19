use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    DekRecord as WsDekRecord, DeksGetParams, DeksGetResult, DeksRewrapParams, DeksRewrapResult,
    FileDekRecord as WsFileDekRecord, FileDeksGetParams, FileDeksGetResult, FileDeksRewrapParams,
    FileDeksRewrapResult, ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN,
    ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use less_sync_storage::{DekRecord, FileDekRecord, StorageError};
use uuid::Uuid;

const WRAPPED_DEK_LEN: usize = 44;

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
    if !ensure_scope(outbound, auth, id, "sync").await {
        return;
    }

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
    if !ensure_scope(outbound, auth, id, "sync").await {
        return;
    }

    if !authorize_write(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    let deks = match decode_rewrap_deks(outbound, id, params).await {
        Some(deks) => deks,
        None => return,
    };

    match sync_storage.rewrap_deks(space_id, &deks).await {
        Ok(()) => {
            send_result_response(
                outbound,
                id,
                &DeksRewrapResult {
                    ok: true,
                    count: deks.len() as i32,
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
        Err(StorageError::DekRecordNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "one or more DEK records were not found".to_owned(),
            )
            .await;
        }
        Err(StorageError::DekEpochMismatch) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_CONFLICT,
                "DEK epoch does not match current key generation".to_owned(),
            )
            .await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
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
    if !ensure_scope(outbound, auth, id, "files").await {
        return;
    }

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
    if !ensure_scope(outbound, auth, id, "files").await {
        return;
    }

    if !authorize_write(outbound, sync_storage, auth, id, space_id, &params.ucan).await {
        return;
    }

    let deks = match decode_rewrap_file_deks(outbound, id, params).await {
        Some(deks) => deks,
        None => return,
    };

    match sync_storage.rewrap_file_deks(space_id, &deks).await {
        Ok(()) => {
            send_result_response(
                outbound,
                id,
                &FileDeksRewrapResult {
                    ok: true,
                    count: deks.len() as i32,
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
        Err(StorageError::FileDekNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "one or more file DEK records were not found".to_owned(),
            )
            .await;
        }
        Err(StorageError::DekEpochMismatch) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_CONFLICT,
                "DEK epoch does not match current key generation".to_owned(),
            )
            .await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
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

async fn ensure_scope(
    outbound: &OutboundSender,
    auth: &AuthContext,
    id: &str,
    required_scope: &str,
) -> bool {
    if has_scope(&auth.scope, required_scope) {
        return true;
    }

    send_error_response(
        outbound,
        id,
        ERR_CODE_FORBIDDEN,
        format!("{required_scope} scope required"),
    )
    .await;
    false
}

fn has_scope(scope: &str, required: &str) -> bool {
    scope.split_whitespace().any(|token| token == required)
}

async fn decode_rewrap_deks(
    outbound: &OutboundSender,
    id: &str,
    params: DeksRewrapParams,
) -> Option<Vec<DekRecord>> {
    let mut deks = Vec::with_capacity(params.deks.len());

    for dek in params.deks {
        if dek.id.is_empty() {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid record: id must be non-empty string".to_owned(),
            )
            .await;
            return None;
        }
        if dek.dek.len() != WRAPPED_DEK_LEN {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid record: wrapped DEK must be exactly 44 bytes".to_owned(),
            )
            .await;
            return None;
        }

        deks.push(DekRecord {
            id: dek.id,
            wrapped_dek: dek.dek,
            cursor: 0,
        });
    }

    Some(deks)
}

async fn decode_rewrap_file_deks(
    outbound: &OutboundSender,
    id: &str,
    params: FileDeksRewrapParams,
) -> Option<Vec<FileDekRecord>> {
    let mut deks = Vec::with_capacity(params.deks.len());

    for dek in params.deks {
        let file_id = match Uuid::parse_str(&dek.id) {
            Ok(file_id) => file_id,
            Err(_) => {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_BAD_REQUEST,
                    "invalid record: id must be a valid UUID".to_owned(),
                )
                .await;
                return None;
            }
        };
        if dek.dek.len() != WRAPPED_DEK_LEN {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid record: wrapped DEK must be exactly 44 bytes".to_owned(),
            )
            .await;
            return None;
        }

        deks.push(FileDekRecord {
            id: file_id,
            wrapped_dek: dek.dek,
            cursor: 0,
        });
    }

    Some(deks)
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
