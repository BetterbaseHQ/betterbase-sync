use less_sync_auth::Permission;
use less_sync_core::protocol::{
    PullParams, PushParams, PushRpcResult, WsPullBeginData, WsPullCommitData, ERR_CODE_BAD_REQUEST,
    ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS,
    ERR_CODE_KEY_GEN_STALE, ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE, ERR_CODE_RATE_LIMITED,
};
use less_sync_storage::StorageError;
use serde::Serialize;
use uuid::Uuid;

use super::decode_frame_params;
use super::federation_auth::{
    authorize_federation_ucan, AuthFailure, HomeServerPolicy, MissingRootPublicKey,
};
use super::frames::{send_chunk_response, send_error_response, send_result_response};
use crate::ws::realtime::{OutboundSender, RealtimeSession};
use crate::ws::SyncStorage;

pub(super) async fn handle_push_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    id: &str,
    payload: &[u8],
    peer_domain: &str,
    quota_tracker: Option<&crate::FederationQuotaTracker>,
) {
    let params = match decode_frame_params::<PushParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid push params".to_owned(),
            )
            .await;
            return;
        }
    };

    let space_id = match Uuid::parse_str(&params.space) {
        Ok(space_id) => space_id,
        Err(_) => {
            send_result_response(
                outbound,
                id,
                &PushRpcResult {
                    ok: false,
                    cursor: 0,
                    error: ERR_CODE_BAD_REQUEST.to_owned(),
                },
            )
            .await;
            return;
        }
    };

    match authorize_federation_ucan(
        sync_storage,
        space_id,
        &params.ucan,
        Permission::Write,
        MissingRootPublicKey::Forbidden,
        HomeServerPolicy::RequireLocal,
    )
    .await
    {
        Ok(_) => {}
        Err(AuthFailure::Forbidden) => {
            send_result_response(
                outbound,
                id,
                &PushRpcResult {
                    ok: false,
                    cursor: 0,
                    error: ERR_CODE_FORBIDDEN.to_owned(),
                },
            )
            .await;
            return;
        }
        Err(AuthFailure::NotFound) => {
            send_result_response(
                outbound,
                id,
                &PushRpcResult {
                    ok: false,
                    cursor: 0,
                    error: ERR_CODE_NOT_FOUND.to_owned(),
                },
            )
            .await;
            return;
        }
        Err(AuthFailure::Internal) => {
            send_result_response(
                outbound,
                id,
                &PushRpcResult {
                    ok: false,
                    cursor: 0,
                    error: ERR_CODE_INTERNAL.to_owned(),
                },
            )
            .await;
            return;
        }
    }

    let push_bytes = params
        .changes
        .iter()
        .map(push_change_bytes)
        .fold(0_u64, u64::saturating_add);
    if let Some(quota_tracker) = quota_tracker {
        if !quota_tracker
            .check_and_record_push(peer_domain, params.changes.len(), push_bytes)
            .await
        {
            send_error_response(
                outbound,
                id,
                ERR_CODE_RATE_LIMITED,
                "record push quota exceeded".to_owned(),
            )
            .await;
            return;
        }
    }

    let changes = super::push_helpers::map_push_changes(&params);
    let mut sync_cursor = None;
    let response = match sync_storage.push(space_id, &changes).await {
        Ok(result) if result.ok => {
            sync_cursor = Some(result.cursor);
            PushRpcResult {
                ok: true,
                cursor: result.cursor,
                error: String::new(),
            }
        }
        Ok(_) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_CONFLICT.to_owned(),
        },
        Err(StorageError::SpaceNotFound) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_NOT_FOUND.to_owned(),
        },
        Err(StorageError::KeyGenerationStale) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_KEY_GEN_STALE.to_owned(),
        },
        Err(StorageError::InvalidRecordId | StorageError::DuplicateRecordId) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_BAD_REQUEST.to_owned(),
        },
        Err(
            StorageError::BlobTooLarge
            | StorageError::PushRecordLimitExceeded
            | StorageError::PushPayloadLimitExceeded,
        ) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_PAYLOAD_TOO_LARGE.to_owned(),
        },
        Err(_) => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_INTERNAL.to_owned(),
        },
    };

    send_result_response(outbound, id, &response).await;
    super::push_helpers::broadcast_push_sync(realtime, &params, sync_cursor).await;
}

pub(super) async fn handle_pull_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<PullParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid pull params".to_owned(),
            )
            .await;
            return;
        }
    };

    let mut chunk_count = 0_usize;
    for requested in &params.spaces {
        let space_id = match Uuid::parse_str(&requested.id) {
            Ok(space_id) => space_id,
            Err(_) => continue,
        };

        let auth = match authorize_federation_ucan(
            sync_storage,
            space_id,
            &requested.ucan,
            Permission::Read,
            MissingRootPublicKey::NotFound,
            HomeServerPolicy::AllowAny,
        )
        .await
        {
            Ok(auth) => auth,
            Err(_) => continue,
        };

        let pull_result = match sync_storage.pull(space_id, requested.since).await {
            Ok(pull_result) => pull_result,
            Err(StorageError::SpaceNotFound) => continue,
            Err(_) => continue,
        };

        let mut entry_count = 0_i32;
        send_chunk_response(
            outbound,
            id,
            "pull.begin",
            &WsPullBeginData {
                space: requested.id.clone(),
                prev: requested.since,
                cursor: pull_result.cursor,
                key_generation: auth.state.key_generation,
                rewrap_epoch: auth.state.rewrap_epoch,
            },
        )
        .await;
        chunk_count += 1;

        for entry in &pull_result.entries {
            if super::pull_send::send_pull_entry(outbound, id, &requested.id, entry).await {
                chunk_count += 1;
                entry_count += 1;
            }
        }

        send_chunk_response(
            outbound,
            id,
            "pull.commit",
            &WsPullCommitData {
                space: requested.id.clone(),
                prev: requested.since,
                cursor: pull_result.cursor,
                count: entry_count,
            },
        )
        .await;
        chunk_count += 1;
    }

    send_result_response(
        outbound,
        id,
        &PullRpcResult {
            chunks: chunk_count as i32,
        },
    )
    .await;
}

#[derive(Debug, Serialize)]
struct PullRpcResult {
    #[serde(rename = "_chunks")]
    chunks: i32,
}

fn push_change_bytes(change: &less_sync_core::protocol::WsPushChange) -> u64 {
    let blob_bytes = change.blob.as_ref().map_or(0, Vec::len) as u64;
    let dek_bytes = change.wrapped_dek.as_ref().map_or(0, Vec::len) as u64;
    blob_bytes.saturating_add(dek_bytes)
}
