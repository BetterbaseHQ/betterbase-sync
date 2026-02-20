use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::{OutboundSender, RealtimeSession};
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    MembershipAppendParams, MembershipAppendResult, WsMembershipData, WsMembershipEntry,
    ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use less_sync_storage::{MembersLogEntry, StorageError};
use uuid::Uuid;

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<MembershipAppendParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid membership append params".to_owned(),
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

    let entry = MembersLogEntry {
        space_id,
        chain_seq: 0,
        cursor: 0,
        prev_hash: params.prev_hash.unwrap_or_default(),
        entry_hash: params.entry_hash,
        payload: params.payload,
    };
    match sync_storage
        .append_member(space_id, params.expected_version, &entry)
        .await
    {
        Ok(result) => {
            send_result_response(
                outbound,
                id,
                &MembershipAppendResult {
                    chain_seq: result.chain_seq,
                    metadata_version: result.metadata_version,
                },
            )
            .await;
            if let Some(realtime) = realtime {
                realtime
                    .broadcast_membership(
                        &params.space,
                        &WsMembershipData {
                            space: params.space.clone(),
                            cursor: result.cursor,
                            entries: vec![WsMembershipEntry {
                                chain_seq: result.chain_seq,
                                prev_hash: if entry.prev_hash.is_empty() {
                                    None
                                } else {
                                    Some(entry.prev_hash.clone())
                                },
                                entry_hash: entry.entry_hash.clone(),
                                payload: entry.payload.clone(),
                            }],
                        },
                    )
                    .await;
            }
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
        Err(StorageError::VersionConflict | StorageError::HashChainBroken) => {
            send_error_response(outbound, id, ERR_CODE_CONFLICT, "conflict".to_owned()).await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
}
