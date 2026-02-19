use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    MembershipListParams, MembershipListResult, WsMembershipEntry, ERR_CODE_BAD_REQUEST,
    ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
};
use less_sync_storage::StorageError;
use uuid::Uuid;

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<MembershipListParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid membership list params".to_owned(),
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

    let metadata_version = match sync_storage.get_space(space_id).await {
        Ok(space) => space.metadata_version,
        Err(StorageError::SpaceNotFound) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_NOT_FOUND,
                "space not found".to_owned(),
            )
            .await;
            return;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    };

    match sync_storage.get_members(space_id, params.since_seq).await {
        Ok(entries) => {
            let entries = entries
                .into_iter()
                .map(|entry| WsMembershipEntry {
                    chain_seq: entry.chain_seq,
                    prev_hash: if entry.prev_hash.is_empty() {
                        None
                    } else {
                        Some(entry.prev_hash)
                    },
                    entry_hash: entry.entry_hash,
                    payload: entry.payload,
                })
                .collect::<Vec<_>>();
            send_result_response(
                outbound,
                id,
                &MembershipListResult {
                    entries,
                    metadata_version,
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
