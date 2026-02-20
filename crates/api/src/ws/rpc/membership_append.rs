use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::{OutboundSender, RealtimeSession};
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    MembershipAppendParams, MembershipAppendResult, WsMembershipData, WsMembershipEntry,
    ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND, ERR_CODE_RATE_LIMITED,
};
use less_sync_storage::{MembersLogEntry, StorageError};
use uuid::Uuid;

const RATE_LIMIT_MAX: i64 = 10;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    auth: &AuthContext,
    identity_hash_key: Option<&[u8]>,
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

    // Rate limiting (before expensive validation/storage ops).
    let actor_hash = if let Some(key) = identity_hash_key {
        let hash = less_sync_storage::rate_limit_hash(key, &auth.issuer, &auth.user_id);
        let since = SystemTime::now() - RATE_LIMIT_WINDOW;
        match sync_storage
            .count_recent_actions("membership_append", &hash, since)
            .await
        {
            Ok(count) if count >= RATE_LIMIT_MAX => {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_RATE_LIMITED,
                    "rate limit exceeded: max 10 membership appends per hour".to_owned(),
                )
                .await;
                return;
            }
            Ok(_) => {}
            Err(_) => {
                tracing::error!("failed to count recent membership appends");
                send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal error".to_owned())
                    .await;
                return;
            }
        }
        Some(hash)
    } else {
        None
    };

    // Validate entry_hash is 32 bytes (SHA-256 digest).
    if params.entry_hash.len() != 32 {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "entry_hash must be 32 bytes".to_owned(),
        )
        .await;
        return;
    }

    // Payload must not be empty.
    if params.payload.is_empty() {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "payload must not be empty".to_owned(),
        )
        .await;
        return;
    }

    // Verify SHA-256(payload) == entry_hash.
    let computed = Sha256::digest(&params.payload);
    if computed[..] != params.entry_hash[..] {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "entry_hash does not match SHA-256 of payload".to_owned(),
        )
        .await;
        return;
    }

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
            // Record the rate-limit action after successful append.
            if let Some(hash) = &actor_hash {
                if let Err(err) = sync_storage
                    .record_action("membership_append", hash)
                    .await
                {
                    tracing::error!(%err, "failed to record rate limit action");
                }
            }

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
