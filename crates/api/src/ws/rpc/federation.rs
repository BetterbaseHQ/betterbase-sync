use std::time::{Duration, SystemTime, UNIX_EPOCH};

use less_sync_auth::{parse_ucan, validate_chain, AudienceClaim, Permission, ValidateChainParams};
use less_sync_core::protocol::{
    Change, PullParams, PushParams, PushRpcResult, SubscribeParams, SubscribeResult,
    WsMembershipData, WsMembershipEntry, WsPullBeginData, WsPullCommitData, WsPullFileData,
    WsPullRecordData, WsSpaceError, WsSubscribedSpace, WsSyncRecord, ERR_CODE_BAD_REQUEST,
    ERR_CODE_CONFLICT, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS,
    ERR_CODE_KEY_GEN_STALE, ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE,
};
use less_sync_storage::{PullEntryKind, StorageError};
use serde::Serialize;
use uuid::Uuid;

use super::frames::{
    send_chunk_response, send_error_response, send_method_not_found_response, send_result_response,
};
use super::{decode_frame_params, RequestContext, RequestFrame};
use crate::ws::authz;
use crate::ws::realtime::{OutboundSender, RealtimeSession};
use crate::ws::SyncStorage;

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    context: RequestContext<'_>,
    frame: RequestFrame<'_>,
    peer_domain: &str,
    token_keys: Option<&crate::FederationTokenKeys>,
) {
    let RequestFrame {
        id,
        method,
        payload,
    } = frame;
    let RequestContext {
        sync_storage,
        realtime,
        presence_registry: _,
    } = context;

    match method {
        "subscribe" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_subscribe_request(
                outbound,
                sync_storage,
                realtime,
                id,
                payload,
                peer_domain,
                token_keys,
            )
            .await;
        }
        "push" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_push_request(outbound, sync_storage, realtime, id, payload).await;
        }
        "pull" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_pull_request(outbound, sync_storage, id, payload).await;
        }
        _ => {
            send_method_not_found_response(outbound, id, method).await;
        }
    }
}

async fn handle_subscribe_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    id: &str,
    payload: &[u8],
    peer_domain: &str,
    token_keys: Option<&crate::FederationTokenKeys>,
) {
    let params = match decode_frame_params::<SubscribeParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid subscribe params".to_owned(),
            )
            .await;
            return;
        }
    };

    if params.spaces.is_empty() {
        send_result_response(
            outbound,
            id,
            &SubscribeResult {
                spaces: Vec::new(),
                errors: Vec::new(),
            },
        )
        .await;
        return;
    }

    let mut added_spaces = Vec::with_capacity(params.spaces.len());
    let mut spaces = Vec::with_capacity(params.spaces.len());
    let mut errors = Vec::new();

    for requested in &params.spaces {
        let space_id = match Uuid::parse_str(&requested.id) {
            Ok(space_id) => space_id,
            Err(_) => {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_BAD_REQUEST.to_owned(),
                });
                continue;
            }
        };

        let (state, expiry_cap) = if !requested.ucan.is_empty() {
            match authorize_federation_ucan(
                sync_storage,
                space_id,
                &requested.ucan,
                Permission::Read,
                MissingRootPublicKey::NotFound,
                HomeServerPolicy::AllowAny,
            )
            .await
            {
                Ok(authorized) => (authorized.state, authorized.expiry_cap),
                Err(AuthFailure::Forbidden) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_FORBIDDEN.to_owned(),
                    });
                    continue;
                }
                Err(AuthFailure::NotFound) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_NOT_FOUND.to_owned(),
                    });
                    continue;
                }
                Err(AuthFailure::Internal) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_INTERNAL.to_owned(),
                    });
                    continue;
                }
            }
        } else if !requested.token.is_empty() {
            let Some(token_keys) = token_keys else {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_INTERNAL.to_owned(),
                });
                continue;
            };
            let claims = match token_keys.verify_fst(&requested.token, peer_domain) {
                Ok(claims) => claims,
                Err(_) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_FORBIDDEN.to_owned(),
                    });
                    continue;
                }
            };
            if claims.space_id != space_id {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_FORBIDDEN.to_owned(),
                });
                continue;
            }
            let state = match sync_storage.get_space(space_id).await {
                Ok(space) => SpaceState {
                    cursor: space.cursor,
                    key_generation: space.key_generation,
                    rewrap_epoch: space.rewrap_epoch,
                },
                Err(_) => SpaceState::default(),
            };
            (state, Some(claims.expires_at))
        } else {
            errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_BAD_REQUEST.to_owned(),
            });
            continue;
        };

        let token = match token_keys {
            Some(keys) => match keys.create_fst(space_id, peer_domain, expiry_cap) {
                Ok(token) => token,
                Err(_) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_INTERNAL.to_owned(),
                    });
                    continue;
                }
            },
            None => String::new(),
        };

        added_spaces.push(requested.id.clone());
        spaces.push(WsSubscribedSpace {
            id: requested.id.clone(),
            cursor: state.cursor,
            key_generation: state.key_generation,
            rewrap_epoch: state.rewrap_epoch,
            token,
            peers: Vec::new(),
        });
    }

    if let Some(realtime) = realtime {
        realtime.add_spaces(&added_spaces).await;
    }

    send_result_response(outbound, id, &SubscribeResult { spaces, errors }).await;
}

async fn handle_push_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    id: &str,
    payload: &[u8],
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

    let changes = params
        .changes
        .iter()
        .map(|change| Change {
            id: change.id.clone(),
            blob: change.blob.clone(),
            cursor: change.expected_cursor,
            wrapped_dek: change.wrapped_dek.clone(),
            deleted: change.blob.is_none(),
        })
        .collect::<Vec<_>>();
    let sync_records = params
        .changes
        .iter()
        .map(|change| WsSyncRecord {
            id: change.id.clone(),
            blob: change.blob.clone(),
            cursor: change.expected_cursor,
            wrapped_dek: change.wrapped_dek.clone(),
            deleted: change.blob.is_none(),
        })
        .collect::<Vec<_>>();

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

    if let (Some(realtime), Some(cursor)) = (realtime, sync_cursor) {
        realtime
            .broadcast_sync(&params.space, cursor, &sync_records)
            .await;
    }
}

async fn handle_pull_request(
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
            match entry.kind {
                PullEntryKind::Record => {
                    if let Some(record) = &entry.record {
                        send_chunk_response(
                            outbound,
                            id,
                            "pull.record",
                            &WsPullRecordData {
                                space: requested.id.clone(),
                                id: record.id.clone(),
                                blob: record.blob.clone(),
                                cursor: record.cursor,
                                wrapped_dek: record.wrapped_dek.clone(),
                                deleted: record.is_deleted(),
                            },
                        )
                        .await;
                        chunk_count += 1;
                        entry_count += 1;
                    }
                }
                PullEntryKind::Membership => {
                    if let Some(member) = &entry.member {
                        send_chunk_response(
                            outbound,
                            id,
                            "pull.membership",
                            &WsMembershipData {
                                space: requested.id.clone(),
                                cursor: member.cursor,
                                entries: vec![WsMembershipEntry {
                                    chain_seq: member.chain_seq,
                                    prev_hash: if member.prev_hash.is_empty() {
                                        None
                                    } else {
                                        Some(member.prev_hash.clone())
                                    },
                                    entry_hash: member.entry_hash.clone(),
                                    payload: member.payload.clone(),
                                }],
                            },
                        )
                        .await;
                        chunk_count += 1;
                        entry_count += 1;
                    }
                }
                PullEntryKind::File => {
                    if let Some(file) = &entry.file {
                        send_chunk_response(
                            outbound,
                            id,
                            "pull.file",
                            &WsPullFileData {
                                space: requested.id.clone(),
                                id: file.id.to_string(),
                                record_id: file.record_id.to_string(),
                                size: file.size,
                                wrapped_dek: Some(file.wrapped_dek.clone()),
                                cursor: file.cursor,
                                deleted: file.deleted,
                            },
                        )
                        .await;
                        chunk_count += 1;
                        entry_count += 1;
                    }
                }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingRootPublicKey {
    NotFound,
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HomeServerPolicy {
    AllowAny,
    RequireLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailure {
    Forbidden,
    NotFound,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SpaceState {
    cursor: i64,
    key_generation: i32,
    rewrap_epoch: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorizedSpace {
    state: SpaceState,
    expiry_cap: Option<SystemTime>,
}

async fn authorize_federation_ucan(
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
