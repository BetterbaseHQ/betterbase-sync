use super::super::authz::{self, SpaceAuthzError};
use super::super::presence::{MAX_EVENT_DATA_BYTES, MAX_PRESENCE_DATA_BYTES};
use super::super::realtime::OutboundSender;
use super::super::{realtime::RealtimeSession, PresenceRegistry, SyncStorage};
use super::decode_frame_params;
use super::frames::{send_chunk_response, send_error_response, send_result_response};
use betterbase_sync_auth::AuthContext;
use betterbase_sync_core::protocol::{
    PullParams, PushParams, PushRpcResult, SubscribeParams, SubscribeResult, UnsubscribeParams,
    WsEventSendParams, WsPresenceClearParams, WsPresenceSetParams, WsPullBeginData,
    WsPullCommitData, WsSpaceError, WsSubscribedSpace, ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT,
    ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS, ERR_CODE_KEY_GEN_STALE,
    ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE,
};
use betterbase_sync_storage::StorageError;
use serde::Serialize;
use uuid::Uuid;

pub(super) async fn handle_unsubscribe_notification(
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    payload: &[u8],
) -> usize {
    let Some(realtime) = realtime else {
        return 0;
    };

    let params = match decode_frame_params::<UnsubscribeParams>(payload) {
        Ok(params) => params,
        Err(_) => return 0,
    };

    if params.spaces.is_empty() {
        return 0;
    }

    let removed = realtime.remove_spaces(&params.spaces).await;
    let Some(presence_registry) = presence_registry else {
        return removed;
    };

    let conn_id = realtime.peer_id().to_owned();
    for space_id in &params.spaces {
        if presence_registry.clear(space_id, &conn_id).await {
            let pseudonym = presence_registry.peer_pseudonym(&conn_id, space_id);
            realtime
                .broadcast_presence_leave(space_id, &pseudonym)
                .await;
        }
    }
    removed
}

pub(super) async fn handle_presence_set_notification(
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    payload: &[u8],
) {
    let (Some(realtime), Some(presence_registry)) = (realtime, presence_registry) else {
        return;
    };

    let params = match decode_frame_params::<WsPresenceSetParams>(payload) {
        Ok(params) => params,
        Err(_) => return,
    };

    if params.space.is_empty() || params.data.len() > MAX_PRESENCE_DATA_BYTES {
        return;
    }
    if !realtime.is_subscribed(&params.space).await {
        return;
    }

    let conn_id = realtime.peer_id().to_owned();
    let pseudonym = presence_registry.peer_pseudonym(&conn_id, &params.space);
    if presence_registry
        .set(&params.space, &conn_id, params.data.clone())
        .await
    {
        realtime
            .broadcast_presence(&params.space, &pseudonym, params.data)
            .await;
    }
}

pub(super) async fn handle_presence_clear_notification(
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    payload: &[u8],
) {
    let (Some(realtime), Some(presence_registry)) = (realtime, presence_registry) else {
        return;
    };

    let params = match decode_frame_params::<WsPresenceClearParams>(payload) {
        Ok(params) => params,
        Err(_) => return,
    };

    if params.space.is_empty() {
        return;
    }
    if !realtime.is_subscribed(&params.space).await {
        return;
    }

    let conn_id = realtime.peer_id().to_owned();
    if presence_registry.clear(&params.space, &conn_id).await {
        let pseudonym = presence_registry.peer_pseudonym(&conn_id, &params.space);
        realtime
            .broadcast_presence_leave(&params.space, &pseudonym)
            .await;
    }
}

pub(super) async fn handle_event_send_notification(
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    payload: &[u8],
) {
    let Some(realtime) = realtime else {
        return;
    };

    let params = match decode_frame_params::<WsEventSendParams>(payload) {
        Ok(params) => params,
        Err(_) => return,
    };

    if params.space.is_empty() || params.data.len() > MAX_EVENT_DATA_BYTES {
        return;
    }
    if !realtime.is_subscribed(&params.space).await {
        return;
    }

    let conn_id = realtime.peer_id().to_owned();
    let pseudonym = if let Some(presence_registry) = presence_registry {
        presence_registry.peer_pseudonym(&conn_id, &params.space)
    } else {
        conn_id
    };
    realtime
        .broadcast_event(&params.space, &pseudonym, params.data)
        .await;
}

pub(super) struct SubscribeContext<'a> {
    pub(super) realtime: Option<&'a RealtimeSession>,
    pub(super) presence_registry: Option<&'a PresenceRegistry>,
    pub(super) federation_forwarder: Option<&'a dyn crate::FederationForwarder>,
}

pub(super) async fn handle_subscribe_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    context: SubscribeContext<'_>,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let SubscribeContext {
        realtime,
        presence_registry,
        federation_forwarder,
    } = context;

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
    if params.spaces.len() > crate::federation_quota::MAX_SUBSCRIBE_SPACES {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "too many spaces in subscribe request".to_owned(),
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

        match authz::authorize_read_space(sync_storage, auth, space_id, &requested.ucan).await {
            Ok(space_state) => {
                let home_server = space_state.home_server.clone();
                if let (Some(federation_forwarder), Some(home_server)) =
                    (federation_forwarder, home_server)
                {
                    let peer_domain = betterbase_sync_auth::canonicalize_domain(&home_server);
                    let peer_ws_url = crate::federation_client::peer_ws_url(&home_server);
                    if federation_forwarder
                        .subscribe(&peer_domain, &peer_ws_url, std::slice::from_ref(requested))
                        .await
                        .is_err()
                    {
                        errors.push(WsSpaceError {
                            space: requested.id.clone(),
                            error: ERR_CODE_INTERNAL.to_owned(),
                        });
                        continue;
                    }
                }
                added_spaces.push(requested.id.clone());
                let peers = if requested.presence {
                    if let (Some(presence_registry), Some(realtime)) = (presence_registry, realtime)
                    {
                        presence_registry
                            .peers(&requested.id, realtime.peer_id())
                            .await
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                spaces.push(WsSubscribedSpace {
                    id: requested.id.clone(),
                    cursor: space_state.cursor,
                    key_generation: space_state.key_generation,
                    rewrap_epoch: space_state.rewrap_epoch,
                    token: String::new(),
                    peers,
                })
            }
            Err(SpaceAuthzError::Forbidden) => errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_FORBIDDEN.to_owned(),
            }),
            Err(SpaceAuthzError::Internal) => errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_INTERNAL.to_owned(),
            }),
        }
    }

    if let Some(realtime) = realtime {
        let _ = realtime.add_spaces(&added_spaces).await;
    }

    send_result_response(outbound, id, &SubscribeResult { spaces, errors }).await;
}

pub(super) async fn handle_push_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    federation_forwarder: Option<&dyn crate::FederationForwarder>,
    auth: &AuthContext,
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

    match authz::authorize_write_space(sync_storage, auth, space_id, &params.ucan).await {
        Ok(_) => {}
        Err(SpaceAuthzError::Forbidden) => {
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
        Err(SpaceAuthzError::Internal) => {
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

    if let Some(federation_forwarder) = federation_forwarder {
        let home_server = sync_storage
            .get_space(space_id)
            .await
            .ok()
            .and_then(|space| space.home_server);
        if let Some(home_server) = home_server {
            let peer_domain = betterbase_sync_auth::canonicalize_domain(&home_server);
            let peer_ws_url = crate::federation_client::peer_ws_url(&home_server);
            let response = match federation_forwarder
                .forward_push(&peer_domain, &peer_ws_url, &params)
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    let _ = federation_forwarder
                        .restore_subscriptions(&peer_domain, &peer_ws_url)
                        .await;
                    federation_forwarder
                        .forward_push(&peer_domain, &peer_ws_url, &params)
                        .await
                        .unwrap_or_else(|_| PushRpcResult {
                            ok: false,
                            cursor: 0,
                            error: ERR_CODE_INTERNAL.to_owned(),
                        })
                }
            };
            send_result_response(outbound, id, &response).await;
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
    federation_forwarder: Option<&dyn crate::FederationForwarder>,
    auth: &AuthContext,
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

        let space_state = match authz::authorize_read_space(
            sync_storage,
            auth,
            space_id,
            &requested.ucan,
        )
        .await
        {
            Ok(space_state) => space_state,
            Err(_) => continue,
        };

        if let (Some(federation_forwarder), Some(home_server)) =
            (federation_forwarder, space_state.home_server.clone())
        {
            let peer_domain = betterbase_sync_auth::canonicalize_domain(&home_server);
            let peer_ws_url = crate::federation_client::peer_ws_url(&home_server);
            let remote_chunks = match federation_forwarder
                .pull(&peer_domain, &peer_ws_url, std::slice::from_ref(requested))
                .await
            {
                Ok(chunks) => chunks,
                Err(_) => continue,
            };
            for chunk in remote_chunks {
                send_chunk_response(outbound, id, &chunk.name, &chunk.data).await;
                chunk_count += 1;
            }
            continue;
        }

        let mut pull_stream = match sync_storage.stream_pull(space_id, requested.since).await {
            Ok(stream) => stream,
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
                cursor: pull_stream.meta.cursor,
                key_generation: pull_stream.meta.key_generation,
                rewrap_epoch: pull_stream.meta.rewrap_epoch,
            },
        )
        .await;
        chunk_count += 1;

        let mut stream_error = false;
        while let Some(entry) = pull_stream.next().await {
            match entry {
                Ok(entry) => {
                    if super::pull_send::send_pull_entry(outbound, id, &requested.id, &entry).await
                    {
                        chunk_count += 1;
                        entry_count += 1;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, space = %requested.id, "pull stream error");
                    stream_error = true;
                    break;
                }
            }
        }

        if stream_error {
            continue;
        }

        send_chunk_response(
            outbound,
            id,
            "pull.commit",
            &WsPullCommitData {
                space: requested.id.clone(),
                prev: requested.since,
                cursor: pull_stream.meta.cursor,
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
