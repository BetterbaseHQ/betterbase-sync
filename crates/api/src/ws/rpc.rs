use super::SyncStorage;
use axum::extract::ws::{Message, WebSocket};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    Change, PullParams, PushParams, PushRpcResult, SubscribeParams, SubscribeResult,
    WsMembershipData, WsMembershipEntry, WsPullBeginData, WsPullCommitData, WsPullFileData,
    WsPullRecordData, WsSpaceError, WsSubscribedSpace, ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT,
    ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS, ERR_CODE_KEY_GEN_STALE, ERR_CODE_METHOD_NOT_FOUND,
    ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE, RPC_CHUNK, RPC_RESPONSE,
};
use less_sync_storage::{PullEntryKind, StorageError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

pub(crate) async fn handle_request(
    socket: &mut WebSocket,
    sync_storage: Option<&dyn SyncStorage>,
    auth: &AuthContext,
    id: &str,
    method: &str,
    payload: &[u8],
) {
    match method {
        "subscribe" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    socket,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_subscribe_request(socket, sync_storage, auth, id, payload).await;
        }
        "push" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    socket,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_push_request(socket, sync_storage, id, payload).await;
        }
        "pull" => {
            let Some(sync_storage) = sync_storage else {
                send_error_response(
                    socket,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handle_pull_request(socket, sync_storage, auth, id, payload).await;
        }
        _ => {
            send_method_not_found_response(socket, id, method).await;
        }
    }
}

async fn handle_subscribe_request(
    socket: &mut WebSocket,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_request_params::<SubscribeParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                socket,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid subscribe params".to_owned(),
            )
            .await;
            return;
        }
    };

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

        match sync_storage
            .get_or_create_space(space_id, &auth.client_id)
            .await
        {
            Ok(space) => spaces.push(WsSubscribedSpace {
                id: requested.id.clone(),
                cursor: space.cursor,
                key_generation: space.key_generation,
                rewrap_epoch: space.rewrap_epoch,
                token: String::new(),
                peers: Vec::new(),
            }),
            Err(_) => errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_INTERNAL.to_owned(),
            }),
        }
    }

    send_result_response(socket, id, &SubscribeResult { spaces, errors }).await;
}

async fn handle_push_request(
    socket: &mut WebSocket,
    sync_storage: &dyn SyncStorage,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_request_params::<PushParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                socket,
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
                socket,
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

    let response = match sync_storage.push(space_id, &changes).await {
        Ok(result) if result.ok => PushRpcResult {
            ok: true,
            cursor: result.cursor,
            error: String::new(),
        },
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

    send_result_response(socket, id, &response).await;
}

async fn handle_pull_request(
    socket: &mut WebSocket,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_request_params::<PullParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                socket,
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

        let space_state = match sync_storage
            .get_or_create_space(space_id, &auth.client_id)
            .await
        {
            Ok(space_state) => space_state,
            Err(StorageError::SpaceNotFound) => continue,
            Err(_) => continue,
        };
        let pull_result = match sync_storage.pull(space_id, requested.since).await {
            Ok(pull_result) => pull_result,
            Err(StorageError::SpaceNotFound) => continue,
            Err(_) => continue,
        };

        let mut entry_count = 0_i32;
        send_chunk_response(
            socket,
            id,
            "pull.begin",
            &WsPullBeginData {
                space: requested.id.clone(),
                prev: requested.since,
                cursor: pull_result.cursor,
                key_generation: space_state.key_generation,
                rewrap_epoch: space_state.rewrap_epoch,
            },
        )
        .await;
        chunk_count += 1;

        for entry in &pull_result.entries {
            match entry.kind {
                PullEntryKind::Record => {
                    if let Some(record) = &entry.record {
                        send_chunk_response(
                            socket,
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
                            socket,
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
                            socket,
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
            socket,
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
        socket,
        id,
        &PullRpcResult {
            chunks: chunk_count as i32,
        },
    )
    .await;
}

fn decode_request_params<T>(payload: &[u8]) -> Result<T, serde_cbor::Error>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct RequestEnvelope<T> {
        #[serde(rename = "params")]
        params: T,
    }

    serde_cbor::from_slice::<RequestEnvelope<T>>(payload).map(|envelope| envelope.params)
}

#[derive(Debug, Serialize)]
struct RpcErrorFrame<'a> {
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id")]
    id: &'a str,
    #[serde(rename = "error")]
    error: RpcErrorPayload,
}

#[derive(Debug, Serialize)]
struct RpcErrorPayload {
    #[serde(rename = "code")]
    code: &'static str,
    #[serde(rename = "message")]
    message: String,
}

#[derive(Debug, Serialize)]
struct RpcResultFrame<'a, T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id")]
    id: &'a str,
    #[serde(rename = "result")]
    result: &'a T,
}

#[derive(Debug, Serialize)]
struct RpcChunkFrame<'a, T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    frame_type: i32,
    #[serde(rename = "id")]
    id: &'a str,
    #[serde(rename = "name")]
    name: &'a str,
    #[serde(rename = "data")]
    data: &'a T,
}

#[derive(Debug, Serialize)]
struct PullRpcResult {
    #[serde(rename = "_chunks")]
    chunks: i32,
}

async fn send_method_not_found_response(socket: &mut WebSocket, id: &str, method: &str) {
    send_error_response(
        socket,
        id,
        ERR_CODE_METHOD_NOT_FOUND,
        format!("unknown method: {method}"),
    )
    .await;
}

async fn send_result_response<T>(socket: &mut WebSocket, id: &str, result: &T)
where
    T: Serialize,
{
    let frame = RpcResultFrame {
        frame_type: RPC_RESPONSE,
        id,
        result,
    };
    let encoded = match serde_cbor::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let _ = socket.send(Message::Binary(encoded.into())).await;
}

async fn send_chunk_response<T>(socket: &mut WebSocket, id: &str, name: &str, data: &T)
where
    T: Serialize,
{
    let frame = RpcChunkFrame {
        frame_type: RPC_CHUNK,
        id,
        name,
        data,
    };
    let encoded = match serde_cbor::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let _ = socket.send(Message::Binary(encoded.into())).await;
}

async fn send_error_response(
    socket: &mut WebSocket,
    id: &str,
    code: &'static str,
    message: String,
) {
    let frame = RpcErrorFrame {
        frame_type: RPC_RESPONSE,
        id,
        error: RpcErrorPayload { code, message },
    };
    let encoded = match serde_cbor::to_vec(&frame) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let _ = socket.send(Message::Binary(encoded.into())).await;
}
