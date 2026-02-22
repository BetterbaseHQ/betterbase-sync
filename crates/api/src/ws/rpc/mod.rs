use super::realtime::{OutboundSender, RealtimeSession};
use super::PresenceRegistry;
use super::SyncStorage;
use betterbase_sync_auth::{AuthContext, TokenValidator};
use betterbase_sync_core::protocol::{
    WsFileData, WsMembershipData, WsRevokedData, WsSyncData, ERR_CODE_INTERNAL, RPC_RESPONSE,
};
use serde::de::DeserializeOwned;

mod deks;
mod epoch;
mod federation;
mod federation_auth;
mod federation_subscribe;
mod federation_sync;
mod frames;
mod handlers;
mod invitation;
mod membership_append;
mod membership_list;
mod membership_revoke;
mod pull_send;
mod push_helpers;
mod space_create;
mod token_refresh;

pub(crate) struct RequestContext<'a> {
    pub sync_storage: Option<&'a dyn SyncStorage>,
    pub realtime: Option<&'a RealtimeSession>,
    pub presence_registry: Option<&'a PresenceRegistry>,
    pub federation_forwarder: Option<&'a dyn crate::FederationForwarder>,
    pub federation_trusted_domains: &'a [String],
    pub identity_hash_key: Option<&'a [u8]>,
}

pub(crate) enum RequestMode<'a> {
    Client,
    Federation {
        peer_domain: &'a str,
        token_keys: Option<&'a crate::FederationTokenKeys>,
        quota_tracker: Option<&'a crate::FederationQuotaTracker>,
    },
}

pub(crate) struct RequestFrame<'a> {
    pub id: &'a str,
    pub method: &'a str,
    pub payload: &'a [u8],
}

pub(crate) async fn handle_request(
    outbound: &OutboundSender,
    context: RequestContext<'_>,
    mode: RequestMode<'_>,
    auth: &mut AuthContext,
    validator: &(dyn TokenValidator + Send + Sync),
    frame: RequestFrame<'_>,
) {
    match mode {
        RequestMode::Client => {
            handle_client_request(outbound, context, auth, validator, frame).await;
        }
        RequestMode::Federation {
            peer_domain,
            token_keys,
            quota_tracker,
        } => {
            federation::handle_request(
                outbound,
                context,
                frame,
                peer_domain,
                token_keys,
                quota_tracker,
            )
            .await;
        }
    }
}

async fn handle_client_request(
    outbound: &OutboundSender,
    context: RequestContext<'_>,
    auth: &mut AuthContext,
    validator: &(dyn TokenValidator + Send + Sync),
    frame: RequestFrame<'_>,
) {
    let RequestFrame {
        id,
        method,
        payload,
    } = frame;
    let RequestContext {
        sync_storage,
        realtime,
        presence_registry,
        federation_forwarder,
        federation_trusted_domains,
        identity_hash_key,
    } = context;

    match method {
        "token.refresh" => {
            token_refresh::handle_request(outbound, auth, validator, id, payload).await;
        }
        "space.create" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            space_create::handle_request(outbound, sync_storage, auth, id, payload).await;
        }
        "membership.append" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            membership_append::handle_request(
                outbound,
                sync_storage,
                realtime,
                auth,
                identity_hash_key,
                id,
                payload,
            )
            .await;
        }
        "membership.list" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            membership_list::handle_request(outbound, sync_storage, auth, id, payload).await;
        }
        "membership.revoke" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            membership_revoke::handle_request(outbound, sync_storage, realtime, auth, id, payload)
                .await;
        }
        "invitation.create" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            invitation::handle_create_request(
                outbound,
                sync_storage,
                realtime,
                auth,
                identity_hash_key,
                federation_forwarder,
                federation_trusted_domains,
                id,
                payload,
            )
            .await;
        }
        "invitation.list" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            invitation::handle_list_request(outbound, sync_storage, auth, id, payload).await;
        }
        "invitation.get" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            invitation::handle_get_request(outbound, sync_storage, auth, id, payload).await;
        }
        "invitation.delete" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            invitation::handle_delete_request(outbound, sync_storage, auth, id, payload).await;
        }
        "epoch.begin" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            epoch::handle_begin_request(outbound, sync_storage, auth, id, payload).await;
        }
        "epoch.complete" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            epoch::handle_complete_request(outbound, sync_storage, auth, id, payload).await;
        }
        "deks.get" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            deks::handle_get_request(outbound, sync_storage, auth, id, payload).await;
        }
        "deks.rewrap" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            deks::handle_rewrap_request(outbound, sync_storage, auth, id, payload).await;
        }
        "file.deks.get" | "deks.getFiles" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            deks::handle_file_get_request(outbound, sync_storage, auth, id, payload).await;
        }
        "file.deks.rewrap" | "deks.rewrapFiles" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            deks::handle_file_rewrap_request(outbound, sync_storage, auth, id, payload).await;
        }
        "subscribe" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handlers::handle_subscribe_request(
                outbound,
                sync_storage,
                handlers::SubscribeContext {
                    realtime,
                    presence_registry,
                    federation_forwarder,
                },
                auth,
                id,
                payload,
            )
            .await;
        }
        "push" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handlers::handle_push_request(
                outbound,
                sync_storage,
                realtime,
                federation_forwarder,
                auth,
                id,
                payload,
            )
            .await;
        }
        "pull" => {
            let Some(sync_storage) = sync_storage else {
                frames::send_error_response(
                    outbound,
                    id,
                    ERR_CODE_INTERNAL,
                    "sync storage is not configured".to_owned(),
                )
                .await;
                return;
            };
            handlers::handle_pull_request(
                outbound,
                sync_storage,
                federation_forwarder,
                auth,
                id,
                payload,
            )
            .await;
        }
        _ => {
            frames::send_method_not_found_response(outbound, id, method).await;
        }
    }
}

pub(crate) async fn handle_notification(
    mode: RequestMode<'_>,
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    method: &str,
    payload: &[u8],
) {
    match mode {
        RequestMode::Client => {
            handle_client_notification(realtime, presence_registry, method, payload).await;
        }
        RequestMode::Federation {
            peer_domain,
            quota_tracker,
            ..
        } => match method {
            "unsubscribe" => {
                let removed =
                    handlers::handle_unsubscribe_notification(realtime, presence_registry, payload)
                        .await;
                if removed > 0 {
                    if let Some(quota_tracker) = quota_tracker {
                        quota_tracker.remove_spaces(peer_domain, removed).await;
                    }
                }
            }
            "sync" | "membership" | "file" | "revoked" => {
                handle_federation_rebroadcast(realtime, method, payload).await;
            }
            _ => {}
        },
    }
}

async fn handle_client_notification(
    realtime: Option<&RealtimeSession>,
    presence_registry: Option<&PresenceRegistry>,
    method: &str,
    payload: &[u8],
) {
    match method {
        "unsubscribe" => {
            let _ = handlers::handle_unsubscribe_notification(realtime, presence_registry, payload)
                .await;
        }
        "presence.set" => {
            handlers::handle_presence_set_notification(realtime, presence_registry, payload).await;
        }
        "presence.clear" => {
            handlers::handle_presence_clear_notification(realtime, presence_registry, payload)
                .await;
        }
        "event.send" => {
            handlers::handle_event_send_notification(realtime, presence_registry, payload).await;
        }
        _ => {}
    }
}

/// Re-broadcast notifications received from a federation peer to local space subscribers.
async fn handle_federation_rebroadcast(
    realtime: Option<&RealtimeSession>,
    method: &str,
    payload: &[u8],
) {
    let Some(realtime) = realtime else {
        return;
    };

    match method {
        "sync" => {
            let Ok(params) = decode_frame_params::<WsSyncData>(payload) else {
                return;
            };
            if params.records.is_empty() {
                return;
            }
            // Broadcast the full struct to preserve key_generation and rewrap_epoch.
            realtime
                .broadcast_notification(&params.space, "sync", &params)
                .await;
        }
        "membership" => {
            let Ok(params) = decode_frame_params::<WsMembershipData>(payload) else {
                return;
            };
            realtime.broadcast_membership(&params.space, &params).await;
        }
        "file" => {
            let Ok(params) = decode_frame_params::<WsFileData>(payload) else {
                return;
            };
            realtime.broadcast_file(&params.space, &params).await;
        }
        "revoked" => {
            let Ok(params) = decode_frame_params::<WsRevokedData>(payload) else {
                return;
            };
            realtime
                .broadcast_revocation(&params.space, &params.reason)
                .await;
        }
        _ => {}
    }
}

pub(super) fn decode_frame_params<T>(
    payload: &[u8],
) -> Result<T, minicbor_serde::error::DecodeError>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct FrameEnvelope<T> {
        #[serde(rename = "params")]
        params: T,
    }

    minicbor_serde::from_slice::<FrameEnvelope<T>>(payload).map(|envelope| envelope.params)
}

#[derive(Debug, serde::Serialize)]
pub(super) struct RpcResultFrame<'a, T>
where
    T: serde::Serialize,
{
    #[serde(rename = "type")]
    pub frame_type: i32,
    #[serde(rename = "id")]
    pub id: &'a str,
    #[serde(rename = "result")]
    pub result: &'a T,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct RpcChunkFrame<'a, T>
where
    T: serde::Serialize,
{
    #[serde(rename = "type")]
    pub frame_type: i32,
    #[serde(rename = "id")]
    pub id: &'a str,
    #[serde(rename = "name")]
    pub name: &'a str,
    #[serde(rename = "data")]
    pub data: &'a T,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct RpcErrorFrame<'a> {
    #[serde(rename = "type")]
    pub frame_type: i32,
    #[serde(rename = "id")]
    pub id: &'a str,
    #[serde(rename = "error")]
    pub error: RpcErrorPayload,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct RpcErrorPayload {
    #[serde(rename = "code")]
    pub code: &'static str,
    #[serde(rename = "message")]
    pub message: String,
}

pub(super) const RESPONSE_FRAME_TYPE: i32 = RPC_RESPONSE;
