use super::realtime::{OutboundSender, RealtimeSession};
use super::PresenceRegistry;
use super::SyncStorage;
use less_sync_auth::{AuthContext, TokenValidator};
use less_sync_core::protocol::{ERR_CODE_INTERNAL, RPC_RESPONSE};
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
mod space_create;
mod token_refresh;

pub(crate) struct RequestContext<'a> {
    pub sync_storage: Option<&'a dyn SyncStorage>,
    pub realtime: Option<&'a RealtimeSession>,
    pub presence_registry: Option<&'a PresenceRegistry>,
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
            membership_append::handle_request(outbound, sync_storage, auth, id, payload).await;
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
            membership_revoke::handle_request(outbound, sync_storage, auth, id, payload).await;
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
            invitation::handle_create_request(outbound, sync_storage, auth, id, payload).await;
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
                realtime,
                presence_registry,
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
            handlers::handle_push_request(outbound, sync_storage, realtime, auth, id, payload)
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
            handlers::handle_pull_request(outbound, sync_storage, auth, id, payload).await;
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
        } => {
            if method == "unsubscribe" {
                let removed =
                    handlers::handle_unsubscribe_notification(realtime, presence_registry, payload)
                        .await;
                if removed > 0 {
                    if let Some(quota_tracker) = quota_tracker {
                        quota_tracker.remove_spaces(peer_domain, removed).await;
                    }
                }
            }
        }
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
            handlers::handle_event_send_notification(realtime, payload).await;
        }
        _ => {}
    }
}

pub(super) fn decode_frame_params<T>(payload: &[u8]) -> Result<T, serde_cbor::Error>
where
    T: DeserializeOwned,
{
    #[derive(serde::Deserialize)]
    struct FrameEnvelope<T> {
        #[serde(rename = "params")]
        params: T,
    }

    serde_cbor::from_slice::<FrameEnvelope<T>>(payload).map(|envelope| envelope.params)
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
