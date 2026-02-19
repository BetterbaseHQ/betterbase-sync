use super::realtime::{OutboundSender, RealtimeSession};
use super::SyncStorage;
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{ERR_CODE_INTERNAL, RPC_RESPONSE};
use serde::de::DeserializeOwned;

mod frames;
mod handlers;

pub(crate) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: Option<&dyn SyncStorage>,
    realtime: Option<&RealtimeSession>,
    auth: &AuthContext,
    id: &str,
    method: &str,
    payload: &[u8],
) {
    match method {
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
            handlers::handle_subscribe_request(outbound, sync_storage, realtime, auth, id, payload)
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
            handlers::handle_push_request(outbound, sync_storage, realtime, id, payload).await;
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
    realtime: Option<&RealtimeSession>,
    method: &str,
    payload: &[u8],
) {
    if method != "unsubscribe" {
        return;
    }

    handlers::handle_unsubscribe_notification(realtime, payload).await;
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
