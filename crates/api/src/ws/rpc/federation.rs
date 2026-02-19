use less_sync_core::protocol::ERR_CODE_INTERNAL;

use super::frames::{send_error_response, send_method_not_found_response};
use super::{RequestContext, RequestFrame};
use crate::ws::realtime::OutboundSender;

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    context: RequestContext<'_>,
    frame: RequestFrame<'_>,
    peer_domain: &str,
    token_keys: Option<&crate::FederationTokenKeys>,
    quota_tracker: Option<&crate::FederationQuotaTracker>,
) {
    let RequestContext {
        sync_storage,
        realtime,
        ..
    } = context;
    let RequestFrame {
        id,
        method,
        payload,
    } = frame;

    match method {
        "subscribe" => {
            let Some(sync_storage) = sync_storage else {
                send_missing_storage_error(outbound, id).await;
                return;
            };
            super::federation_subscribe::handle_subscribe_request(
                outbound,
                sync_storage,
                realtime,
                id,
                payload,
                super::federation_subscribe::FederationSubscribeContext {
                    peer_domain,
                    token_keys,
                    quota_tracker,
                },
            )
            .await;
        }
        "push" => {
            let Some(sync_storage) = sync_storage else {
                send_missing_storage_error(outbound, id).await;
                return;
            };
            super::federation_sync::handle_push_request(
                outbound,
                sync_storage,
                realtime,
                id,
                payload,
                peer_domain,
                quota_tracker,
            )
            .await;
        }
        "pull" => {
            let Some(sync_storage) = sync_storage else {
                send_missing_storage_error(outbound, id).await;
                return;
            };
            super::federation_sync::handle_pull_request(outbound, sync_storage, id, payload).await;
        }
        _ => {
            send_method_not_found_response(outbound, id, method).await;
        }
    }
}

async fn send_missing_storage_error(outbound: &OutboundSender, id: &str) {
    send_error_response(
        outbound,
        id,
        ERR_CODE_INTERNAL,
        "sync storage is not configured".to_owned(),
    )
    .await;
}
