use std::time::{Duration, SystemTime};

use super::super::realtime::{OutboundSender, RealtimeSession};
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::{canonicalize_domain, AuthContext};
use less_sync_core::protocol::{
    FederationInvitationParams, FederationInvitationResult, InvitationCreateParams,
    InvitationCreateResult, InvitationDeleteParams, InvitationGetParams, InvitationListParams,
    InvitationListResult, ERR_CODE_BAD_REQUEST, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS,
    ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE, ERR_CODE_RATE_LIMITED,
};
use less_sync_storage::{Invitation, StorageError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const DEFAULT_INVITATION_LIST_LIMIT: usize = 50;
const MAX_INVITATION_LIST_LIMIT: usize = 200;
const MAX_INVITATION_PAYLOAD: usize = 128 * 1024;
const RATE_LIMIT_MAX: i64 = 10;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Debug, serde::Serialize)]
struct EmptyResult {}

pub(super) async fn handle_create_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    auth: &AuthContext,
    identity_hash_key: Option<&[u8]>,
    federation_forwarder: Option<&dyn crate::FederationForwarder>,
    federation_trusted_domains: &[String],
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<InvitationCreateParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid invitation create params".to_owned(),
            )
            .await;
            return;
        }
    };
    // Rate limiting (before validation to prevent free probing).
    let actor_hash = if let Some(key) = identity_hash_key {
        let hash = less_sync_storage::rate_limit_hash(key, &auth.issuer, &auth.user_id);
        let since = SystemTime::now() - RATE_LIMIT_WINDOW;
        match sync_storage
            .count_recent_actions("invitation", &hash, since)
            .await
        {
            Ok(count) if count >= RATE_LIMIT_MAX => {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_RATE_LIMITED,
                    "rate limit exceeded: max 10 invitations per hour".to_owned(),
                )
                .await;
                return;
            }
            Ok(_) => {}
            Err(_) => {
                tracing::error!("failed to count recent invitations");
                send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal error".to_owned())
                    .await;
                return;
            }
        }
        Some(hash)
    } else {
        None
    };

    if let Some((code, message)) = validate_invitation_params(&params.mailbox_id, &params.payload) {
        send_error_response(outbound, id, code, message).await;
        return;
    }

    if !params.server.is_empty() {
        let peer_domain = canonicalize_domain(&params.server);
        let Some(federation_forwarder) = federation_forwarder else {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "federation is not enabled on this server".to_owned(),
            )
            .await;
            return;
        };

        let trusted = federation_trusted_domains
            .iter()
            .any(|domain| domain == &peer_domain);
        if !trusted {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "target server is not a trusted federation peer".to_owned(),
            )
            .await;
            return;
        }

        let peer_ws_url = crate::federation_client::peer_ws_url(&params.server);
        let forward = FederationInvitationParams {
            mailbox_id: params.mailbox_id.clone(),
            payload: params.payload.clone(),
        };
        if federation_forwarder
            .forward_invitation(&peer_domain, &peer_ws_url, &forward)
            .await
            .is_err()
        {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INTERNAL,
                "failed to deliver invitation to remote server".to_owned(),
            )
            .await;
            return;
        }

        // Record rate-limit action after successful forward.
        if let Some(hash) = &actor_hash {
            if let Err(err) = sync_storage.record_action("invitation", hash).await {
                tracing::error!(%err, "failed to record rate limit action");
            }
        }

        send_result_response(
            outbound,
            id,
            &InvitationCreateResult {
                id: "forwarded".to_owned(),
                payload: params.payload,
                created_at: String::new(),
                expires_at: String::new(),
            },
        )
        .await;
        return;
    }

    let invitation = Invitation {
        id: Uuid::nil(),
        mailbox_id: params.mailbox_id,
        payload: params.payload.into_bytes(),
        created_at: SystemTime::now(),
        expires_at: SystemTime::now(),
    };
    let target_mailbox_id = invitation.mailbox_id.clone();
    let created = match sync_storage.create_invitation(&invitation).await {
        Ok(created) => created,
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    };

    // Record rate-limit action after successful creation.
    if let Some(hash) = &actor_hash {
        if let Err(err) = sync_storage.record_action("invitation", hash).await {
            tracing::error!(%err, "failed to record rate limit action");
        }
    }

    if let Some(realtime) = realtime {
        realtime.broadcast_invitation(&target_mailbox_id);
    }

    match invitation_to_result(created) {
        Ok(result) => send_result_response(outbound, id, &result).await,
        Err(_) => send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await,
    }
}

pub(super) async fn handle_federation_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    id: &str,
    payload: &[u8],
    peer_domain: &str,
    quota_tracker: Option<&crate::FederationQuotaTracker>,
) {
    let params = match decode_frame_params::<FederationInvitationParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid params".to_owned(),
            )
            .await;
            return;
        }
    };

    if let Some((code, message)) = validate_invitation_params(&params.mailbox_id, &params.payload) {
        send_error_response(outbound, id, code, message).await;
        return;
    }

    if let Some(quota_tracker) = quota_tracker {
        if !quota_tracker.check_and_record_invitation(peer_domain).await {
            send_error_response(
                outbound,
                id,
                ERR_CODE_RATE_LIMITED,
                "invitation quota exceeded".to_owned(),
            )
            .await;
            return;
        }
    }

    let target_mailbox_id = params.mailbox_id.clone();
    let invitation = Invitation {
        id: Uuid::nil(),
        mailbox_id: params.mailbox_id,
        payload: params.payload.into_bytes(),
        created_at: SystemTime::now(),
        expires_at: SystemTime::now(),
    };
    if sync_storage.create_invitation(&invitation).await.is_err() {
        send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal error".to_owned()).await;
        return;
    }

    if let Some(realtime) = realtime {
        realtime.broadcast_invitation(&target_mailbox_id);
    }

    send_result_response(outbound, id, &FederationInvitationResult { ok: true }).await;
}

pub(super) async fn handle_list_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<InvitationListParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid invitation list params".to_owned(),
            )
            .await;
            return;
        }
    };

    let after = if params.after.is_empty() {
        None
    } else {
        match Uuid::parse_str(&params.after) {
            Ok(after) => Some(after),
            Err(_) => {
                send_error_response(
                    outbound,
                    id,
                    ERR_CODE_BAD_REQUEST,
                    "invalid invitation cursor".to_owned(),
                )
                .await;
                return;
            }
        }
    };
    let limit = if params.limit <= 0 {
        DEFAULT_INVITATION_LIST_LIMIT
    } else {
        usize::try_from(params.limit)
            .unwrap_or(DEFAULT_INVITATION_LIST_LIMIT)
            .min(MAX_INVITATION_LIST_LIMIT)
    };

    let invitations = match sync_storage
        .list_invitations(mailbox_id_for_auth(auth), limit, after)
        .await
    {
        Ok(invitations) => invitations,
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    };

    let mut mapped = Vec::with_capacity(invitations.len());
    for invitation in invitations {
        let result = match invitation_to_result(invitation) {
            Ok(result) => result,
            Err(_) => {
                send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
                return;
            }
        };
        mapped.push(result);
    }

    send_result_response(
        outbound,
        id,
        &InvitationListResult {
            invitations: mapped,
        },
    )
    .await;
}

pub(super) async fn handle_get_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<InvitationGetParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid invitation get params".to_owned(),
            )
            .await;
            return;
        }
    };
    let invitation_id = match Uuid::parse_str(&params.id) {
        Ok(invitation_id) => invitation_id,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid invitation id".to_owned(),
            )
            .await;
            return;
        }
    };

    let invitation = match sync_storage
        .get_invitation(invitation_id, mailbox_id_for_auth(auth))
        .await
    {
        Ok(invitation) => invitation,
        Err(StorageError::InvitationNotFound) => {
            send_error_response(outbound, id, ERR_CODE_NOT_FOUND, "not found".to_owned()).await;
            return;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    };

    match invitation_to_result(invitation) {
        Ok(result) => send_result_response(outbound, id, &result).await,
        Err(_) => send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await,
    }
}

pub(super) async fn handle_delete_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<InvitationDeleteParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid invitation delete params".to_owned(),
            )
            .await;
            return;
        }
    };
    let invitation_id = match Uuid::parse_str(&params.id) {
        Ok(invitation_id) => invitation_id,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_BAD_REQUEST,
                "invalid invitation id".to_owned(),
            )
            .await;
            return;
        }
    };

    match sync_storage
        .delete_invitation(invitation_id, mailbox_id_for_auth(auth))
        .await
    {
        Ok(()) => send_result_response(outbound, id, &EmptyResult {}).await,
        Err(StorageError::InvitationNotFound) => {
            send_error_response(outbound, id, ERR_CODE_NOT_FOUND, "not found".to_owned()).await;
        }
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        }
    }
}

fn mailbox_id_for_auth(auth: &AuthContext) -> &str {
    if auth.mailbox_id.is_empty() {
        &auth.client_id
    } else {
        &auth.mailbox_id
    }
}

fn validate_invitation_params(mailbox_id: &str, payload: &str) -> Option<(&'static str, String)> {
    if mailbox_id.is_empty() {
        return Some((ERR_CODE_BAD_REQUEST, "missing mailbox_id".to_owned()));
    }
    if mailbox_id.len() != 64 || !is_hex_lower(mailbox_id) {
        return Some((
            ERR_CODE_BAD_REQUEST,
            "mailbox_id must be 64-char hex string".to_owned(),
        ));
    }
    if payload.is_empty() {
        return Some((ERR_CODE_BAD_REQUEST, "missing payload".to_owned()));
    }
    if payload.len() > MAX_INVITATION_PAYLOAD {
        return Some((ERR_CODE_PAYLOAD_TOO_LARGE, "payload too large".to_owned()));
    }
    None
}

fn is_hex_lower(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invitation_to_result(
    invitation: Invitation,
) -> Result<InvitationCreateResult, time::error::Format> {
    Ok(InvitationCreateResult {
        id: invitation.id.to_string(),
        payload: String::from_utf8_lossy(&invitation.payload).to_string(),
        created_at: format_system_time(invitation.created_at)?,
        expires_at: format_system_time(invitation.expires_at)?,
    })
}

fn format_system_time(value: SystemTime) -> Result<String, time::error::Format> {
    OffsetDateTime::from(value).format(&Rfc3339)
}
