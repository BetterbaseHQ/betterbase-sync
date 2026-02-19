use std::time::SystemTime;

use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    FederationInvitationParams, InvitationCreateParams, InvitationCreateResult,
    InvitationDeleteParams, InvitationGetParams, InvitationListParams, InvitationListResult,
    ERR_CODE_BAD_REQUEST, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS,
    ERR_CODE_NOT_FOUND,
};
use less_sync_storage::{Invitation, StorageError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const DEFAULT_INVITATION_LIST_LIMIT: usize = 50;
const MAX_INVITATION_LIST_LIMIT: usize = 200;

#[derive(Debug, serde::Serialize)]
struct EmptyResult {}

pub(super) async fn handle_create_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    federation_forwarder: Option<&dyn crate::FederationForwarder>,
    federation_trusted_domains: &[String],
    auth: &AuthContext,
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
    if params.mailbox_id.is_empty() {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "invalid mailbox id".to_owned(),
        )
        .await;
        return;
    }
    if params.mailbox_id != mailbox_id_for_auth(auth) {
        send_error_response(outbound, id, ERR_CODE_FORBIDDEN, "forbidden".to_owned()).await;
        return;
    }

    if !params.server.is_empty() {
        let peer_domain = less_sync_auth::canonicalize_domain(&params.server);
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
    let created = match sync_storage.create_invitation(&invitation).await {
        Ok(created) => created,
        Err(_) => {
            send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
            return;
        }
    };

    match invitation_to_result(created) {
        Ok(result) => send_result_response(outbound, id, &result).await,
        Err(_) => send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await,
    }
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
