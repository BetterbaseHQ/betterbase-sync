use super::super::authz::{self, SpaceAuthzError};
use super::super::realtime::{OutboundSender, RealtimeSession};
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use less_sync_auth::AuthContext;
use less_sync_core::protocol::{
    MembershipRevokeParams, ERR_CODE_BAD_REQUEST, ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS,
};
use uuid::Uuid;

#[derive(Debug, serde::Serialize)]
struct EmptyResult {}

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<MembershipRevokeParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid membership revoke params".to_owned(),
            )
            .await;
            return;
        }
    };
    if params.ucan_cid.is_empty() {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "invalid ucan cid".to_owned(),
        )
        .await;
        return;
    }
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

    if sync_storage
        .revoke_ucan(space_id, &params.ucan_cid)
        .await
        .is_err()
    {
        send_error_response(outbound, id, ERR_CODE_INTERNAL, "internal".to_owned()).await;
        return;
    }

    if let Some(realtime) = realtime {
        realtime
            .broadcast_revocation(&params.space, "ucan_revoked")
            .await;
    }

    send_result_response(outbound, id, &EmptyResult {}).await;
}
