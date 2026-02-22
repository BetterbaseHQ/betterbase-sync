use super::super::realtime::OutboundSender;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use betterbase_sync_auth::{AuthContext, AuthError, TokenValidator};
use betterbase_sync_core::protocol::{TokenRefreshParams, TokenRefreshResult, ERR_CODE_INVALID_PARAMS};

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    auth: &mut AuthContext,
    validator: &(dyn TokenValidator + Send + Sync),
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<TokenRefreshParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid token refresh params".to_owned(),
            )
            .await;
            return;
        }
    };

    let refreshed = match validator.validate_token(&params.token).await {
        Ok(context) => context,
        Err(error) => {
            send_result_response(
                outbound,
                id,
                &TokenRefreshResult {
                    ok: false,
                    error: auth_error_message(error),
                },
            )
            .await;
            return;
        }
    };

    if !has_scope(&refreshed.scope, "sync") {
        send_result_response(
            outbound,
            id,
            &TokenRefreshResult {
                ok: false,
                error: "sync scope required".to_owned(),
            },
        )
        .await;
        return;
    }

    if refreshed.user_id != auth.user_id || refreshed.client_id != auth.client_id {
        send_result_response(
            outbound,
            id,
            &TokenRefreshResult {
                ok: false,
                error: "token identity mismatch".to_owned(),
            },
        )
        .await;
        return;
    }

    *auth = refreshed;
    send_result_response(
        outbound,
        id,
        &TokenRefreshResult {
            ok: true,
            error: String::new(),
        },
    )
    .await;
}

fn has_scope(scope: &str, required: &str) -> bool {
    scope.split_whitespace().any(|token| token == required)
}

fn auth_error_message(error: AuthError) -> String {
    match error {
        AuthError::MissingToken => "missing auth token".to_owned(),
        AuthError::InvalidToken => "invalid auth token".to_owned(),
        AuthError::ExpiredToken => "expired auth token".to_owned(),
        AuthError::UntrustedIssuer => "untrusted auth issuer".to_owned(),
    }
}
