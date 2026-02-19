use std::time::SystemTime;

use less_sync_auth::Permission;
use less_sync_core::protocol::{
    SubscribeParams, SubscribeResult, WsSpaceError, WsSubscribedSpace, ERR_CODE_BAD_REQUEST,
    ERR_CODE_FORBIDDEN, ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS, ERR_CODE_NOT_FOUND,
    ERR_CODE_RATE_LIMITED,
};
use uuid::Uuid;

use super::decode_frame_params;
use super::federation_auth::{
    authorize_federation_ucan, AuthFailure, HomeServerPolicy, MissingRootPublicKey, SpaceState,
};
use super::frames::{send_error_response, send_result_response};
use crate::ws::realtime::{OutboundSender, RealtimeSession};
use crate::ws::SyncStorage;

pub(super) struct FederationSubscribeContext<'a> {
    pub peer_domain: &'a str,
    pub token_keys: Option<&'a crate::FederationTokenKeys>,
    pub quota_tracker: Option<&'a crate::FederationQuotaTracker>,
}

pub(super) async fn handle_subscribe_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    realtime: Option<&RealtimeSession>,
    id: &str,
    payload: &[u8],
    context: FederationSubscribeContext<'_>,
) {
    let FederationSubscribeContext {
        peer_domain,
        token_keys,
        quota_tracker,
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

    if params.spaces.is_empty() {
        send_result_response(
            outbound,
            id,
            &SubscribeResult {
                spaces: Vec::new(),
                errors: Vec::new(),
            },
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

        let (state, expiry_cap) = if !requested.ucan.is_empty() {
            match authorize_federation_ucan(
                sync_storage,
                space_id,
                &requested.ucan,
                Permission::Read,
                MissingRootPublicKey::NotFound,
                HomeServerPolicy::AllowAny,
            )
            .await
            {
                Ok(authorized) => (authorized.state, authorized.expiry_cap),
                Err(AuthFailure::Forbidden) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_FORBIDDEN.to_owned(),
                    });
                    continue;
                }
                Err(AuthFailure::NotFound) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_NOT_FOUND.to_owned(),
                    });
                    continue;
                }
                Err(AuthFailure::Internal) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_INTERNAL.to_owned(),
                    });
                    continue;
                }
            }
        } else if !requested.token.is_empty() {
            let Some(token_keys) = token_keys else {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_INTERNAL.to_owned(),
                });
                continue;
            };
            let claims = match token_keys.verify_fst(&requested.token, peer_domain) {
                Ok(claims) => claims,
                Err(_) => {
                    errors.push(WsSpaceError {
                        space: requested.id.clone(),
                        error: ERR_CODE_FORBIDDEN.to_owned(),
                    });
                    continue;
                }
            };
            if claims.space_id != space_id {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_FORBIDDEN.to_owned(),
                });
                continue;
            }
            let state = match sync_storage.get_space(space_id).await {
                Ok(space) => SpaceState {
                    cursor: space.cursor,
                    key_generation: space.key_generation,
                    rewrap_epoch: space.rewrap_epoch,
                },
                Err(_) => SpaceState::default(),
            };
            (state, Some(claims.expires_at))
        } else {
            errors.push(WsSpaceError {
                space: requested.id.clone(),
                error: ERR_CODE_BAD_REQUEST.to_owned(),
            });
            continue;
        };

        let token = match issue_fst(token_keys, space_id, peer_domain, expiry_cap) {
            Ok(token) => token,
            Err(()) => {
                errors.push(WsSpaceError {
                    space: requested.id.clone(),
                    error: ERR_CODE_INTERNAL.to_owned(),
                });
                continue;
            }
        };

        added_spaces.push(requested.id.clone());
        spaces.push(WsSubscribedSpace {
            id: requested.id.clone(),
            cursor: state.cursor,
            key_generation: state.key_generation,
            rewrap_epoch: state.rewrap_epoch,
            token,
            peers: Vec::new(),
        });
    }

    let new_space_count = if let Some(realtime) = realtime {
        let mut already_subscribed = 0_usize;
        for space_id in &added_spaces {
            if realtime.is_subscribed(space_id).await {
                already_subscribed = already_subscribed.saturating_add(1);
            }
        }
        added_spaces.len().saturating_sub(already_subscribed)
    } else {
        0
    };

    if new_space_count > 0 {
        if let Some(quota_tracker) = quota_tracker {
            if !quota_tracker
                .try_add_spaces(peer_domain, new_space_count)
                .await
            {
                for space in spaces.drain(..) {
                    errors.push(WsSpaceError {
                        space: space.id,
                        error: ERR_CODE_RATE_LIMITED.to_owned(),
                    });
                }
                added_spaces.clear();
            }
        }
    }

    if let Some(realtime) = realtime {
        let _ = realtime.add_spaces(&added_spaces).await;
    }

    send_result_response(outbound, id, &SubscribeResult { spaces, errors }).await;
}

fn issue_fst(
    token_keys: Option<&crate::FederationTokenKeys>,
    space_id: Uuid,
    peer_domain: &str,
    expiry_cap: Option<SystemTime>,
) -> Result<String, ()> {
    match token_keys {
        Some(keys) => keys
            .create_fst(space_id, peer_domain, expiry_cap)
            .map_err(|_| ()),
        None => Ok(String::new()),
    }
}
