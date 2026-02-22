use super::super::realtime::OutboundSender;
use super::super::SyncStorage;
use super::decode_frame_params;
use super::frames::{send_error_response, send_result_response};
use betterbase_sync_auth::AuthContext;
use betterbase_sync_core::protocol::{
    SpaceCreateParams, SpaceCreateResult, ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT,
    ERR_CODE_INTERNAL, ERR_CODE_INVALID_PARAMS,
};
use betterbase_sync_storage::StorageError;
use uuid::Uuid;

/// A compressed SEC1 public key is exactly 33 bytes with a 0x02 or 0x03 prefix.
fn is_valid_compressed_public_key(key: &[u8]) -> bool {
    key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03)
}

pub(super) async fn handle_request(
    outbound: &OutboundSender,
    sync_storage: &dyn SyncStorage,
    auth: &AuthContext,
    id: &str,
    payload: &[u8],
) {
    let params = match decode_frame_params::<SpaceCreateParams>(payload) {
        Ok(params) => params,
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INVALID_PARAMS,
                "invalid space create params".to_owned(),
            )
            .await;
            return;
        }
    };

    let space_id = match Uuid::parse_str(&params.id) {
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
    if !is_valid_compressed_public_key(&params.root_public_key) {
        send_error_response(
            outbound,
            id,
            ERR_CODE_BAD_REQUEST,
            "invalid root public key".to_owned(),
        )
        .await;
        return;
    }

    match sync_storage
        .create_space(
            space_id,
            &auth.client_id,
            Some(params.root_public_key.as_slice()),
        )
        .await
    {
        Ok(space) => {
            send_result_response(
                outbound,
                id,
                &SpaceCreateResult {
                    id: space.id,
                    key_generation: space.key_generation,
                },
            )
            .await;
        }
        Err(StorageError::SpaceExists) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_CONFLICT,
                "space already exists".to_owned(),
            )
            .await;
        }
        Err(_) => {
            send_error_response(
                outbound,
                id,
                ERR_CODE_INTERNAL,
                "failed to create space".to_owned(),
            )
            .await;
        }
    }
}
