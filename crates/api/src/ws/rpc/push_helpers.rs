use betterbase_sync_core::protocol::{
    Change, PushParams, PushRpcResult, WsSyncRecord, ERR_CODE_BAD_REQUEST, ERR_CODE_CONFLICT,
    ERR_CODE_EPOCH_STALE, ERR_CODE_INTERNAL, ERR_CODE_NOT_FOUND, ERR_CODE_PAYLOAD_TOO_LARGE,
};
use betterbase_sync_storage::StorageError;

use crate::ws::realtime::RealtimeSession;

/// Map a storage-layer push failure to its wire result. Shared by the
/// client and federation push handlers so the classification cannot
/// drift between them: conflicts reconcile via pull, client protocol
/// violations reject permanently (the client quarantines instead of
/// retrying forever), and anything unclassified is traced before it
/// becomes `internal`.
pub(super) fn push_error_result(
    err: &StorageError,
    space_id: &str,
    changes_len: usize,
) -> PushRpcResult {
    match err {
        StorageError::VersionConflict | StorageError::RecordNotFound => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_CONFLICT.to_owned(),
        },
        StorageError::RecordIdCollision => {
            // A record id that already exists in another space cannot be a
            // conflict the client could resolve (pull finds nothing) — it
            // is a client protocol violation. Reject permanently so the
            // client quarantines instead of retrying forever.
            tracing::error!(
                "push rejected: record id collides with another space (space {space_id})"
            );
            PushRpcResult {
                ok: false,
                cursor: 0,
                error: ERR_CODE_BAD_REQUEST.to_owned(),
            }
        }
        StorageError::SpaceNotFound => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_NOT_FOUND.to_owned(),
        },
        StorageError::EpochStale => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_EPOCH_STALE.to_owned(),
        },
        StorageError::InvalidRecordId | StorageError::DuplicateRecordId => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_BAD_REQUEST.to_owned(),
        },
        StorageError::BlobTooLarge
        | StorageError::PushRecordLimitExceeded
        | StorageError::PushPayloadLimitExceeded => PushRpcResult {
            ok: false,
            cursor: 0,
            error: ERR_CODE_PAYLOAD_TOO_LARGE.to_owned(),
        },
        other => {
            tracing::error!(
                "push rejected with unclassified storage error: {other} (space {space_id}, {changes_len} changes)"
            );
            PushRpcResult {
                ok: false,
                cursor: 0,
                error: ERR_CODE_INTERNAL.to_owned(),
            }
        }
    }
}

/// Convert push params into storage Change structs.
pub(super) fn map_push_changes(params: &PushParams) -> Vec<Change> {
    params
        .changes
        .iter()
        .map(|change| Change {
            id: change.id.clone(),
            blob: change.blob.clone(),
            cursor: change.expected_cursor,
            wrapped_dek: change.wrapped_dek.clone(),
            deleted: change.blob.is_none(),
        })
        .collect()
}

/// Broadcast sync records to realtime subscribers after a successful push.
pub(super) async fn broadcast_push_sync(
    realtime: Option<&RealtimeSession>,
    params: &PushParams,
    cursor: Option<i64>,
) {
    let (Some(realtime), Some(cursor)) = (realtime, cursor) else {
        return;
    };

    let sync_records: Vec<WsSyncRecord> = params
        .changes
        .iter()
        .map(|change| WsSyncRecord {
            id: change.id.clone(),
            blob: change.blob.clone(),
            cursor,
            wrapped_dek: change.wrapped_dek.clone(),
            deleted: change.blob.is_none(),
        })
        .collect();

    realtime
        .broadcast_sync(&params.space, cursor, &sync_records)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire contract for push rejections: conflicts reconcile via
    /// pull, protocol violations reject permanently (client quarantine),
    /// unclassified errors surface as internal. A reshuffle that maps
    /// RecordIdCollision to conflict would rebuild the retry-forever
    /// wedge this taxonomy exists to prevent.
    #[test]
    fn push_error_result_maps_the_taxonomy() {
        let cases: [(StorageError, &str); 7] = [
            (StorageError::VersionConflict, ERR_CODE_CONFLICT),
            (StorageError::RecordNotFound, ERR_CODE_CONFLICT),
            (StorageError::RecordIdCollision, ERR_CODE_BAD_REQUEST),
            (StorageError::InvalidRecordId, ERR_CODE_BAD_REQUEST),
            (StorageError::SpaceNotFound, ERR_CODE_NOT_FOUND),
            (StorageError::EpochStale, ERR_CODE_EPOCH_STALE),
            (
                StorageError::PushPayloadLimitExceeded,
                ERR_CODE_PAYLOAD_TOO_LARGE,
            ),
        ];
        for (err, code) in cases {
            let result = push_error_result(&err, "space", 1);
            assert!(!result.ok, "{err:?}");
            assert_eq!(result.error, code, "{err:?}");
        }
        let internal = push_error_result(&StorageError::Unavailable, "space", 1);
        assert!(!internal.ok);
        assert_eq!(internal.error, ERR_CODE_INTERNAL);
    }
}
