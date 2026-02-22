use betterbase_sync_core::protocol::{Change, PushParams, WsSyncRecord};

use crate::ws::realtime::RealtimeSession;

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
