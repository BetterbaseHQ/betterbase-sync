use betterbase_sync_core::protocol::{
    WsMembershipData, WsMembershipEntry, WsPullFileData, WsPullRecordData,
};
use betterbase_sync_storage::PullEntry;

use super::frames::send_chunk_response;
use crate::ws::realtime::OutboundSender;

/// Send a single pull entry as the appropriate chunk type.
/// Returns true if a chunk was sent, false if the entry was skipped due to a
/// missing field (which should never happen if the storage layer is correct).
pub(super) async fn send_pull_entry(
    outbound: &OutboundSender,
    id: &str,
    space_id: &str,
    entry: &PullEntry,
) -> bool {
    match entry.kind {
        betterbase_sync_storage::PullEntryKind::Record => {
            let Some(record) = &entry.record else {
                tracing::error!(
                    space = space_id,
                    cursor = entry.cursor,
                    "pull entry has kind=Record but record is None — storage bug"
                );
                return false;
            };
            send_chunk_response(
                outbound,
                id,
                "pull.record",
                &WsPullRecordData {
                    space: space_id.to_owned(),
                    id: record.id.clone(),
                    blob: record.blob.clone(),
                    cursor: record.cursor,
                    wrapped_dek: record.wrapped_dek.clone(),
                    deleted: record.is_deleted(),
                },
            )
            .await;
            true
        }
        betterbase_sync_storage::PullEntryKind::Membership => {
            let Some(member) = &entry.member else {
                tracing::error!(
                    space = space_id,
                    cursor = entry.cursor,
                    "pull entry has kind=Membership but member is None — storage bug"
                );
                return false;
            };
            send_chunk_response(
                outbound,
                id,
                "pull.membership",
                &WsMembershipData {
                    space: space_id.to_owned(),
                    cursor: member.cursor,
                    entries: vec![WsMembershipEntry {
                        chain_seq: member.chain_seq,
                        prev_hash: if member.prev_hash.is_empty() {
                            None
                        } else {
                            Some(member.prev_hash.clone())
                        },
                        entry_hash: member.entry_hash.clone(),
                        payload: member.payload.clone(),
                    }],
                },
            )
            .await;
            true
        }
        betterbase_sync_storage::PullEntryKind::File => {
            let Some(file) = &entry.file else {
                tracing::error!(
                    space = space_id,
                    cursor = entry.cursor,
                    "pull entry has kind=File but file is None — storage bug"
                );
                return false;
            };
            send_chunk_response(
                outbound,
                id,
                "pull.file",
                &WsPullFileData {
                    space: space_id.to_owned(),
                    id: file.id.to_string(),
                    record_id: file.record_id.to_string(),
                    size: file.size,
                    wrapped_dek: Some(file.wrapped_dek.clone()),
                    cursor: file.cursor,
                    deleted: file.deleted,
                },
            )
            .await;
            true
        }
    }
}
