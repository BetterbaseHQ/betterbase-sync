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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::realtime::OutboundFrame;
    use betterbase_sync_core::protocol::{WsMembershipData, WsPullFileData, RPC_CHUNK};
    use betterbase_sync_storage::{FileEntry, MembersLogEntry, PullEntryKind};
    use uuid::Uuid;

    #[derive(serde::Deserialize)]
    struct Chunk<T> {
        #[serde(rename = "type")]
        frame_type: i32,
        id: String,
        name: String,
        data: T,
    }

    fn decode<T: for<'de> serde::Deserialize<'de>>(frame: OutboundFrame) -> Chunk<T> {
        let OutboundFrame::Binary(bytes) = frame else {
            panic!("binary frame");
        };
        let chunk: Chunk<T> = minicbor_serde::from_slice(&bytes).expect("decode");
        assert_eq!(chunk.frame_type, RPC_CHUNK);
        assert_eq!(chunk.id, "request");
        chunk
    }

    #[tokio::test]
    async fn incomplete_pull_entries_emit_no_chunks() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for kind in [
            PullEntryKind::Record,
            PullEntryKind::Membership,
            PullEntryKind::File,
        ] {
            let entry = PullEntry {
                kind,
                cursor: 9,
                record: None,
                member: None,
                file: None,
            };
            assert!(!send_pull_entry(&tx, "request", "space", &entry).await);
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn membership_chunks_preserve_chain_and_omit_empty_previous_hash() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for previous in [Vec::new(), vec![0, 128, 255]] {
            let member = MembersLogEntry {
                space_id: Uuid::nil(),
                chain_seq: 3,
                cursor: 9,
                prev_hash: previous.clone(),
                entry_hash: vec![255; 32],
                payload: vec![0, 255],
            };
            let entry = PullEntry {
                kind: PullEntryKind::Membership,
                cursor: 9,
                record: None,
                member: Some(member),
                file: None,
            };
            assert!(send_pull_entry(&tx, "request", "space", &entry).await);
            let chunk: Chunk<WsMembershipData> = decode(rx.recv().await.expect("chunk"));
            assert_eq!(chunk.name, "pull.membership");
            assert_eq!(chunk.data.space, "space");
            assert_eq!(chunk.data.cursor, 9);
            assert_eq!(chunk.data.entries.len(), 1);
            assert_eq!(chunk.data.entries[0].chain_seq, 3);
            assert_eq!(
                chunk.data.entries[0].prev_hash,
                if previous.is_empty() {
                    None
                } else {
                    Some(previous)
                }
            );
            assert_eq!(chunk.data.entries[0].entry_hash, vec![255; 32]);
            assert_eq!(chunk.data.entries[0].payload, vec![0, 255]);
        }
    }

    #[tokio::test]
    async fn file_tombstone_chunk_preserves_identity_cursor_and_wrapper() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let entry = PullEntry {
            kind: PullEntryKind::File,
            cursor: 9,
            record: None,
            member: None,
            file: Some(FileEntry {
                id,
                record_id,
                size: 0,
                deleted: true,
                wrapped_dek: vec![255; 44],
                cursor: 9,
            }),
        };
        assert!(send_pull_entry(&tx, "request", "space", &entry).await);
        let chunk: Chunk<WsPullFileData> = decode(rx.recv().await.expect("chunk"));
        assert_eq!(chunk.name, "pull.file");
        assert_eq!(chunk.data.space, "space");
        assert_eq!(chunk.data.id, id.to_string());
        assert_eq!(chunk.data.record_id, record_id.to_string());
        assert_eq!(chunk.data.cursor, 9);
        assert_eq!(chunk.data.size, 0);
        assert!(chunk.data.deleted);
        assert_eq!(chunk.data.wrapped_dek, Some(vec![255; 44]));
    }
}
