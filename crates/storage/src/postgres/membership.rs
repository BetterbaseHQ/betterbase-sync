use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{AppendLogResult, MembersLogEntry, MembershipStorage, StorageError};

#[async_trait]
impl MembershipStorage for PostgresStorage {
    async fn append_member(
        &self,
        space_id: Uuid,
        expected_version: i32,
        entry: &MembersLogEntry,
    ) -> Result<AppendLogResult, StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let current_version: i32 =
            sqlx::query_scalar("SELECT metadata_version FROM spaces WHERE id = $1 FOR UPDATE")
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| match error {
                    sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                    _ => StorageError::Database(error.to_string()),
                })?;
        if current_version != expected_version {
            return Err(StorageError::VersionConflict);
        }

        let mut last_seq = 0;
        match sqlx::query_as::<_, LastMemberRow>(
            "SELECT chain_seq, entry_hash FROM members WHERE space_id = $1 ORDER BY chain_seq DESC LIMIT 1",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        {
            Ok(last) => {
                last_seq = last.chain_seq;
                if entry.prev_hash.is_empty() || entry.prev_hash != last.entry_hash {
                    return Err(StorageError::HashChainBroken);
                }
            }
            Err(sqlx::Error::RowNotFound) => {
                if !entry.prev_hash.is_empty() {
                    return Err(StorageError::HashChainBroken);
                }
            }
            Err(error) => return Err(StorageError::Database(error.to_string())),
        }

        let new_chain_seq = last_seq + 1;
        let new_cursor: i64 = sqlx::query_scalar(
            "UPDATE spaces SET cursor = cursor + 1 WHERE id = $1 RETURNING cursor",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let prev_hash = if entry.prev_hash.is_empty() {
            None
        } else {
            Some(entry.prev_hash.as_slice())
        };

        sqlx::query(
            "INSERT INTO members (space_id, chain_seq, cursor, prev_hash, entry_hash, payload) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(space_id)
        .bind(new_chain_seq)
        .bind(new_cursor)
        .bind(prev_hash)
        .bind(&entry.entry_hash)
        .bind(&entry.payload)
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let new_version = current_version + 1;
        sqlx::query("UPDATE spaces SET metadata_version = $1 WHERE id = $2")
            .bind(new_version)
            .bind(space_id)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(AppendLogResult {
            chain_seq: new_chain_seq,
            cursor: new_cursor,
            metadata_version: new_version,
        })
    }

    async fn get_members(
        &self,
        space_id: Uuid,
        since_seq: i32,
    ) -> Result<Vec<MembersLogEntry>, StorageError> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM spaces WHERE id = $1)")
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        if !exists {
            return Err(StorageError::SpaceNotFound);
        }

        let rows = sqlx::query_as::<_, MemberRow>(
            r#"
            SELECT space_id, chain_seq, cursor, prev_hash, entry_hash, payload
            FROM members
            WHERE space_id = $1
              AND chain_seq > $2
            ORDER BY chain_seq ASC
            "#,
        )
        .bind(space_id)
        .bind(since_seq)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| MembersLogEntry {
                space_id: row.space_id,
                chain_seq: row.chain_seq,
                cursor: row.cursor,
                prev_hash: row.prev_hash.unwrap_or_default(),
                entry_hash: row.entry_hash,
                payload: row.payload,
            })
            .collect())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct LastMemberRow {
    chain_seq: i32,
    entry_hash: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct MemberRow {
    space_id: Uuid,
    chain_seq: i32,
    cursor: i64,
    prev_hash: Option<Vec<u8>>,
    entry_hash: Vec<u8>,
    payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use crate::{MembershipStorage, StorageError};

    #[tokio::test]
    async fn append_member_chains_and_updates_metadata_version() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let hash1 = vec![0x11; 32];
        let first = storage
            .append_member(space_id, 0, &member_entry(&[], &hash1, b"entry-1"))
            .await
            .expect("append first member");
        assert_eq!(first.chain_seq, 1);
        assert_eq!(first.metadata_version, 1);

        let hash2 = vec![0x22; 32];
        let second = storage
            .append_member(space_id, 1, &member_entry(&hash1, &hash2, b"entry-2"))
            .await
            .expect("append second member");
        assert_eq!(second.chain_seq, 2);
        assert_eq!(second.metadata_version, 2);

        let members = storage.get_members(space_id, 0).await.expect("get members");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].chain_seq, 1);
        assert_eq!(members[1].chain_seq, 2);
        assert_eq!(members[1].prev_hash, hash1);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn append_member_rejects_cas_and_hash_chain_conflicts() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let cas_error = storage
            .append_member(
                space_id,
                999,
                &member_entry(&[], &[0x33; 32], b"entry-with-bad-version"),
            )
            .await
            .expect_err("expected version conflict");
        assert_eq!(cas_error, StorageError::VersionConflict);

        let first_prev_hash_error = storage
            .append_member(
                space_id,
                0,
                &member_entry(b"should-not-exist", &[0x44; 32], b"entry"),
            )
            .await
            .expect_err("first entry with prev_hash should fail");
        assert_eq!(first_prev_hash_error, StorageError::HashChainBroken);

        storage
            .append_member(space_id, 0, &member_entry(&[], &[0x55; 32], b"entry-1"))
            .await
            .expect("append baseline member");
        let chained_error = storage
            .append_member(
                space_id,
                1,
                &member_entry(b"wrong-prev-hash", &[0x66; 32], b"entry-2"),
            )
            .await
            .expect_err("chained entry with wrong prev_hash should fail");
        assert_eq!(chained_error, StorageError::HashChainBroken);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn append_member_and_get_members_require_existing_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = uuid::Uuid::new_v4();

        let append_error = storage
            .append_member(missing, 0, &member_entry(&[], &[0x11; 32], b"entry"))
            .await
            .expect_err("missing space append should fail");
        assert_eq!(append_error, StorageError::SpaceNotFound);

        let members_error = storage
            .get_members(missing, 0)
            .await
            .expect_err("missing space get members should fail");
        assert_eq!(members_error, StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn get_members_with_since() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Append 3 entries
        let mut prev_hash: Vec<u8> = vec![];
        for i in 1..=3 {
            let hash = vec![i as u8; 32];
            storage
                .append_member(
                    space_id,
                    i - 1,
                    &member_entry(&prev_hash, &hash, format!("entry {i}").as_bytes()),
                )
                .await
                .unwrap_or_else(|_| panic!("append {i} failed"));
            prev_hash = hash;
        }

        // Get entries since seq 2 — should only return entry 3
        let entries = storage
            .get_members(space_id, 2)
            .await
            .expect("get members with since");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].chain_seq, 3);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_members_empty() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let entries = storage
            .get_members(space_id, 0)
            .await
            .expect("get members empty");
        assert!(entries.is_empty());

        cleanup_space(&storage, space_id).await;
    }
}
