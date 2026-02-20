#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use less_sync_core::protocol::{Change, Space};
use less_sync_core::validation::{validate_record_id, DEFAULT_MAX_BLOB_SIZE};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    AdvanceEpochOptions, AdvanceEpochResult, AppendLogResult, DekRecord, EpochConflict,
    FederationKey, FederationSigningKey, FileDekRecord, FileMetadata, Invitation, MembersLogEntry,
    PullEntry, PullEntryKind, PullResult, PullStreamMeta, PushOptions, PushResult, Storage,
    StorageError,
};

const MAX_RECORDS_LIMIT: usize = 100_000;
const MAX_PUSH_PAYLOAD: i64 = 500 * 1024 * 1024;
const WRAPPED_DEK_LENGTH: usize = 44;

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        let row = sqlx::query_as::<_, SpaceRow>(
            r#"
            SELECT
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            FROM spaces
            WHERE id = $1
            "#,
        )
        .bind(space_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        Ok(row.into())
    }

    pub async fn get_spaces(
        &self,
        space_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Space>, StorageError> {
        if space_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query_as::<_, SpaceRow>(
            r#"
            SELECT
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            FROM spaces
            WHERE id = ANY($1)
            "#,
        )
        .bind(space_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let id = row.id;
                (id, row.into())
            })
            .collect())
    }

    pub async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError> {
        let root_public_key = root_public_key.map(ToOwned::to_owned);
        let row = sqlx::query_as::<_, SpaceRow>(
            r#"
            INSERT INTO spaces (id, client_id, root_public_key)
            VALUES ($1, $2, $3)
            RETURNING
                id,
                client_id,
                root_public_key,
                key_generation,
                min_key_generation,
                metadata_version,
                cursor,
                rewrap_epoch,
                home_server
            "#,
        )
        .bind(space_id)
        .bind(client_id)
        .bind(root_public_key)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                StorageError::SpaceExists
            } else {
                StorageError::Database(error.to_string())
            }
        })?;

        Ok(row.into())
    }

    pub async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<Space, StorageError> {
        match self.get_space(space_id).await {
            Ok(space) => return Ok(space),
            Err(StorageError::SpaceNotFound) => {}
            Err(error) => return Err(error),
        }

        match self.create_space(space_id, client_id, None).await {
            Ok(space) => Ok(space),
            Err(StorageError::SpaceExists) => self.get_space(space_id).await,
            Err(error) => Err(error),
        }
    }

    pub async fn pull(&self, space_id: Uuid, since: i64) -> Result<PullResult, StorageError> {
        // REPEATABLE READ ensures snapshot consistency across the cursor fetch
        // and the UNION ALL — prevents phantom entries from concurrent writes.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;

        let rows = sqlx::query_as::<_, StreamPullRow>(
            r#"
            SELECT
                'r' AS kind,
                id,
                cursor,
                blob,
                wrapped_dek,
                NULL::uuid AS record_id,
                NULL::bigint AS size,
                deleted,
                NULL::int AS chain_seq,
                NULL::bytea AS prev_hash,
                NULL::bytea AS entry_hash,
                NULL::bytea AS payload
            FROM records
            WHERE space_id = $1
              AND cursor > $2
              AND ($2 <> 0 OR deleted = FALSE)
            UNION ALL
            SELECT
                'm' AS kind,
                NULL::uuid AS id,
                cursor,
                NULL::bytea AS blob,
                NULL::bytea AS wrapped_dek,
                NULL::uuid AS record_id,
                NULL::bigint AS size,
                FALSE AS deleted,
                chain_seq,
                prev_hash,
                entry_hash,
                payload
            FROM members
            WHERE space_id = $1
              AND cursor > $2
            UNION ALL
            SELECT
                'f' AS kind,
                id,
                cursor,
                NULL::bytea AS blob,
                wrapped_dek,
                record_id,
                size,
                deleted,
                NULL::int AS chain_seq,
                NULL::bytea AS prev_hash,
                NULL::bytea AS entry_hash,
                NULL::bytea AS payload
            FROM files
            WHERE space_id = $1
              AND cursor > $2
              AND ($2 <> 0 OR deleted = FALSE)
            ORDER BY cursor ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let mut entries = Vec::with_capacity(rows.len());
        let mut record_count = 0_usize;
        for row in rows {
            match row.kind.as_str() {
                "r" => {
                    let id = row.id.ok_or_else(|| {
                        StorageError::Database("pull record missing id".to_owned())
                    })?;
                    record_count += 1;
                    entries.push(PullEntry {
                        kind: PullEntryKind::Record,
                        cursor: row.cursor,
                        record: Some(Change {
                            id: id.to_string(),
                            blob: row.blob,
                            cursor: row.cursor,
                            wrapped_dek: row.wrapped_dek,
                            deleted: row.deleted,
                        }),
                        member: None,
                        file: None,
                    });
                }
                "m" => {
                    entries.push(PullEntry {
                        kind: PullEntryKind::Membership,
                        cursor: row.cursor,
                        record: None,
                        member: Some(MembersLogEntry {
                            space_id,
                            chain_seq: row.chain_seq.ok_or_else(|| {
                                StorageError::Database("pull member missing chain_seq".to_owned())
                            })?,
                            cursor: row.cursor,
                            prev_hash: row.prev_hash.unwrap_or_default(),
                            entry_hash: row.entry_hash.unwrap_or_default(),
                            payload: row.payload.unwrap_or_default(),
                        }),
                        file: None,
                    });
                }
                "f" => {
                    let id = row
                        .id
                        .ok_or_else(|| StorageError::Database("pull file missing id".to_owned()))?;
                    let record_id = row.record_id.ok_or_else(|| {
                        StorageError::Database("pull file missing record_id".to_owned())
                    })?;
                    entries.push(PullEntry {
                        kind: PullEntryKind::File,
                        cursor: row.cursor,
                        record: None,
                        member: None,
                        file: Some(crate::FileEntry {
                            id,
                            record_id,
                            size: row.size.unwrap_or_default(),
                            deleted: row.deleted,
                            wrapped_dek: row.wrapped_dek.unwrap_or_default(),
                            cursor: row.cursor,
                        }),
                    });
                }
                _ => {}
            }
        }

        Ok(PullResult {
            entries,
            record_count,
            cursor,
        })
    }

    pub async fn stream_pull(
        &self,
        space_id: Uuid,
        since: i64,
        on_meta: &(dyn Fn(PullStreamMeta) -> Result<(), StorageError> + Send + Sync),
        on_entry: &(dyn Fn(PullEntry) -> Result<(), StorageError> + Send + Sync),
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        // Keep all reads within one consistent snapshot.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let meta_row = sqlx::query_as::<_, PullMetaRow>(
            "SELECT cursor, key_generation, rewrap_epoch FROM spaces WHERE id = $1",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        on_meta(PullStreamMeta {
            cursor: meta_row.cursor,
            key_generation: meta_row.key_generation,
            rewrap_epoch: meta_row.rewrap_epoch,
        })?;

        let rows = sqlx::query_as::<_, StreamPullRow>(
            r#"
            SELECT
                'r' AS kind,
                id,
                cursor,
                blob,
                wrapped_dek,
                NULL::uuid AS record_id,
                NULL::bigint AS size,
                deleted,
                NULL::int AS chain_seq,
                NULL::bytea AS prev_hash,
                NULL::bytea AS entry_hash,
                NULL::bytea AS payload
            FROM records
            WHERE space_id = $1
              AND cursor > $2
              AND ($2 <> 0 OR deleted = FALSE)
            UNION ALL
            SELECT
                'm' AS kind,
                NULL::uuid AS id,
                cursor,
                NULL::bytea AS blob,
                NULL::bytea AS wrapped_dek,
                NULL::uuid AS record_id,
                NULL::bigint AS size,
                FALSE AS deleted,
                chain_seq,
                prev_hash,
                entry_hash,
                payload
            FROM members
            WHERE space_id = $1
              AND cursor > $2
            UNION ALL
            SELECT
                'f' AS kind,
                id,
                cursor,
                NULL::bytea AS blob,
                wrapped_dek,
                record_id,
                size,
                deleted,
                NULL::int AS chain_seq,
                NULL::bytea AS prev_hash,
                NULL::bytea AS entry_hash,
                NULL::bytea AS payload
            FROM files
            WHERE space_id = $1
              AND cursor > $2
              AND ($2 <> 0 OR deleted = FALSE)
            ORDER BY cursor ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        for row in rows {
            match row.kind.as_str() {
                "r" => {
                    let id = row.id.ok_or_else(|| {
                        StorageError::Database("stream pull record missing id".to_owned())
                    })?;
                    on_entry(PullEntry {
                        kind: PullEntryKind::Record,
                        cursor: row.cursor,
                        record: Some(Change {
                            id: id.to_string(),
                            blob: row.blob,
                            cursor: row.cursor,
                            wrapped_dek: row.wrapped_dek,
                            deleted: row.deleted,
                        }),
                        member: None,
                        file: None,
                    })?;
                }
                "m" => {
                    on_entry(PullEntry {
                        kind: PullEntryKind::Membership,
                        cursor: row.cursor,
                        record: None,
                        member: Some(MembersLogEntry {
                            space_id,
                            chain_seq: row.chain_seq.ok_or_else(|| {
                                StorageError::Database(
                                    "stream pull member missing chain_seq".to_owned(),
                                )
                            })?,
                            cursor: row.cursor,
                            prev_hash: row.prev_hash.unwrap_or_default(),
                            entry_hash: row.entry_hash.unwrap_or_default(),
                            payload: row.payload.unwrap_or_default(),
                        }),
                        file: None,
                    })?;
                }
                "f" => {
                    let id = row.id.ok_or_else(|| {
                        StorageError::Database("stream pull file missing id".to_owned())
                    })?;
                    let record_id = row.record_id.ok_or_else(|| {
                        StorageError::Database("stream pull file missing record_id".to_owned())
                    })?;
                    on_entry(PullEntry {
                        kind: PullEntryKind::File,
                        cursor: row.cursor,
                        record: None,
                        member: None,
                        file: Some(crate::FileEntry {
                            id,
                            record_id,
                            size: row.size.unwrap_or_default(),
                            deleted: row.deleted,
                            wrapped_dek: row.wrapped_dek.unwrap_or_default(),
                            cursor: row.cursor,
                        }),
                    })?;
                }
                _ => {}
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn record_exists(
        &self,
        space_id: Uuid,
        record_id: Uuid,
    ) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records WHERE space_id = $1 AND id = $2)",
        )
        .bind(space_id)
        .bind(record_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }

    pub async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        if wrapped_dek.len() != WRAPPED_DEK_LENGTH {
            return Err(StorageError::InvalidWrappedDek);
        }
        if size < 0 {
            return Err(StorageError::InvalidFileSize);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let new_cursor: i64 = sqlx::query_scalar(
            "UPDATE spaces SET cursor = cursor + 1 WHERE id = $1 RETURNING cursor",
        )
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        let result = sqlx::query(
            r#"
            INSERT INTO files (space_id, id, record_id, size, wrapped_dek, cursor)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (space_id, id) DO NOTHING
            "#,
        )
        .bind(space_id)
        .bind(file_id)
        .bind(record_id)
        .bind(size)
        .bind(wrapped_dek)
        .bind(new_cursor)
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        // Preserve idempotency without advancing space cursor when the file already exists.
        if result.rows_affected() == 0 {
            tx.rollback()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            return Ok(None);
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(Some(new_cursor))
    }

    pub async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError> {
        let row = sqlx::query_as::<_, FileMetadataRow>(
            r#"
            SELECT id, record_id, size, wrapped_dek, cursor
            FROM files
            WHERE space_id = $1 AND id = $2
            "#,
        )
        .bind(space_id)
        .bind(file_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::FileNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        Ok(FileMetadata {
            id: row.id,
            record_id: row.record_id,
            size: row.size,
            wrapped_dek: row.wrapped_dek,
            cursor: row.cursor,
        })
    }

    pub async fn file_exists(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM files WHERE space_id = $1 AND id = $2)",
        )
        .bind(space_id)
        .bind(file_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }

    pub async fn get_file_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<FileDekRecord>, StorageError> {
        let rows = sqlx::query_as::<_, FileDekRow>(
            r#"
            SELECT id, wrapped_dek, cursor
            FROM files
            WHERE space_id = $1
              AND cursor > $2
            ORDER BY cursor ASC, id ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| FileDekRecord {
                id: row.id,
                wrapped_dek: row.wrapped_dek,
                cursor: row.cursor,
            })
            .collect())
    }

    pub async fn rewrap_file_deks(
        &self,
        space_id: Uuid,
        deks: &[FileDekRecord],
    ) -> Result<(), StorageError> {
        if deks.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let key_generation: i32 =
            sqlx::query_scalar("SELECT key_generation FROM spaces WHERE id = $1 FOR UPDATE")
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| match error {
                    sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                    _ => StorageError::Database(error.to_string()),
                })?;

        for dek in deks {
            let epoch = parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
            if epoch != key_generation {
                return Err(StorageError::DekEpochMismatch);
            }
        }

        for dek in deks {
            let result =
                sqlx::query("UPDATE files SET wrapped_dek = $1 WHERE id = $2 AND space_id = $3")
                    .bind(&dek.wrapped_dek)
                    .bind(dek.id)
                    .bind(space_id)
                    .execute(tx.as_mut())
                    .await
                    .map_err(|error| StorageError::Database(error.to_string()))?;

            if result.rows_affected() != 1 {
                return Err(StorageError::FileDekNotFound);
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn delete_files_for_records(
        &self,
        space_id: Uuid,
        record_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, StorageError> {
        if record_ids.is_empty() {
            return Ok(Vec::new());
        }

        sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM files WHERE space_id = $1 AND record_id = ANY($2) RETURNING id",
        )
        .bind(space_id)
        .bind(record_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))
    }

    pub async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE space_id = $1 AND ucan_cid = $2)",
        )
        .bind(space_id)
        .bind(ucan_cid)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(exists)
    }

    pub async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO revocations (space_id, ucan_cid)
            VALUES ($1, $2)
            ON CONFLICT (space_id, ucan_cid) DO NOTHING
            "#,
        )
        .bind(space_id)
        .bind(ucan_cid)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn create_invitation(
        &self,
        invitation: &Invitation,
    ) -> Result<Invitation, StorageError> {
        let row = sqlx::query_as::<_, InvitationRow>(
            r#"
            INSERT INTO invitations (mailbox_id, payload, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '7 days')
            RETURNING
                id,
                mailbox_id,
                payload,
                (EXTRACT(EPOCH FROM created_at) * 1000000)::BIGINT AS created_at_us,
                (EXTRACT(EPOCH FROM expires_at) * 1000000)::BIGINT AS expires_at_us
            "#,
        )
        .bind(&invitation.mailbox_id)
        .bind(&invitation.payload)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Invitation::try_from(row)
    }

    pub async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError> {
        let limit = limit.min(i64::MAX as usize) as i64;

        let rows = if let Some(after) = after {
            sqlx::query_as::<_, InvitationRow>(
                r#"
                SELECT
                    id,
                    mailbox_id,
                    payload,
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::BIGINT AS created_at_us,
                    (EXTRACT(EPOCH FROM expires_at) * 1000000)::BIGINT AS expires_at_us
                FROM invitations
                WHERE mailbox_id = $1
                  AND expires_at > NOW()
                  AND (created_at, id) > (
                      SELECT created_at, id FROM invitations
                      WHERE id = $2 AND mailbox_id = $1
                  )
                ORDER BY created_at ASC, id ASC
                LIMIT $3
                "#,
            )
            .bind(mailbox_id)
            .bind(after)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, InvitationRow>(
                r#"
                SELECT
                    id,
                    mailbox_id,
                    payload,
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::BIGINT AS created_at_us,
                    (EXTRACT(EPOCH FROM expires_at) * 1000000)::BIGINT AS expires_at_us
                FROM invitations
                WHERE mailbox_id = $1
                  AND expires_at > NOW()
                ORDER BY created_at ASC, id ASC
                LIMIT $2
                "#,
            )
            .bind(mailbox_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|error| StorageError::Database(error.to_string()))?;

        rows.into_iter().map(Invitation::try_from).collect()
    }

    pub async fn get_invitation(
        &self,
        id: Uuid,
        mailbox_id: &str,
    ) -> Result<Invitation, StorageError> {
        let row = sqlx::query_as::<_, InvitationRow>(
            r#"
            SELECT
                id,
                mailbox_id,
                payload,
                (EXTRACT(EPOCH FROM created_at) * 1000000)::BIGINT AS created_at_us,
                (EXTRACT(EPOCH FROM expires_at) * 1000000)::BIGINT AS expires_at_us
            FROM invitations
            WHERE id = $1
              AND mailbox_id = $2
              AND expires_at > NOW()
            "#,
        )
        .bind(id)
        .bind(mailbox_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::InvitationNotFound,
            _ => StorageError::Database(error.to_string()),
        })?;

        Invitation::try_from(row)
    }

    pub async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM invitations WHERE id = $1 AND mailbox_id = $2")
            .bind(id)
            .bind(mailbox_id)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(StorageError::InvitationNotFound);
        }
        Ok(())
    }

    pub async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError> {
        let since_micros = system_time_to_unix_micros(since)?;
        let count = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM rate_limit_actions
            WHERE action = $1
              AND actor_hash = $2
              AND created_at > to_timestamp(($3::double precision) / 1000000.0)
            "#,
        )
        .bind(action)
        .bind(actor_hash)
        .bind(since_micros)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(count)
    }

    pub async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO rate_limit_actions (action, actor_hash) VALUES ($1, $2)")
            .bind(action)
            .bind(actor_hash)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn cleanup_expired_actions(&self, before: SystemTime) -> Result<i64, StorageError> {
        let before_micros = system_time_to_unix_micros(before)?;
        let result = sqlx::query(
            "DELETE FROM rate_limit_actions WHERE created_at < to_timestamp(($1::double precision) / 1000000.0)",
        )
        .bind(before_micros)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(result.rows_affected() as i64)
    }

    pub async fn purge_expired_invitations(&self) -> Result<i64, StorageError> {
        let result = sqlx::query("DELETE FROM invitations WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(result.rows_affected() as i64)
    }

    pub async fn append_member(
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

    pub async fn get_members(
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

    pub async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError> {
        let set_min = opts.is_some_and(|value| value.set_min_key_generation);
        let result = if set_min {
            sqlx::query(
                "UPDATE spaces SET key_generation = $1, rewrap_epoch = $1, min_key_generation = $1 WHERE id = $2 AND key_generation = $3 AND rewrap_epoch IS NULL",
            )
            .bind(requested_epoch)
            .bind(space_id)
            .bind(requested_epoch - 1)
            .execute(&self.pool)
            .await
        } else {
            sqlx::query(
                "UPDATE spaces SET key_generation = $1, rewrap_epoch = $1 WHERE id = $2 AND key_generation = $3 AND rewrap_epoch IS NULL",
            )
            .bind(requested_epoch)
            .bind(space_id)
            .bind(requested_epoch - 1)
            .execute(&self.pool)
            .await
        }
        .map_err(|error| StorageError::Database(error.to_string()))?;

        if result.rows_affected() == 0 {
            let state = sqlx::query_as::<_, EpochStateRow>(
                "SELECT key_generation, rewrap_epoch FROM spaces WHERE id = $1",
            )
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;
            return Err(StorageError::EpochConflict(EpochConflict {
                current_epoch: state.key_generation,
                rewrap_epoch: state.rewrap_epoch,
            }));
        }

        Ok(AdvanceEpochResult {
            epoch: requested_epoch,
        })
    }

    pub async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE spaces SET rewrap_epoch = NULL WHERE id = $1 AND rewrap_epoch = $2",
        )
        .bind(space_id)
        .bind(epoch)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        if result.rows_affected() == 0 {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM spaces WHERE id = $1)")
                    .bind(space_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|error| StorageError::Database(error.to_string()))?;
            if !exists {
                return Err(StorageError::SpaceNotFound);
            }
            return Err(StorageError::EpochMismatch);
        }
        Ok(())
    }

    pub async fn get_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<DekRecord>, StorageError> {
        let rows = sqlx::query_as::<_, DekRow>(
            r#"
            SELECT id, wrapped_dek, cursor
            FROM records
            WHERE space_id = $1
              AND cursor > $2
              AND wrapped_dek IS NOT NULL
            ORDER BY cursor ASC, id ASC
            "#,
        )
        .bind(space_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| DekRecord {
                id: row.id.to_string(),
                wrapped_dek: row.wrapped_dek,
                cursor: row.cursor,
            })
            .collect())
    }

    pub async fn rewrap_deks(
        &self,
        space_id: Uuid,
        deks: &[DekRecord],
    ) -> Result<(), StorageError> {
        if deks.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let key_generation: i32 =
            sqlx::query_scalar("SELECT key_generation FROM spaces WHERE id = $1 FOR UPDATE")
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| match error {
                    sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                    _ => StorageError::Database(error.to_string()),
                })?;

        for dek in deks {
            let epoch = parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
            if epoch != key_generation {
                return Err(StorageError::DekEpochMismatch);
            }

            let record_id = Uuid::parse_str(&dek.id).map_err(|_| StorageError::InvalidRecordId)?;
            let result =
                sqlx::query("UPDATE records SET wrapped_dek = $1 WHERE id = $2 AND space_id = $3")
                    .bind(&dek.wrapped_dek)
                    .bind(record_id)
                    .bind(space_id)
                    .execute(tx.as_mut())
                    .await
                    .map_err(|error| StorageError::Database(error.to_string()))?;
            if result.rows_affected() != 1 {
                return Err(StorageError::DekRecordNotFound);
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn get_space_home_server(
        &self,
        space_id: Uuid,
    ) -> Result<Option<String>, StorageError> {
        sqlx::query_scalar("SELECT home_server FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })
    }

    pub async fn set_space_home_server(
        &self,
        space_id: Uuid,
        home_server: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE spaces SET home_server = $2 WHERE id = $1")
            .bind(space_id)
            .bind(home_server)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(StorageError::SpaceNotFound);
        }
        Ok(())
    }

    pub async fn ensure_federation_key(
        &self,
        kid: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO federation_signing_keys (kid, private_key, public_key, is_active, is_primary)
            VALUES (
                $1,
                $2,
                $3,
                TRUE,
                NOT EXISTS (
                    SELECT 1
                    FROM federation_signing_keys
                    WHERE is_primary = TRUE AND is_active = TRUE
                )
            )
            ON CONFLICT (kid) DO NOTHING
            "#,
        )
        .bind(kid)
        .bind(private_key)
        .bind(public_key)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn set_federation_primary_key(&self, kid: &str) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        sqlx::query(
            "UPDATE federation_signing_keys SET is_primary = FALSE WHERE is_primary = TRUE",
        )
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        let updated = sqlx::query(
            r#"
            UPDATE federation_signing_keys
            SET is_primary = TRUE, is_active = TRUE, deactivated_at = NULL
            WHERE kid = $1
            "#,
        )
        .bind(kid)
        .execute(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::FederationKeyNotFound);
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    pub async fn deactivate_federation_key(&self, kid: &str) -> Result<(), StorageError> {
        let updated = sqlx::query(
            r#"
            UPDATE federation_signing_keys
            SET is_active = FALSE, is_primary = FALSE, deactivated_at = NOW()
            WHERE kid = $1
            "#,
        )
        .bind(kid)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::FederationKeyNotFound);
        }
        Ok(())
    }

    pub async fn get_federation_private_key(&self, kid: &str) -> Result<Vec<u8>, StorageError> {
        sqlx::query_scalar("SELECT private_key FROM federation_signing_keys WHERE kid = $1")
            .bind(kid)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::FederationKeyNotFound,
                _ => StorageError::Database(error.to_string()),
            })
    }

    pub async fn get_federation_signing_key(
        &self,
    ) -> Result<Option<FederationSigningKey>, StorageError> {
        let row = sqlx::query_as::<_, FederationSigningKeyRow>(
            r#"
            SELECT kid, private_key, public_key
            FROM federation_signing_keys
            WHERE is_active = TRUE AND is_primary = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(row.map(|row| FederationSigningKey {
            kid: row.kid,
            private_key: row.private_key,
            public_key: row.public_key,
        }))
    }

    pub async fn list_federation_public_keys(&self) -> Result<Vec<FederationKey>, StorageError> {
        let rows = sqlx::query_as::<_, FederationKeyRow>(
            r#"
            SELECT kid, public_key
            FROM federation_signing_keys
            WHERE is_active = TRUE
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| FederationKey {
                kid: row.kid,
                public_key: row.public_key,
            })
            .collect())
    }

    pub async fn push(
        &self,
        space_id: Uuid,
        changes: &[Change],
        opts: Option<&PushOptions>,
    ) -> Result<PushResult, StorageError> {
        if changes.is_empty() {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            let cursor = get_space_cursor_for_update(&mut tx, space_id).await?;
            tx.commit()
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            return Ok(PushResult {
                ok: true,
                cursor,
                deleted_file_ids: Vec::new(),
            });
        }

        if changes.len() > MAX_RECORDS_LIMIT {
            return Err(StorageError::PushRecordLimitExceeded);
        }

        let mut total_payload = 0_i64;
        let mut record_ids = Vec::with_capacity(changes.len());
        let mut seen_ids = HashSet::with_capacity(changes.len());
        for change in changes {
            validate_record_id(&change.id).map_err(|_| StorageError::InvalidRecordId)?;
            let record_id =
                Uuid::parse_str(&change.id).map_err(|_| StorageError::InvalidRecordId)?;
            if !seen_ids.insert(record_id) {
                return Err(StorageError::DuplicateRecordId);
            }
            record_ids.push(record_id);

            let blob_len = change.blob.as_ref().map_or(0, |blob| blob.len() as i64);
            if blob_len > DEFAULT_MAX_BLOB_SIZE {
                return Err(StorageError::BlobTooLarge);
            }
            total_payload += blob_len;
        }

        if total_payload > MAX_PUSH_PAYLOAD {
            return Err(StorageError::PushPayloadLimitExceeded);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        let space_cursor = get_space_cursor_for_update(&mut tx, space_id).await?;

        if let Some(opts) = opts {
            if opts.key_generation > 0 {
                let row = sqlx::query_as::<_, SpaceAuthRow>(
                    "SELECT root_public_key, min_key_generation FROM spaces WHERE id = $1",
                )
                .bind(space_id)
                .fetch_one(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
                if row.root_public_key.is_some() && opts.key_generation < row.min_key_generation {
                    return Err(StorageError::KeyGenerationStale);
                }
            }
        }

        let existing_rows = sqlx::query_as::<_, ExistingRecordRow>(
            "SELECT id, cursor FROM records WHERE space_id = $1 AND id = ANY($2)",
        )
        .bind(space_id)
        .bind(&record_ids)
        .fetch_all(tx.as_mut())
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;
        let existing_sequences = existing_rows
            .into_iter()
            .map(|row| (row.id, row.cursor))
            .collect::<HashMap<_, _>>();

        for (idx, change) in changes.iter().enumerate() {
            let record_id = record_ids[idx];
            let existing_sequence = existing_sequences.get(&record_id).copied();

            let has_conflict = match (change.cursor, existing_sequence) {
                (0, Some(_)) => true,
                (0, None) => false,
                (_, None) => true,
                (cursor, Some(existing)) => cursor != existing,
            };

            if has_conflict {
                return Ok(PushResult {
                    ok: false,
                    cursor: 0,
                    deleted_file_ids: Vec::new(),
                });
            }
        }

        let new_cursor = space_cursor + 1;
        let mut tombstoned_ids = Vec::new();
        for (idx, change) in changes.iter().enumerate() {
            let record_id = record_ids[idx];
            let deleted = change.blob.is_none();
            if deleted {
                tombstoned_ids.push(record_id);
            }

            if existing_sequences.contains_key(&record_id) {
                sqlx::query(
                    "UPDATE records SET blob = $1, cursor = $2, wrapped_dek = $3, deleted = $4 WHERE id = $5",
                )
                .bind(&change.blob)
                .bind(new_cursor)
                .bind(&change.wrapped_dek)
                .bind(deleted)
                .bind(record_id)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            } else {
                sqlx::query(
                    "INSERT INTO records (id, space_id, blob, cursor, wrapped_dek, deleted) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(record_id)
                .bind(space_id)
                .bind(&change.blob)
                .bind(new_cursor)
                .bind(&change.wrapped_dek)
                .bind(deleted)
                .execute(tx.as_mut())
                .await
                .map_err(|error| StorageError::Database(error.to_string()))?;
            }
        }

        sqlx::query("UPDATE spaces SET cursor = $1 WHERE id = $2")
            .bind(new_cursor)
            .bind(space_id)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        let mut deleted_file_ids = Vec::new();
        if !tombstoned_ids.is_empty() {
            let rows = sqlx::query_scalar::<_, Uuid>(
                "DELETE FROM files WHERE space_id = $1 AND record_id = ANY($2) RETURNING id",
            )
            .bind(space_id)
            .bind(&tombstoned_ids)
            .fetch_all(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
            deleted_file_ids.extend(rows);
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        Ok(PushResult {
            ok: true,
            cursor: new_cursor,
            deleted_file_ids,
        })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[async_trait]
impl Storage for PostgresStorage {
    async fn ping(&self) -> Result<(), StorageError> {
        PostgresStorage::ping(self).await
    }

    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        PostgresStorage::get_space(self, space_id).await
    }

    async fn get_spaces(&self, space_ids: &[Uuid]) -> Result<HashMap<Uuid, Space>, StorageError> {
        PostgresStorage::get_spaces(self, space_ids).await
    }

    async fn create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
        root_public_key: Option<&[u8]>,
    ) -> Result<Space, StorageError> {
        PostgresStorage::create_space(self, space_id, client_id, root_public_key).await
    }

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<Space, StorageError> {
        PostgresStorage::get_or_create_space(self, space_id, client_id).await
    }

    async fn pull(&self, space_id: Uuid, since: i64) -> Result<PullResult, StorageError> {
        PostgresStorage::pull(self, space_id, since).await
    }

    async fn stream_pull(
        &self,
        space_id: Uuid,
        since: i64,
        on_meta: &(dyn Fn(PullStreamMeta) -> Result<(), StorageError> + Send + Sync),
        on_entry: &(dyn Fn(PullEntry) -> Result<(), StorageError> + Send + Sync),
    ) -> Result<(), StorageError> {
        PostgresStorage::stream_pull(self, space_id, since, on_meta, on_entry).await
    }

    async fn push(
        &self,
        space_id: Uuid,
        changes: &[Change],
        opts: Option<&PushOptions>,
    ) -> Result<PushResult, StorageError> {
        PostgresStorage::push(self, space_id, changes, opts).await
    }

    async fn record_exists(&self, space_id: Uuid, record_id: Uuid) -> Result<bool, StorageError> {
        PostgresStorage::record_exists(self, space_id, record_id).await
    }

    async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        PostgresStorage::record_file(self, space_id, file_id, record_id, size, wrapped_dek).await
    }

    async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError> {
        PostgresStorage::get_file_metadata(self, space_id, file_id).await
    }

    async fn file_exists(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, StorageError> {
        PostgresStorage::file_exists(self, space_id, file_id).await
    }

    async fn get_file_deks(
        &self,
        space_id: Uuid,
        since: i64,
    ) -> Result<Vec<FileDekRecord>, StorageError> {
        PostgresStorage::get_file_deks(self, space_id, since).await
    }

    async fn rewrap_file_deks(
        &self,
        space_id: Uuid,
        deks: &[FileDekRecord],
    ) -> Result<(), StorageError> {
        PostgresStorage::rewrap_file_deks(self, space_id, deks).await
    }

    async fn delete_files_for_records(
        &self,
        space_id: Uuid,
        record_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, StorageError> {
        PostgresStorage::delete_files_for_records(self, space_id, record_ids).await
    }

    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
        PostgresStorage::is_revoked(self, space_id, ucan_cid).await
    }

    async fn revoke_ucan(&self, space_id: Uuid, ucan_cid: &str) -> Result<(), StorageError> {
        PostgresStorage::revoke_ucan(self, space_id, ucan_cid).await
    }

    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError> {
        PostgresStorage::create_invitation(self, invitation).await
    }

    async fn list_invitations(
        &self,
        mailbox_id: &str,
        limit: usize,
        after: Option<Uuid>,
    ) -> Result<Vec<Invitation>, StorageError> {
        PostgresStorage::list_invitations(self, mailbox_id, limit, after).await
    }

    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError> {
        PostgresStorage::get_invitation(self, id, mailbox_id).await
    }

    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError> {
        PostgresStorage::delete_invitation(self, id, mailbox_id).await
    }

    async fn count_recent_actions(
        &self,
        action: &str,
        actor_hash: &str,
        since: SystemTime,
    ) -> Result<i64, StorageError> {
        PostgresStorage::count_recent_actions(self, action, actor_hash, since).await
    }

    async fn record_action(&self, action: &str, actor_hash: &str) -> Result<(), StorageError> {
        PostgresStorage::record_action(self, action, actor_hash).await
    }

    async fn cleanup_expired_actions(&self, before: SystemTime) -> Result<i64, StorageError> {
        PostgresStorage::cleanup_expired_actions(self, before).await
    }

    async fn purge_expired_invitations(&self) -> Result<i64, StorageError> {
        PostgresStorage::purge_expired_invitations(self).await
    }

    async fn append_member(
        &self,
        space_id: Uuid,
        expected_version: i32,
        entry: &MembersLogEntry,
    ) -> Result<AppendLogResult, StorageError> {
        PostgresStorage::append_member(self, space_id, expected_version, entry).await
    }

    async fn get_members(
        &self,
        space_id: Uuid,
        since_seq: i32,
    ) -> Result<Vec<MembersLogEntry>, StorageError> {
        PostgresStorage::get_members(self, space_id, since_seq).await
    }

    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError> {
        PostgresStorage::advance_epoch(self, space_id, requested_epoch, opts).await
    }

    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
        PostgresStorage::complete_rewrap(self, space_id, epoch).await
    }

    async fn get_deks(&self, space_id: Uuid, since: i64) -> Result<Vec<DekRecord>, StorageError> {
        PostgresStorage::get_deks(self, space_id, since).await
    }

    async fn rewrap_deks(&self, space_id: Uuid, deks: &[DekRecord]) -> Result<(), StorageError> {
        PostgresStorage::rewrap_deks(self, space_id, deks).await
    }

    async fn get_space_home_server(&self, space_id: Uuid) -> Result<Option<String>, StorageError> {
        PostgresStorage::get_space_home_server(self, space_id).await
    }

    async fn set_space_home_server(
        &self,
        space_id: Uuid,
        home_server: &str,
    ) -> Result<(), StorageError> {
        PostgresStorage::set_space_home_server(self, space_id, home_server).await
    }

    async fn ensure_federation_key(
        &self,
        kid: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError> {
        PostgresStorage::ensure_federation_key(self, kid, private_key, public_key).await
    }

    async fn set_federation_primary_key(&self, kid: &str) -> Result<(), StorageError> {
        PostgresStorage::set_federation_primary_key(self, kid).await
    }

    async fn deactivate_federation_key(&self, kid: &str) -> Result<(), StorageError> {
        PostgresStorage::deactivate_federation_key(self, kid).await
    }

    async fn get_federation_private_key(&self, kid: &str) -> Result<Vec<u8>, StorageError> {
        PostgresStorage::get_federation_private_key(self, kid).await
    }

    async fn get_federation_signing_key(
        &self,
    ) -> Result<Option<FederationSigningKey>, StorageError> {
        PostgresStorage::get_federation_signing_key(self).await
    }

    async fn list_federation_public_keys(&self) -> Result<Vec<FederationKey>, StorageError> {
        PostgresStorage::list_federation_public_keys(self).await
    }

    fn close(&self) -> Result<(), StorageError> {
        // Calling close() marks the pool closed immediately; we intentionally don't await
        // the shutdown future in this synchronous trait method.
        std::mem::drop(self.pool.close());
        Ok(())
    }
}

async fn get_space_cursor_for_update(
    tx: &mut Transaction<'_, Postgres>,
    space_id: Uuid,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("SELECT cursor FROM spaces WHERE id = $1 FOR UPDATE")
        .bind(space_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
            _ => StorageError::Database(error.to_string()),
        })
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceRow {
    id: Uuid,
    client_id: String,
    root_public_key: Option<Vec<u8>>,
    key_generation: i32,
    min_key_generation: i32,
    metadata_version: i32,
    cursor: i64,
    rewrap_epoch: Option<i32>,
    home_server: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SpaceAuthRow {
    root_public_key: Option<Vec<u8>>,
    min_key_generation: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct ExistingRecordRow {
    id: Uuid,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct PullMetaRow {
    cursor: i64,
    key_generation: i32,
    rewrap_epoch: Option<i32>,
}

#[derive(Debug, sqlx::FromRow)]
struct StreamPullRow {
    kind: String,
    id: Option<Uuid>,
    cursor: i64,
    blob: Option<Vec<u8>>,
    wrapped_dek: Option<Vec<u8>>,
    record_id: Option<Uuid>,
    size: Option<i64>,
    deleted: bool,
    chain_seq: Option<i32>,
    prev_hash: Option<Vec<u8>>,
    entry_hash: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
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

#[derive(Debug, sqlx::FromRow)]
struct EpochStateRow {
    key_generation: i32,
    rewrap_epoch: Option<i32>,
}

#[derive(Debug, sqlx::FromRow)]
struct DekRow {
    id: Uuid,
    wrapped_dek: Vec<u8>,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FileMetadataRow {
    id: Uuid,
    record_id: Uuid,
    size: i64,
    wrapped_dek: Vec<u8>,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FileDekRow {
    id: Uuid,
    wrapped_dek: Vec<u8>,
    cursor: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    mailbox_id: String,
    payload: Vec<u8>,
    created_at_us: i64,
    expires_at_us: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FederationKeyRow {
    kid: String,
    public_key: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct FederationSigningKeyRow {
    kid: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl From<SpaceRow> for Space {
    fn from(value: SpaceRow) -> Self {
        Self {
            id: value.id.to_string(),
            client_id: value.client_id,
            root_public_key: value.root_public_key,
            key_generation: value.key_generation,
            min_key_generation: value.min_key_generation,
            metadata_version: value.metadata_version,
            cursor: value.cursor,
            rewrap_epoch: value.rewrap_epoch,
            home_server: value.home_server,
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505")
    )
}

fn parse_dek_epoch(wrapped_dek: &[u8]) -> Option<i32> {
    let epoch = wrapped_dek
        .get(0..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(i32::from_be_bytes);
    epoch.filter(|value| *value > 0)
}

fn system_time_to_unix_micros(value: SystemTime) -> Result<i64, StorageError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_micros())
            .map_err(|_| StorageError::Database("timestamp out of range".to_owned())),
        Err(error) => {
            let micros = i64::try_from(error.duration().as_micros())
                .map_err(|_| StorageError::Database("timestamp out of range".to_owned()))?;
            Ok(-micros)
        }
    }
}

fn unix_micros_to_system_time(value: i64) -> Result<SystemTime, StorageError> {
    let micros = value.unsigned_abs();
    let duration = Duration::from_micros(micros);
    if value >= 0 {
        Ok(UNIX_EPOCH + duration)
    } else {
        UNIX_EPOCH
            .checked_sub(duration)
            .ok_or_else(|| StorageError::Database("timestamp out of range".to_owned()))
    }
}

impl TryFrom<InvitationRow> for Invitation {
    type Error = StorageError;

    fn try_from(value: InvitationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            mailbox_id: value.mailbox_id,
            payload: value.payload,
            created_at: unix_micros_to_system_time(value.created_at_us)?,
            expires_at: unix_micros_to_system_time(value.expires_at_us)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::env;
    use std::time::{Duration, SystemTime};

    use less_sync_core::protocol::Change;
    use sqlx::postgres::PgPoolOptions;

    use super::PostgresStorage;
    use crate::{
        AdvanceEpochOptions, DekRecord, EpochConflict, FileDekRecord, Invitation, MembersLogEntry,
        PullEntry, PullStreamMeta, Storage, StorageError,
    };

    async fn test_storage() -> Option<PostgresStorage> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => return None,
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect test database");
        crate::migrate_with_pool(&pool)
            .await
            .expect("apply migrations");
        Some(PostgresStorage::from_pool(pool))
    }

    async fn cleanup_space(storage: &PostgresStorage, space_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM spaces WHERE id = $1")
            .bind(space_id)
            .execute(storage.pool())
            .await;
    }

    async fn create_space(storage: &PostgresStorage, space_id: uuid::Uuid) {
        storage
            .create_space(space_id, "client-1", None)
            .await
            .expect("create space");
    }

    fn change(id: &str, blob: Option<&[u8]>, cursor: i64) -> Change {
        Change {
            id: id.to_owned(),
            blob: blob.map(ToOwned::to_owned),
            cursor,
            wrapped_dek: None,
            deleted: false,
        }
    }

    async fn create_record(storage: &PostgresStorage, space_id: uuid::Uuid) -> uuid::Uuid {
        let record_id = uuid::Uuid::new_v4();
        let id = record_id.to_string();
        storage
            .push(space_id, &[change(&id, Some(b"record"), 0)], None)
            .await
            .expect("create record");
        record_id
    }

    async fn create_record_with_dek(
        storage: &PostgresStorage,
        space_id: uuid::Uuid,
        wrapped_dek: Vec<u8>,
    ) -> uuid::Uuid {
        let record_id = uuid::Uuid::new_v4();
        let id = record_id.to_string();
        storage
            .push(
                space_id,
                &[Change {
                    id,
                    blob: Some(b"record".to_vec()),
                    cursor: 0,
                    wrapped_dek: Some(wrapped_dek),
                    deleted: false,
                }],
                None,
            )
            .await
            .expect("create record with DEK");
        record_id
    }

    fn wrapped_dek(fill: u8) -> Vec<u8> {
        vec![fill; super::WRAPPED_DEK_LENGTH]
    }

    fn wrapped_dek_with_epoch(epoch: i32, fill: u8) -> Vec<u8> {
        let mut wrapped = wrapped_dek(fill);
        wrapped[0..4].copy_from_slice(&epoch.to_be_bytes());
        wrapped
    }

    fn mailbox_id() -> String {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    }

    fn invitation_input(mailbox_id: &str, payload: &[u8]) -> Invitation {
        Invitation {
            id: uuid::Uuid::nil(),
            mailbox_id: mailbox_id.to_owned(),
            payload: payload.to_vec(),
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn member_entry(prev_hash: &[u8], entry_hash: &[u8], payload: &[u8]) -> MembersLogEntry {
        MembersLogEntry {
            space_id: uuid::Uuid::nil(),
            chain_seq: 0,
            cursor: 0,
            prev_hash: prev_hash.to_vec(),
            entry_hash: entry_hash.to_vec(),
            payload: payload.to_vec(),
        }
    }

    #[tokio::test]
    async fn create_and_get_space_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        let created = storage
            .create_space(space_id, "client-1", Some(&[1, 2, 3]))
            .await
            .expect("create space");
        let fetched = storage.get_space(space_id).await.expect("get space");

        assert_eq!(created.id, fetched.id);
        assert_eq!(fetched.id, space_id.to_string());
        assert_eq!(fetched.client_id, "client-1");
        assert_eq!(fetched.root_public_key, Some(vec![1, 2, 3]));

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_space_returns_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = uuid::Uuid::new_v4();

        let error = storage
            .get_space(missing)
            .await
            .expect_err("missing space should fail");
        assert_eq!(error, crate::StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn create_space_conflict_returns_space_exists() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        storage
            .create_space(space_id, "client-1", None)
            .await
            .expect("create first space");
        let error = storage
            .create_space(space_id, "client-1", None)
            .await
            .expect_err("duplicate insert should fail");
        assert_eq!(error, crate::StorageError::SpaceExists);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_or_create_space_is_idempotent() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();

        let first = storage
            .get_or_create_space(space_id, "client-1")
            .await
            .expect("create");
        let second = storage
            .get_or_create_space(space_id, "client-1")
            .await
            .expect("get existing");
        assert_eq!(first.id, second.id);
        assert_eq!(second.root_public_key, None);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spaces WHERE id = $1")
            .bind(space_id)
            .fetch_one(storage.pool())
            .await
            .expect("count rows");
        assert_eq!(count, 1);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_spaces_omits_missing_ids() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        let missing = uuid::Uuid::new_v4();

        storage
            .create_space(space_a, "client-a", None)
            .await
            .expect("create a");
        storage
            .create_space(space_b, "client-b", None)
            .await
            .expect("create b");

        let spaces = storage
            .get_spaces(&[space_a, space_b, missing])
            .await
            .expect("get spaces");
        assert_eq!(spaces.len(), 2);
        assert!(spaces.contains_key(&space_a));
        assert!(spaces.contains_key(&space_b));
        assert!(!spaces.contains_key(&missing));

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn pull_empty_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage.pull(space_id, 0).await.expect("pull empty");
        assert!(result.records().is_empty());
        assert_eq!(result.cursor, 0);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn pull_space_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let error = storage
            .pull(uuid::Uuid::new_v4(), 0)
            .await
            .expect_err("missing space");
        assert_eq!(error, crate::StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn push_to_existing_space() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let changes = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"hello"),
            0,
        )];
        let result = storage.push(space_id, &changes, None).await.expect("push");
        assert!(result.ok);
        assert_eq!(result.cursor, 1);

        let space = storage.get_space(space_id).await.expect("get space");
        assert_eq!(space.cursor, 1);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_new_record_exists() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let first = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v1"),
            0,
        )];
        storage
            .push(space_id, &first, None)
            .await
            .expect("first push");

        let second = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v2"),
            0,
        )];
        let result = storage
            .push(space_id, &second, None)
            .await
            .expect("second push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_update_existing_record() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let create = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v1"),
            0,
        )];
        storage.push(space_id, &create, None).await.expect("create");

        let update = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"v2"),
            1,
        )];
        let result = storage.push(space_id, &update, None).await.expect("update");
        assert!(result.ok);
        assert_eq!(result.cursor, 2);

        let pulled = storage.pull(space_id, 0).await.expect("pull");
        assert_eq!(pulled.records().len(), 1);
        assert_eq!(pulled.records()[0].blob, Some(b"v2".to_vec()));

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_delete_and_initial_sync_skips_tombstones() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let create = vec![change(
            "019400e8-7b5d-7000-8000-000000000001",
            Some(b"data"),
            0,
        )];
        storage.push(space_id, &create, None).await.expect("create");

        let tombstone = vec![change("019400e8-7b5d-7000-8000-000000000001", None, 1)];
        let result = storage
            .push(space_id, &tombstone, None)
            .await
            .expect("tombstone push");
        assert!(result.ok);

        let since_one = storage.pull(space_id, 1).await.expect("pull since 1");
        assert_eq!(since_one.records().len(), 1);
        assert!(since_one.records()[0].is_deleted());

        let initial = storage.pull(space_id, 0).await.expect("initial pull");
        assert!(initial.records().is_empty());

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn record_exists_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let missing = storage
            .record_exists(space_id, uuid::Uuid::new_v4())
            .await
            .expect("exists query");
        assert!(!missing);

        let id = "019400e8-7b5d-7000-8000-000000000001";
        let parsed = uuid::Uuid::parse_str(id).expect("parse id");
        storage
            .push(space_id, &[change(id, Some(b"x"), 0)], None)
            .await
            .expect("push");

        let exists = storage
            .record_exists(space_id, parsed)
            .await
            .expect("exists query");
        assert!(exists);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn record_file_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();
        let wrapped_dek = wrapped_dek(0xfe);

        let cursor = storage
            .record_file(space_id, file_id, record_id, 100, &wrapped_dek)
            .await
            .expect("record file")
            .expect("should return cursor for new file");
        assert!(cursor > 0);
        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("get metadata");
        assert_eq!(metadata.id, file_id);
        assert_eq!(metadata.record_id, record_id);
        assert_eq!(metadata.size, 100);
        assert_eq!(metadata.wrapped_dek, wrapped_dek);
        assert_eq!(metadata.cursor, cursor);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn record_file_is_idempotent_without_cursor_advance() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();
        let wrapped_dek = wrapped_dek(0xfe);

        let first_cursor = storage
            .record_file(space_id, file_id, record_id, 100, &wrapped_dek)
            .await
            .expect("first record file")
            .expect("should return cursor for new file");

        let second_result = storage
            .record_file(space_id, file_id, record_id, 100, &wrapped_dek)
            .await
            .expect("second record file");
        assert_eq!(second_result, None, "idempotent call should return None");
        let space_cursor = storage.get_space(space_id).await.expect("get space").cursor;
        assert_eq!(space_cursor, first_cursor, "cursor should not advance");

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn record_file_validates_wrapped_dek_and_size() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let invalid_dek = storage
            .record_file(space_id, uuid::Uuid::new_v4(), record_id, 100, b"short")
            .await
            .expect_err("short wrapped dek should fail");
        assert_eq!(invalid_dek, StorageError::InvalidWrappedDek);

        let invalid_size = storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                -1,
                &wrapped_dek(0xfe),
            )
            .await
            .expect_err("negative file size should fail");
        assert_eq!(invalid_size, StorageError::InvalidFileSize);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_file_metadata_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .get_file_metadata(space_id, uuid::Uuid::new_v4())
            .await
            .expect_err("missing file should fail");
        assert_eq!(error, StorageError::FileNotFound);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn file_exists_and_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;
        let record_id = create_record(&storage, space_a).await;
        let file_id = uuid::Uuid::new_v4();
        let wrapped_dek = wrapped_dek(0xfe);

        let before = storage
            .file_exists(space_a, file_id)
            .await
            .expect("exists before insert");
        assert!(!before);

        storage
            .record_file(space_a, file_id, record_id, 100, &wrapped_dek)
            .await
            .expect("record file");

        let exists_a = storage
            .file_exists(space_a, file_id)
            .await
            .expect("exists in space a");
        let exists_b = storage
            .file_exists(space_b, file_id)
            .await
            .expect("exists in space b");
        assert!(exists_a);
        assert!(!exists_b);

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn get_file_deks_respects_since_cursor() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let file_a = uuid::Uuid::new_v4();
        let file_b = uuid::Uuid::new_v4();
        storage
            .record_file(space_id, file_a, record_id, 100, &wrapped_dek(0xaa))
            .await
            .expect("record file a");
        let all = storage
            .get_file_deks(space_id, 0)
            .await
            .expect("get all deks");
        assert_eq!(all.len(), 1);
        let first_cursor = all[0].cursor;

        storage
            .record_file(space_id, file_b, record_id, 200, &wrapped_dek(0xbb))
            .await
            .expect("record file b");
        let since = storage
            .get_file_deks(space_id, first_cursor)
            .await
            .expect("get since");
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].id, file_b);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn rewrap_file_deks_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(
                space_id,
                file_id,
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xaa),
            )
            .await
            .expect("record file");

        let new_dek = wrapped_dek_with_epoch(1, 0xcc);
        storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: new_dek.clone(),
                    cursor: 0,
                }],
            )
            .await
            .expect("rewrap");

        let metadata = storage
            .get_file_metadata(space_id, file_id)
            .await
            .expect("get metadata");
        assert_eq!(metadata.wrapped_dek, new_dek);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn rewrap_file_deks_epoch_mismatch() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;
        let file_id = uuid::Uuid::new_v4();

        storage
            .record_file(
                space_id,
                file_id,
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xaa),
            )
            .await
            .expect("record file");

        sqlx::query("UPDATE spaces SET key_generation = 2 WHERE id = $1")
            .bind(space_id)
            .execute(storage.pool())
            .await
            .expect("advance key generation");

        let error = storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: file_id,
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xcc),
                    cursor: 0,
                }],
            )
            .await
            .expect_err("epoch mismatch should fail");
        assert_eq!(error, StorageError::DekEpochMismatch);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn rewrap_file_deks_missing_file() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .rewrap_file_deks(
                space_id,
                &[FileDekRecord {
                    id: uuid::Uuid::new_v4(),
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xcc),
                    cursor: 0,
                }],
            )
            .await
            .expect_err("missing file should fail");
        assert_eq!(error, StorageError::FileDekNotFound);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn rewrap_file_deks_empty_is_noop() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        storage
            .rewrap_file_deks(space_id, &[])
            .await
            .expect("empty rewrap should succeed");

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn delete_files_for_records_deletes_and_returns_ids() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let file_a = uuid::Uuid::new_v4();
        let file_b = uuid::Uuid::new_v4();
        storage
            .record_file(space_id, file_a, record_id, 100, &wrapped_dek(0xaa))
            .await
            .expect("record file a");
        storage
            .record_file(space_id, file_b, record_id, 200, &wrapped_dek(0xbb))
            .await
            .expect("record file b");

        let deleted = storage
            .delete_files_for_records(space_id, &[record_id])
            .await
            .expect("delete files");
        let deleted_set = deleted.into_iter().collect::<HashSet<_>>();
        assert_eq!(deleted_set.len(), 2);
        assert!(deleted_set.contains(&file_a));
        assert!(deleted_set.contains(&file_b));

        let exists_a = storage
            .file_exists(space_id, file_a)
            .await
            .expect("exists a");
        let exists_b = storage
            .file_exists(space_id, file_b)
            .await
            .expect("exists b");
        assert!(!exists_a);
        assert!(!exists_b);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn delete_files_for_records_empty_returns_empty() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let deleted = storage
            .delete_files_for_records(space_id, &[])
            .await
            .expect("empty delete");
        assert!(deleted.is_empty());

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn revoke_ucan_roundtrip_and_space_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;
        let ucan_cid = "bafy-test-cid-1";

        let initial = storage
            .is_revoked(space_a, ucan_cid)
            .await
            .expect("is revoked before insert");
        assert!(!initial);

        storage
            .revoke_ucan(space_a, ucan_cid)
            .await
            .expect("first revoke");
        storage
            .revoke_ucan(space_a, ucan_cid)
            .await
            .expect("idempotent revoke");

        let revoked_a = storage
            .is_revoked(space_a, ucan_cid)
            .await
            .expect("is revoked for space a");
        let revoked_b = storage
            .is_revoked(space_b, ucan_cid)
            .await
            .expect("is revoked for space b");
        assert!(revoked_a);
        assert!(!revoked_b);

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn invitation_crud_and_mailbox_scope() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let mailbox_a = mailbox_id();
        let mailbox_b = mailbox_id();

        storage
            .create_invitation(&invitation_input(&mailbox_a, b"encrypted-payload"))
            .await
            .expect("create invitation");

        let list_a = storage
            .list_invitations(&mailbox_a, 10, None)
            .await
            .expect("list mailbox a");
        assert_eq!(list_a.len(), 1);
        assert!(list_a[0].expires_at > list_a[0].created_at);

        let list_b = storage
            .list_invitations(&mailbox_b, 10, None)
            .await
            .expect("list mailbox b");
        assert!(list_b.is_empty());

        let invitation_id = list_a[0].id;
        let got = storage
            .get_invitation(invitation_id, &mailbox_a)
            .await
            .expect("get invitation");
        assert_eq!(got.mailbox_id, mailbox_a);
        assert_eq!(got.payload, b"encrypted-payload");

        let wrong_mailbox = storage
            .get_invitation(invitation_id, &mailbox_b)
            .await
            .expect_err("wrong mailbox get should fail");
        assert_eq!(wrong_mailbox, StorageError::InvitationNotFound);

        let wrong_delete = storage
            .delete_invitation(invitation_id, &mailbox_b)
            .await
            .expect_err("wrong mailbox delete should fail");
        assert_eq!(wrong_delete, StorageError::InvitationNotFound);

        storage
            .delete_invitation(invitation_id, &mailbox_a)
            .await
            .expect("delete invitation");
        let after_delete = storage
            .get_invitation(invitation_id, &mailbox_a)
            .await
            .expect_err("deleted invitation should not be found");
        assert_eq!(after_delete, StorageError::InvitationNotFound);
    }

    #[tokio::test]
    async fn list_invitations_pagination_and_expiry() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let mailbox = mailbox_id();

        storage
            .create_invitation(&invitation_input(&mailbox, b"p1"))
            .await
            .expect("create invitation 1");
        storage
            .create_invitation(&invitation_input(&mailbox, b"p2"))
            .await
            .expect("create invitation 2");
        storage
            .create_invitation(&invitation_input(&mailbox, b"p3"))
            .await
            .expect("create invitation 3");

        let created = storage
            .list_invitations(&mailbox, 10, None)
            .await
            .expect("list created invitations");
        assert_eq!(created.len(), 3);
        let expired_id = created[1].id;

        sqlx::query(
            "UPDATE invitations SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(expired_id)
        .execute(storage.pool())
        .await
        .expect("expire invitation");

        let list = storage
            .list_invitations(&mailbox, 10, None)
            .await
            .expect("list non-expired");
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|inv| inv.id != expired_id));

        let get_expired = storage
            .get_invitation(expired_id, &mailbox)
            .await
            .expect_err("expired invitation should not be found");
        assert_eq!(get_expired, StorageError::InvitationNotFound);

        let page1 = storage
            .list_invitations(&mailbox, 1, None)
            .await
            .expect("list page 1");
        assert_eq!(page1.len(), 1);
        let page2 = storage
            .list_invitations(&mailbox, 10, Some(page1[0].id))
            .await
            .expect("list page 2");
        assert_eq!(page2.len(), 1);
        assert_ne!(page2[0].id, page1[0].id);

        let purged = storage
            .purge_expired_invitations()
            .await
            .expect("purge expired invitations");
        assert!(purged >= 1);
    }

    #[tokio::test]
    async fn list_invitations_cursor_edge_cases() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let mailbox_a = mailbox_id();
        let mailbox_b = mailbox_id();

        storage
            .create_invitation(&invitation_input(&mailbox_a, b"a1"))
            .await
            .expect("create a1");
        storage
            .create_invitation(&invitation_input(&mailbox_a, b"a2"))
            .await
            .expect("create a2");
        storage
            .create_invitation(&invitation_input(&mailbox_b, b"b1"))
            .await
            .expect("create b1");

        let b = storage
            .list_invitations(&mailbox_b, 10, None)
            .await
            .expect("list b");
        assert_eq!(b.len(), 1);
        let wrong_cursor = storage
            .list_invitations(&mailbox_a, 10, Some(b[0].id))
            .await
            .expect("wrong-mailbox cursor");
        assert!(wrong_cursor.is_empty());

        let missing_cursor = storage
            .list_invitations(&mailbox_a, 10, Some(uuid::Uuid::new_v4()))
            .await
            .expect("missing cursor");
        assert!(missing_cursor.is_empty());

        let zero_limit = storage
            .list_invitations(&mailbox_a, 0, None)
            .await
            .expect("zero limit");
        assert!(zero_limit.is_empty());
    }

    #[tokio::test]
    async fn rate_limit_actions_lifecycle() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let action = format!("invitation-{}", uuid::Uuid::new_v4());
        let other_action = format!("membership-{}", uuid::Uuid::new_v4());
        let actor_a = "actor-hash-a";
        let actor_b = "actor-hash-b";

        storage
            .record_action(&action, actor_a)
            .await
            .expect("record action #1");
        storage
            .record_action(&action, actor_a)
            .await
            .expect("record action #2");
        storage
            .record_action(&action, actor_b)
            .await
            .expect("record action #3");
        storage
            .record_action(&other_action, actor_a)
            .await
            .expect("record action #4");

        let since_past = SystemTime::now() - Duration::from_secs(3600);
        let count_a = storage
            .count_recent_actions(&action, actor_a, since_past)
            .await
            .expect("count actor a");
        let count_b = storage
            .count_recent_actions(&action, actor_b, since_past)
            .await
            .expect("count actor b");
        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);

        let since_future = SystemTime::now() + Duration::from_secs(60);
        let count_future = storage
            .count_recent_actions(&action, actor_a, since_future)
            .await
            .expect("count future");
        assert_eq!(count_future, 0);

        sqlx::query(
            "UPDATE rate_limit_actions SET created_at = NOW() - INTERVAL '2 hours' WHERE action = $1 OR action = $2",
        )
        .bind(&action)
        .bind(&other_action)
        .execute(storage.pool())
        .await
        .expect("age action rows");

        let removed = storage
            .cleanup_expired_actions(SystemTime::now() - Duration::from_secs(3600))
            .await
            .expect("cleanup expired actions");
        assert!(removed >= 4);

        let count_after = storage
            .count_recent_actions(&action, actor_a, since_past)
            .await
            .expect("count after cleanup");
        assert_eq!(count_after, 0);
    }

    #[tokio::test]
    async fn space_home_server_roundtrip() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let before = storage
            .get_space_home_server(space_id)
            .await
            .expect("get home server");
        assert_eq!(before, None);

        storage
            .set_space_home_server(space_id, "https://example.test")
            .await
            .expect("set home server");
        let after = storage
            .get_space_home_server(space_id)
            .await
            .expect("get updated home server");
        assert_eq!(after.as_deref(), Some("https://example.test"));

        let missing_get = storage
            .get_space_home_server(uuid::Uuid::new_v4())
            .await
            .expect_err("missing space get should fail");
        assert_eq!(missing_get, StorageError::SpaceNotFound);
        let missing_set = storage
            .set_space_home_server(uuid::Uuid::new_v4(), "https://missing.test")
            .await
            .expect_err("missing space set should fail");
        assert_eq!(missing_set, StorageError::SpaceNotFound);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn federation_keys_rotation_keeps_overlap_window_and_promotes_new_primary() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing = storage
            .get_federation_private_key("fed-missing")
            .await
            .expect_err("missing key should fail");
        assert_eq!(missing, StorageError::FederationKeyNotFound);

        let kid_a = format!("fed-{}", uuid::Uuid::new_v4());
        let kid_b = format!("fed-{}", uuid::Uuid::new_v4());
        let private_a = b"test-private-key-seed-32-bytes!!".to_vec();
        let public_a = b"test-public-key-32-bytes-here!!!".to_vec();
        let private_b = b"second-seed-32-bytes-long!!!!!!".to_vec();
        let public_b = b"second-pub-key-32-bytes-long!!!".to_vec();

        storage
            .ensure_federation_key(&kid_a, &private_a, &public_a)
            .await
            .expect("ensure key a");
        let primary_a = storage
            .get_federation_signing_key()
            .await
            .expect("get primary key a")
            .expect("primary key a exists");
        assert_eq!(primary_a.kid, kid_a);
        assert_eq!(primary_a.private_key, private_a);
        assert_eq!(primary_a.public_key, public_a);

        storage
            .ensure_federation_key(&kid_a, b"different-seed-32-bytes-long!!!!", &public_a)
            .await
            .expect("ensure key a idempotent");
        let got_again = storage
            .get_federation_private_key(&kid_a)
            .await
            .expect("get key a again");
        assert_eq!(got_again, private_a);

        storage
            .ensure_federation_key(&kid_b, &private_b, &public_b)
            .await
            .expect("ensure key b");

        storage
            .set_federation_primary_key(&kid_b)
            .await
            .expect("promote key b");
        let primary_b = storage
            .get_federation_signing_key()
            .await
            .expect("get promoted key b")
            .expect("promoted key b exists");
        assert_eq!(primary_b.kid, kid_b);
        assert_eq!(primary_b.private_key, private_b);
        assert_eq!(primary_b.public_key, public_b);

        // Rotation overlap window: previously active keys remain in JWKS until deactivated.
        let keys = storage
            .list_federation_public_keys()
            .await
            .expect("list federation keys");
        let key_a = keys.iter().find(|key| key.kid == kid_a).cloned();
        let key_b = keys.iter().find(|key| key.kid == kid_b).cloned();
        assert!(key_a.is_some());
        assert!(key_b.is_some());
        assert_eq!(key_a.expect("key a").public_key, public_a);
        assert_eq!(key_b.expect("key b").public_key, public_b);

        storage
            .deactivate_federation_key(&kid_a)
            .await
            .expect("deactivate old key a");
        let active_keys = storage
            .list_federation_public_keys()
            .await
            .expect("list active federation keys");
        assert_eq!(active_keys.len(), 1);
        assert_eq!(active_keys[0].kid, kid_b);
    }

    #[tokio::test]
    async fn federation_key_primary_and_deactivate_validate_target_kid() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let missing_primary = storage
            .set_federation_primary_key("fed-missing")
            .await
            .expect_err("promoting missing key should fail");
        assert_eq!(missing_primary, StorageError::FederationKeyNotFound);

        let missing_deactivate = storage
            .deactivate_federation_key("fed-missing")
            .await
            .expect_err("deactivating missing key should fail");
        assert_eq!(missing_deactivate, StorageError::FederationKeyNotFound);
    }

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
    async fn advance_epoch_conflict_and_rewrap_flow() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let advanced = storage
            .advance_epoch(space_id, 2, None)
            .await
            .expect("advance to epoch 2");
        assert_eq!(advanced.epoch, 2);

        let conflict = storage
            .advance_epoch(space_id, 3, None)
            .await
            .expect_err("advance while rewrap pending should fail");
        match conflict {
            StorageError::EpochConflict(EpochConflict {
                current_epoch,
                rewrap_epoch,
            }) => {
                assert_eq!(current_epoch, 2);
                assert_eq!(rewrap_epoch, Some(2));
            }
            other => panic!("expected epoch conflict, got {other:?}"),
        }

        storage
            .complete_rewrap(space_id, 2)
            .await
            .expect("complete rewrap");
        storage
            .advance_epoch(space_id, 3, None)
            .await
            .expect("advance to epoch 3");

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn advance_epoch_sets_min_generation_and_handles_mismatch() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let mismatch = storage
            .advance_epoch(space_id, 3, None)
            .await
            .expect_err("skip-epoch advance should fail");
        match mismatch {
            StorageError::EpochConflict(EpochConflict {
                current_epoch,
                rewrap_epoch,
            }) => {
                assert_eq!(current_epoch, 1);
                assert_eq!(rewrap_epoch, None);
            }
            other => panic!("expected epoch conflict, got {other:?}"),
        }

        storage
            .advance_epoch(
                space_id,
                2,
                Some(&AdvanceEpochOptions {
                    set_min_key_generation: true,
                }),
            )
            .await
            .expect("advance with set_min_key_generation");
        let space = storage.get_space(space_id).await.expect("get space");
        assert_eq!(space.min_key_generation, 2);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn complete_rewrap_validates_epoch_and_space_existence() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let no_rewrap_error = storage
            .complete_rewrap(space_id, 1)
            .await
            .expect_err("completing absent rewrap should fail");
        assert_eq!(no_rewrap_error, StorageError::EpochMismatch);

        storage
            .advance_epoch(space_id, 2, None)
            .await
            .expect("advance epoch");
        let wrong_epoch = storage
            .complete_rewrap(space_id, 3)
            .await
            .expect_err("wrong epoch should fail");
        assert_eq!(wrong_epoch, StorageError::EpochMismatch);

        storage
            .complete_rewrap(space_id, 2)
            .await
            .expect("complete matching epoch");
        let space = storage.get_space(space_id).await.expect("get space");
        assert_eq!(space.rewrap_epoch, None);

        let missing_error = storage
            .complete_rewrap(uuid::Uuid::new_v4(), 2)
            .await
            .expect_err("missing space should fail");
        assert_eq!(missing_error, StorageError::SpaceNotFound);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn get_deks_and_rewrap_deks_epoch_validation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id =
            create_record_with_dek(&storage, space_id, wrapped_dek_with_epoch(1, 0xaa)).await;

        let initial = storage
            .get_deks(space_id, 0)
            .await
            .expect("get initial DEKs");
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].id, record_id.to_string());

        storage
            .advance_epoch(space_id, 2, None)
            .await
            .expect("advance epoch");

        let wrong_epoch = storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: record_id.to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(1, 0xbb),
                    cursor: 0,
                }],
            )
            .await
            .expect_err("wrong DEK epoch should fail");
        assert_eq!(wrong_epoch, StorageError::DekEpochMismatch);

        let invalid_id = storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: "not-a-uuid".to_owned(),
                    wrapped_dek: wrapped_dek_with_epoch(2, 0xbb),
                    cursor: 0,
                }],
            )
            .await
            .expect_err("invalid record id should fail");
        assert_eq!(invalid_id, StorageError::InvalidRecordId);

        storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: record_id.to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(2, 0xcc),
                    cursor: 0,
                }],
            )
            .await
            .expect("rewrap with matching epoch");
        let updated = storage
            .get_deks(space_id, 0)
            .await
            .expect("get updated DEKs");
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].wrapped_dek, wrapped_dek_with_epoch(2, 0xcc));

        let missing_record = storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(2, 0xdd),
                    cursor: 0,
                }],
            )
            .await
            .expect_err("missing record should fail");
        assert_eq!(missing_record, StorageError::DekRecordNotFound);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn stream_pull_returns_unified_ordered_entries() {
        use std::sync::Mutex;

        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id = create_record(&storage, space_id).await;

        let member_hash = vec![0x77; 32];
        storage
            .append_member(
                space_id,
                0,
                &member_entry(&[], &member_hash, b"member-entry"),
            )
            .await
            .expect("append member");
        storage
            .record_file(
                space_id,
                uuid::Uuid::new_v4(),
                record_id,
                100,
                &wrapped_dek_with_epoch(1, 0xee),
            )
            .await
            .expect("record file");

        let meta = Mutex::new(None::<PullStreamMeta>);
        let entries = Mutex::new(Vec::<PullEntry>::new());
        storage
            .stream_pull(
                space_id,
                0,
                &|value| {
                    *meta.lock().expect("lock meta") = Some(value);
                    Ok(())
                },
                &|entry| {
                    entries.lock().expect("lock entries").push(entry);
                    Ok(())
                },
            )
            .await
            .expect("stream pull");

        let meta = meta.lock().expect("lock meta").clone().expect("meta");
        assert_eq!(meta.key_generation, 1);
        assert_eq!(meta.rewrap_epoch, None);

        let entries = entries.lock().expect("lock entries").clone();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, crate::PullEntryKind::Record);
        assert_eq!(entries[1].kind, crate::PullEntryKind::Membership);
        assert_eq!(entries[2].kind, crate::PullEntryKind::File);
        assert!(entries[0].cursor < entries[1].cursor);
        assert!(entries[1].cursor < entries[2].cursor);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn storage_trait_dispatch_smoke() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let backend: &dyn Storage = &storage;
        let space_id = uuid::Uuid::new_v4();

        backend
            .create_space(space_id, "client-trait", None)
            .await
            .expect("create via trait");
        let fetched = backend.get_space(space_id).await.expect("get via trait");
        assert_eq!(fetched.id, space_id.to_string());
        assert_eq!(fetched.client_id, "client-trait");

        cleanup_space(&storage, space_id).await;
    }

    // =========================================================================
    // Push validation tests (ported from Go)
    // =========================================================================

    #[tokio::test]
    async fn push_space_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let error = storage
            .push(
                uuid::Uuid::new_v4(),
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"hello"),
                    0,
                )],
                None,
            )
            .await
            .expect_err("push to missing space should fail");
        assert_eq!(error, StorageError::SpaceNotFound);
    }

    #[tokio::test]
    async fn push_invalid_record_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .push(space_id, &[change("invalid-id", Some(b"data"), 0)], None)
            .await
            .expect_err("invalid record ID should fail");
        assert_eq!(error, StorageError::InvalidRecordId);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_blob_too_large() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let large_blob =
            vec![0u8; (less_sync_core::validation::DEFAULT_MAX_BLOB_SIZE + 1) as usize];
        let error = storage
            .push(
                space_id,
                &[Change {
                    id: "019400e8-7b5d-7000-8000-000000000001".to_owned(),
                    blob: Some(large_blob),
                    cursor: 0,
                    wrapped_dek: None,
                    deleted: false,
                }],
                None,
            )
            .await
            .expect_err("oversized blob should fail");
        assert_eq!(error, StorageError::BlobTooLarge);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_duplicate_record_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let error = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"first"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"second"), 0),
                ],
                None,
            )
            .await
            .expect_err("duplicate record ID should fail");
        assert_eq!(error, StorageError::DuplicateRecordId);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_empty_changes() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage
            .push(space_id, &[], None)
            .await
            .expect("empty push should succeed");
        assert!(result.ok);
        assert_eq!(result.cursor, 0);

        cleanup_space(&storage, space_id).await;
    }

    // =========================================================================
    // Push conflict tests (ported from Go)
    // =========================================================================

    #[tokio::test]
    async fn push_conflict_record_modified() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let id = "019400e8-7b5d-7000-8000-000000000001";

        // Create record
        storage
            .push(space_id, &[change(id, Some(b"v1"), 0)], None)
            .await
            .expect("create");

        // Update record
        storage
            .push(space_id, &[change(id, Some(b"v2"), 1)], None)
            .await
            .expect("update");

        // Try to update with old cursor
        let result = storage
            .push(space_id, &[change(id, Some(b"v3"), 1)], None)
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_record_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Try to update a record that doesn't exist (cursor > 0 implies update)
        let result = storage
            .push(
                space_id,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"v1"),
                    5,
                )],
                None,
            )
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_conflict_with_tombstone() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let id = "019400e8-7b5d-7000-8000-000000000001";

        // Create record
        storage
            .push(space_id, &[change(id, Some(b"data"), 0)], None)
            .await
            .expect("create");

        // Delete record (tombstone)
        storage
            .push(space_id, &[change(id, None, 1)], None)
            .await
            .expect("tombstone");

        // Try to create "new" record with same ID (cursor=0) — should conflict
        let result = storage
            .push(space_id, &[change(id, Some(b"new data"), 0)], None)
            .await
            .expect("conflict push");
        assert!(!result.ok);

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_all_or_nothing() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Create a record
        storage
            .push(
                space_id,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"v1"),
                    0,
                )],
                None,
            )
            .await
            .expect("create first record");

        // Try to push: one valid new record + one conflicting
        let result = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"new"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"bad"), 0),
                ],
                None,
            )
            .await
            .expect("conflict push");
        assert!(!result.ok);

        // Verify the new record was NOT created (all-or-nothing)
        let pull_result = storage.pull(space_id, 0).await.expect("pull");
        assert_eq!(pull_result.records().len(), 1);
        assert_eq!(
            pull_result.records()[0].id,
            "019400e8-7b5d-7000-8000-000000000001"
        );

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_multiple_records_same_sequence() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let result = storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"a"), 0),
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"b"), 0),
                    change("019400e8-7b5d-7000-8000-000000000003", Some(b"c"), 0),
                ],
                None,
            )
            .await
            .expect("push multiple");
        assert!(result.ok);
        assert_eq!(result.cursor, 1);

        let pull_result = storage.pull(space_id, 0).await.expect("pull");
        assert_eq!(pull_result.records().len(), 3);
        for record in pull_result.records() {
            assert_eq!(record.cursor, 1);
        }

        cleanup_space(&storage, space_id).await;
    }

    #[tokio::test]
    async fn push_tombstone_deletes_files() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Push a live record with a wrapped DEK
        let record_id = uuid::Uuid::new_v4();
        let record_id_str = record_id.to_string();
        let dek = wrapped_dek(0xdd);
        storage
            .push(
                space_id,
                &[Change {
                    id: record_id_str.clone(),
                    blob: Some(b"data".to_vec()),
                    cursor: 0,
                    wrapped_dek: Some(dek.clone()),
                    deleted: false,
                }],
                None,
            )
            .await
            .expect("push live record");

        // Upload a file for the record
        let file_id = uuid::Uuid::new_v4();
        let file_dek = wrapped_dek(0xfe);
        storage
            .record_file(space_id, file_id, record_id, 100, &file_dek)
            .await
            .expect("record file");

        // Push tombstone
        let result = storage
            .push(
                space_id,
                &[Change {
                    id: record_id_str,
                    blob: None,
                    cursor: 1,
                    wrapped_dek: Some(dek),
                    deleted: false,
                }],
                None,
            )
            .await
            .expect("push tombstone");
        assert!(result.ok);
        assert_eq!(result.deleted_file_ids.len(), 1);
        assert_eq!(result.deleted_file_ids[0], file_id);

        // Verify file is gone
        let exists = storage
            .file_exists(space_id, file_id)
            .await
            .expect("file exists");
        assert!(!exists);

        cleanup_space(&storage, space_id).await;
    }

    // =========================================================================
    // Space isolation and pull ordering tests (ported from Go)
    // =========================================================================

    #[tokio::test]
    async fn space_isolation() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_a = uuid::Uuid::new_v4();
        let space_b = uuid::Uuid::new_v4();
        create_space(&storage, space_a).await;
        create_space(&storage, space_b).await;

        storage
            .push(
                space_a,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000001",
                    Some(b"space a data"),
                    0,
                )],
                None,
            )
            .await
            .expect("push to space a");
        storage
            .push(
                space_b,
                &[change(
                    "019400e8-7b5d-7000-8000-000000000002",
                    Some(b"space b data"),
                    0,
                )],
                None,
            )
            .await
            .expect("push to space b");

        let pull_a = storage.pull(space_a, 0).await.expect("pull space a");
        let pull_b = storage.pull(space_b, 0).await.expect("pull space b");

        assert_eq!(pull_a.records().len(), 1);
        assert_eq!(pull_b.records().len(), 1);
        assert_eq!(pull_a.records()[0].blob, Some(b"space a data".to_vec()));
        assert_eq!(pull_b.records()[0].blob, Some(b"space b data".to_vec()));

        cleanup_space(&storage, space_a).await;
        cleanup_space(&storage, space_b).await;
    }

    #[tokio::test]
    async fn pull_order_by_sequence_then_id() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        // Push records with IDs in non-sorted order; all at cursor=0 (same sequence)
        storage
            .push(
                space_id,
                &[
                    change("019400e8-7b5d-7000-8000-000000000003", Some(b"z"), 0),
                    change("019400e8-7b5d-7000-8000-000000000001", Some(b"a"), 0),
                    change("019400e8-7b5d-7000-8000-000000000002", Some(b"m"), 0),
                ],
                None,
            )
            .await
            .expect("push");

        let result = storage.pull(space_id, 0).await.expect("pull");
        let records = result.records();
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "019400e8-7b5d-7000-8000-000000000001",
                "019400e8-7b5d-7000-8000-000000000002",
                "019400e8-7b5d-7000-8000-000000000003",
            ]
        );

        cleanup_space(&storage, space_id).await;
    }

    // =========================================================================
    // Members tests (ported from Go)
    // =========================================================================

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

    // =========================================================================
    // Epoch tests (ported from Go)
    // =========================================================================

    #[tokio::test]
    async fn advance_epoch_space_not_found() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let error = storage
            .advance_epoch(uuid::Uuid::new_v4(), 2, None)
            .await
            .expect_err("advance on missing space should fail");
        assert_eq!(error, StorageError::SpaceNotFound);
    }
}
