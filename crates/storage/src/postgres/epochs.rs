use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{
    AdvanceEpochOptions, AdvanceEpochResult, DekRecord, EpochConflict, EpochStorage, StorageError,
};

#[async_trait]
impl EpochStorage for PostgresStorage {
    async fn advance_epoch(
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

    async fn complete_rewrap(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
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

    async fn get_deks(&self, space_id: Uuid, since: i64) -> Result<Vec<DekRecord>, StorageError> {
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

    async fn rewrap_deks(&self, space_id: Uuid, deks: &[DekRecord]) -> Result<(), StorageError> {
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
            let epoch =
                super::parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
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

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use crate::{
        AdvanceEpochOptions, DekRecord, EpochConflict, EpochStorage, SpaceStorage, StorageError,
    };

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
    }

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
