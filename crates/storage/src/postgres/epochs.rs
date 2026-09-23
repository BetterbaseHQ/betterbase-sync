use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{
    AdvanceEpochOptions, AdvanceEpochResult, DekRecord, EpochConflict, EpochKeyShare, EpochStorage,
    StorageError,
};

#[async_trait]
impl EpochStorage for PostgresStorage {
    async fn advance_epoch(
        &self,
        space_id: Uuid,
        requested_epoch: i32,
        opts: Option<&AdvanceEpochOptions>,
    ) -> Result<AdvanceEpochResult, StorageError> {
        let set_min = opts.is_some_and(|value| value.set_min_epoch);
        let result = if set_min {
            sqlx::query(
                "UPDATE spaces SET epoch = $1, rewrap_epoch = $1, min_epoch = $1 WHERE id = $2 AND epoch = $3 AND rewrap_epoch IS NULL",
            )
            .bind(requested_epoch)
            .bind(space_id)
            .bind(requested_epoch - 1)
            .execute(&self.pool)
            .await
        } else {
            sqlx::query(
                "UPDATE spaces SET epoch = $1, rewrap_epoch = $1 WHERE id = $2 AND epoch = $3 AND rewrap_epoch IS NULL",
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
                "SELECT epoch, rewrap_epoch FROM spaces WHERE id = $1",
            )
            .bind(space_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;
            return Err(StorageError::EpochConflict(EpochConflict {
                current_epoch: state.epoch,
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
                observed_wrapped_dek: None,
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

        let epoch: i32 = sqlx::query_scalar("SELECT epoch FROM spaces WHERE id = $1 FOR UPDATE")
            .bind(space_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(|error| match error {
                sqlx::Error::RowNotFound => StorageError::SpaceNotFound,
                _ => StorageError::Database(error.to_string()),
            })?;

        for dek in deks {
            let dek_epoch =
                super::parse_dek_epoch(&dek.wrapped_dek).ok_or(StorageError::DekEpochMismatch)?;
            if dek_epoch != epoch {
                return Err(StorageError::DekEpochMismatch);
            }

            let record_id = Uuid::parse_str(&dek.id).map_err(|_| StorageError::InvalidRecordId)?;
            // Compare-and-set: when the client reports the wrapper it observed,
            // only replace a wrapper that is still that value. A concurrent
            // push installs a fresh random DEK; overwriting its wrapper with a
            // rewrap of the stale one would make the record undecryptable
            // (AUD-026).
            let result = sqlx::query(
                "UPDATE records SET wrapped_dek = $1 \
                 WHERE id = $2 AND space_id = $3 \
                 AND ($4::bytea IS NULL OR wrapped_dek = $4)",
            )
            .bind(&dek.wrapped_dek)
            .bind(record_id)
            .bind(space_id)
            .bind(&dek.observed_wrapped_dek)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
            if result.rows_affected() != 1 {
                return Err(match dek.observed_wrapped_dek {
                    Some(_) => StorageError::DekConflict,
                    None => StorageError::DekRecordNotFound,
                });
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn put_epoch_key_shares(
        &self,
        space_id: Uuid,
        epoch: i32,
        shares: &[EpochKeyShare],
    ) -> Result<(), StorageError> {
        if shares.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        // Replace any prior shares for this epoch (rotation restart after an
        // aborted attempt issues a different fresh key).
        sqlx::query("DELETE FROM epoch_keys WHERE space_id = $1 AND epoch = $2")
            .bind(space_id)
            .bind(epoch)
            .execute(tx.as_mut())
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;

        for share in shares {
            let result =
                sqlx::query("INSERT INTO epoch_keys (space_id, epoch, member_did, wrapped_key) VALUES ($1, $2, $3, $4)")
                    .bind(space_id)
                    .bind(epoch)
                    .bind(&share.member_did)
                    .bind(&share.wrapped_key)
                    .execute(tx.as_mut())
                    .await
                    .map_err(|error| StorageError::Database(error.to_string()))?;
            if result.rows_affected() != 1 {
                return Err(StorageError::Database(
                    "epoch key share insert failed".into(),
                ));
            }
        }

        tx.commit()
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }

    async fn get_epoch_key_share(
        &self,
        space_id: Uuid,
        epoch: i32,
        member_did: &str,
    ) -> Result<Vec<u8>, StorageError> {
        let row = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT wrapped_key FROM epoch_keys WHERE space_id = $1 AND epoch = $2 AND member_did = $3",
        )
        .bind(space_id)
        .bind(epoch)
        .bind(member_did)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| StorageError::Database(error.to_string()))?;

        row.ok_or(StorageError::EpochKeyShareNotFound)
    }

    async fn prune_epoch_key_shares(&self, space_id: Uuid, epoch: i32) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM epoch_keys WHERE space_id = $1 AND epoch <= $2")
            .bind(space_id)
            .bind(epoch)
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct EpochStateRow {
    epoch: i32,
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
                    set_min_epoch: true,
                }),
            )
            .await
            .expect("advance with set_min_epoch");
        let space = storage.get_space(space_id).await.expect("get space");
        assert_eq!(space.min_epoch, 2);
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
                    observed_wrapped_dek: None,
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
                    observed_wrapped_dek: None,
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
                    observed_wrapped_dek: None,
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
                    observed_wrapped_dek: None,
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

#[cfg(test)]
mod cas_tests {
    use super::super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn rewrap_with_stale_observed_wrapped_dek_is_rejected() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;
        let record_id =
            create_record_with_dek(&storage, space_id, wrapped_dek_with_epoch(1, 0xaa)).await;
        storage
            .advance_epoch(space_id, 2, None)
            .await
            .expect("advance epoch");

        // The rewrapper read the old wrapper...
        let observed = wrapped_dek_with_epoch(1, 0xaa);
        // ...but a concurrent writer already replaced it with a fresh DEK.
        let concurrent = wrapped_dek_with_epoch(2, 0x99);
        sqlx::query("UPDATE records SET wrapped_dek = $1 WHERE id = $2")
            .bind(&concurrent)
            .bind(record_id)
            .execute(storage.pool())
            .await
            .expect("simulate concurrent replacement");

        // A stale rewrap must not overwrite the newer wrapper (AUD-026).
        let stale = storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: record_id.to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(2, 0xbb),
                    cursor: 0,
                    observed_wrapped_dek: Some(observed),
                }],
            )
            .await
            .expect_err("stale observed DEK must fail");
        assert_eq!(stale, StorageError::DekConflict);

        // The concurrently installed wrapper is intact.
        let current = storage.get_deks(space_id, 0).await.expect("get DEKs");
        assert_eq!(current[0].wrapped_dek, concurrent);

        // A rewrap carrying the up-to-date observation still succeeds.
        storage
            .rewrap_deks(
                space_id,
                &[DekRecord {
                    id: record_id.to_string(),
                    wrapped_dek: wrapped_dek_with_epoch(2, 0xcc),
                    cursor: 0,
                    observed_wrapped_dek: Some(concurrent),
                }],
            )
            .await
            .expect("rewrap with current observation");
        let updated = storage.get_deks(space_id, 0).await.expect("get DEKs");
        assert_eq!(updated[0].wrapped_dek, wrapped_dek_with_epoch(2, 0xcc));
    }
}

#[cfg(test)]
mod epoch_key_share_tests {
    use super::super::test_support::*;
    use super::*;

    use crate::EpochKeyShare;

    #[tokio::test]
    async fn epoch_key_shares_roundtrip_and_replace() {
        let Some(storage) = test_storage().await else {
            return;
        };
        let space_id = uuid::Uuid::new_v4();
        create_space(&storage, space_id).await;

        let shares = vec![
            EpochKeyShare {
                member_did: "did:key:alice".to_owned(),
                wrapped_key: vec![1, 2, 3],
            },
            EpochKeyShare {
                member_did: "did:key:bob".to_owned(),
                wrapped_key: vec![4, 5, 6],
            },
        ];
        storage
            .put_epoch_key_shares(space_id, 2, &shares)
            .await
            .expect("put shares");

        // Each member reads only their own share.
        assert_eq!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:alice")
                .await
                .expect("alice share"),
            vec![1, 2, 3],
        );
        assert_eq!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:bob")
                .await
                .expect("bob share"),
            vec![4, 5, 6],
        );
        // No cross-member reads, and no shares for unknown epochs.
        assert!(matches!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:eve")
                .await
                .unwrap_err(),
            StorageError::EpochKeyShareNotFound
        ));
        assert!(matches!(
            storage
                .get_epoch_key_share(space_id, 3, "did:key:alice")
                .await
                .unwrap_err(),
            StorageError::EpochKeyShareNotFound
        ));

        // Re-putting for the same epoch replaces (rotation restart).
        let replacement = vec![EpochKeyShare {
            member_did: "did:key:alice".to_owned(),
            wrapped_key: vec![9, 9, 9],
        }];
        storage
            .put_epoch_key_shares(space_id, 2, &replacement)
            .await
            .expect("replace shares");
        assert_eq!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:alice")
                .await
                .expect("replaced share"),
            vec![9, 9, 9],
        );
        // Bob's share from the aborted attempt is gone.
        assert!(matches!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:bob")
                .await
                .unwrap_err(),
            StorageError::EpochKeyShareNotFound
        ));

        // Pruning clears shares at or below an epoch.
        storage
            .prune_epoch_key_shares(space_id, 2)
            .await
            .expect("prune");
        assert!(matches!(
            storage
                .get_epoch_key_share(space_id, 2, "did:key:alice")
                .await
                .unwrap_err(),
            StorageError::EpochKeyShareNotFound
        ));
    }
}
