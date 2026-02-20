use async_trait::async_trait;
use uuid::Uuid;

use super::PostgresStorage;
use crate::{Invitation, InvitationStorage, StorageError};

#[async_trait]
impl InvitationStorage for PostgresStorage {
    async fn create_invitation(&self, invitation: &Invitation) -> Result<Invitation, StorageError> {
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

    async fn list_invitations(
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

    async fn get_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<Invitation, StorageError> {
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

    async fn delete_invitation(&self, id: Uuid, mailbox_id: &str) -> Result<(), StorageError> {
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

    async fn purge_expired_invitations(&self) -> Result<i64, StorageError> {
        let result = sqlx::query("DELETE FROM invitations WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Database(error.to_string()))?;
        Ok(result.rows_affected() as i64)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    mailbox_id: String,
    payload: Vec<u8>,
    created_at_us: i64,
    expires_at_us: i64,
}

impl TryFrom<InvitationRow> for Invitation {
    type Error = StorageError;

    fn try_from(value: InvitationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            mailbox_id: value.mailbox_id,
            payload: value.payload,
            created_at: super::unix_micros_to_system_time(value.created_at_us)?,
            expires_at: super::unix_micros_to_system_time(value.expires_at_us)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use crate::{InvitationStorage, StorageError};

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
}
