#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::permission::{ParsePermissionError, Permission};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_VERSION: u8 = 1;
pub const SESSION_TOKEN_LENGTH: usize = 1 + 8 + 1 + 16 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    pub space_id: String,
    pub permission: Permission,
    pub expires_at: SystemTime,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("invalid session token")]
    InvalidSession,
    #[error("session token expired")]
    SessionExpired,
    #[error("session HMAC key must be 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("session expiry before unix epoch")]
    ExpiryBeforeUnixEpoch,
    #[error("session expiry is out of range")]
    ExpiryOutOfRange,
    #[error("invalid session permission: {0}")]
    InvalidPermission(#[from] ParsePermissionError),
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    key: [u8; 32],
    ttl: Duration,
}

impl SessionManager {
    #[must_use]
    pub fn new(key: [u8; 32], ttl: Duration) -> Self {
        Self { key, ttl }
    }

    pub fn from_key_bytes(key: &[u8], ttl: Duration) -> Result<Self, SessionError> {
        if key.len() != 32 {
            return Err(SessionError::InvalidKeyLength(key.len()));
        }

        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(key);
        Ok(Self::new(key_bytes, ttl))
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn issue_token(
        &self,
        space_id: &str,
        permission: Permission,
    ) -> Result<Vec<u8>, SessionError> {
        let expiry_time = SystemTime::now()
            .checked_add(self.ttl)
            .ok_or(SessionError::ExpiryOutOfRange)?;
        let expiry = expiry_time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionError::ExpiryBeforeUnixEpoch)?
            .as_secs();

        let mut token = vec![0_u8; SESSION_TOKEN_LENGTH];
        token[0] = SESSION_VERSION;
        token[1..9].copy_from_slice(&expiry.to_be_bytes());
        token[9] = permission as u8;

        OsRng.fill_bytes(&mut token[10..26]);
        let mac = self.sign(&token[..26], space_id)?;
        token[26..].copy_from_slice(&mac);

        Ok(token)
    }

    pub fn validate_token(
        &self,
        token: &[u8],
        space_id: &str,
    ) -> Result<SessionClaims, SessionError> {
        if token.len() != SESSION_TOKEN_LENGTH || token[0] != SESSION_VERSION {
            return Err(SessionError::InvalidSession);
        }

        let expected = self.sign(&token[..26], space_id)?;
        if !constant_time_eq(&token[26..], &expected) {
            return Err(SessionError::InvalidSession);
        }

        let expiry = u64::from_be_bytes(
            token[1..9]
                .try_into()
                .map_err(|_| SessionError::InvalidSession)?,
        );
        if expiry > i64::MAX as u64 {
            return Err(SessionError::InvalidSession);
        }
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(expiry))
            .ok_or(SessionError::ExpiryOutOfRange)?;

        if SystemTime::now() > expires_at {
            return Err(SessionError::SessionExpired);
        }

        let permission = Permission::try_from(token[9]).map_err(SessionError::InvalidPermission)?;

        Ok(SessionClaims {
            space_id: space_id.to_owned(),
            permission,
            expires_at,
        })
    }

    fn sign(&self, header: &[u8], space_id: &str) -> Result<[u8; 32], SessionError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| SessionError::InvalidKeyLength(self.key.len()))?;
        mac.update(header);
        mac.update(space_id.as_bytes());
        let mut signature = [0_u8; 32];
        signature.copy_from_slice(&mac.finalize().into_bytes());
        Ok(signature)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (&lhs, &rhs) in left.iter().zip(right) {
        diff |= lhs ^ rhs;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SessionError, SessionManager, SESSION_TOKEN_LENGTH};
    use crate::Permission;

    fn test_key() -> [u8; 32] {
        *b"01234567890123456789012345678901"
    }

    #[test]
    fn session_token_round_trip() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let space_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

        let token = manager
            .issue_token(space_id, Permission::Write)
            .expect("issue token");
        assert_eq!(token.len(), SESSION_TOKEN_LENGTH);

        let claims = manager
            .validate_token(&token, space_id)
            .expect("validate token");
        assert_eq!(claims.space_id, space_id);
        assert_eq!(claims.permission, Permission::Write);

        let ttl = claims
            .expires_at
            .duration_since(std::time::SystemTime::now())
            .expect("expiry should be in the future");
        assert!(ttl <= Duration::from_secs(16 * 60));
        assert!(ttl >= Duration::from_secs(14 * 60));
    }

    #[test]
    fn session_token_rejects_wrong_space() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let token = manager
            .issue_token("space-a", Permission::Write)
            .expect("issue token");

        let error = manager
            .validate_token(&token, "space-b")
            .expect_err("space mismatch should fail");
        assert_eq!(error, SessionError::InvalidSession);
    }

    #[test]
    fn session_token_rejects_expired() {
        let manager = SessionManager::new(test_key(), Duration::from_millis(1));
        let token = manager
            .issue_token("space-1", Permission::Read)
            .expect("issue token");

        std::thread::sleep(Duration::from_millis(5));

        let error = manager
            .validate_token(&token, "space-1")
            .expect_err("expired token should fail");
        assert_eq!(error, SessionError::SessionExpired);
    }

    #[test]
    fn session_token_rejects_truncated() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let token = manager
            .issue_token("space-1", Permission::Write)
            .expect("issue token");

        let error = manager
            .validate_token(&token[..20], "space-1")
            .expect_err("truncated token should fail");
        assert_eq!(error, SessionError::InvalidSession);
    }

    #[test]
    fn session_token_rejects_tampered() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let mut token = manager
            .issue_token("space-1", Permission::Write)
            .expect("issue token");
        token[15] ^= 0xff;

        let error = manager
            .validate_token(&token, "space-1")
            .expect_err("tampered token should fail");
        assert_eq!(error, SessionError::InvalidSession);
    }

    #[test]
    fn session_token_rejects_different_key() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let other_key = *b"abcdefghijklmnopqrstuvwxyz012345";
        let other = SessionManager::new(other_key, Duration::from_secs(15 * 60));

        let token = manager
            .issue_token("space-1", Permission::Write)
            .expect("issue token");

        let error = other
            .validate_token(&token, "space-1")
            .expect_err("different key should fail");
        assert_eq!(error, SessionError::InvalidSession);
    }

    #[test]
    fn session_token_preserves_read_permission() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let token = manager
            .issue_token("space-1", Permission::Read)
            .expect("issue token");

        let claims = manager
            .validate_token(&token, "space-1")
            .expect("validate token");
        assert_eq!(claims.permission, Permission::Read);
    }

    #[test]
    fn session_manager_returns_ttl() {
        let ttl = Duration::from_secs(10 * 60);
        let manager = SessionManager::new(test_key(), ttl);
        assert_eq!(manager.ttl(), ttl);
    }

    #[test]
    fn session_manager_rejects_bad_key_length() {
        let error = SessionManager::from_key_bytes(b"short", Duration::from_secs(15 * 60))
            .expect_err("bad key");
        assert_eq!(error, SessionError::InvalidKeyLength(5));
    }

    #[test]
    fn session_token_rejects_wrong_version() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));
        let mut token = manager
            .issue_token("space-1", Permission::Write)
            .expect("issue token");
        token[0] = 99;

        let error = manager
            .validate_token(&token, "space-1")
            .expect_err("invalid version should fail");
        assert_eq!(error, SessionError::InvalidSession);
    }

    #[test]
    fn session_token_rejects_empty() {
        let manager = SessionManager::new(test_key(), Duration::from_secs(15 * 60));

        let nil_error = manager
            .validate_token(&[], "space-1")
            .expect_err("empty token should fail");
        assert_eq!(nil_error, SessionError::InvalidSession);
    }
}
