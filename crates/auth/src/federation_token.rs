#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const FST_VERSION: u8 = 1;
pub const FST_TOKEN_LEN: usize = 1 + 16 + 16 + 32 + 8 + 32;
pub const FST_MAX_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

const FST_KEY_DOMAIN: &[u8] = b"fst-key-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationSubscribeClaims {
    pub space_id: Uuid,
    pub expires_at: SystemTime,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationTokenError {
    #[error("invalid federation subscribe token")]
    InvalidToken,
    #[error("federation subscribe token expired")]
    ExpiredToken,
    #[error("federation token expiry before unix epoch")]
    ExpiryBeforeUnixEpoch,
    #[error("invalid federation HMAC key")]
    InvalidHmacKey,
}

#[must_use]
pub fn derive_fst_key(base_secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(base_secret).expect("HMAC key accepts any size");
    mac.update(FST_KEY_DOMAIN);
    let mut key = [0_u8; 32];
    key.copy_from_slice(&mac.finalize().into_bytes());
    key
}

pub fn create_fst(
    key: &[u8],
    space_id: Uuid,
    peer_domain: &str,
    ucan_expiry: Option<SystemTime>,
) -> Result<String, FederationTokenError> {
    let now = SystemTime::now();
    let mut expires_at = now + FST_MAX_EXPIRY;
    if let Some(ucan_expiry) = ucan_expiry {
        if ucan_expiry < expires_at {
            expires_at = ucan_expiry;
        }
    }

    let expiry = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FederationTokenError::ExpiryBeforeUnixEpoch)?
        .as_secs();

    let mut token = vec![0_u8; FST_TOKEN_LEN];
    token[0] = FST_VERSION;

    OsRng.fill_bytes(&mut token[1..17]);
    token[17..33].copy_from_slice(space_id.as_bytes());

    let domain_hash = Sha256::digest(canonicalize_domain(peer_domain).as_bytes());
    token[33..65].copy_from_slice(&domain_hash);
    token[65..73].copy_from_slice(&expiry.to_be_bytes());

    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| FederationTokenError::InvalidHmacKey)?;
    mac.update(&token[..73]);
    token[73..].copy_from_slice(&mac.finalize().into_bytes());

    Ok(URL_SAFE_NO_PAD.encode(token))
}

pub fn verify_fst(
    key: &[u8],
    token: &str,
    peer_domain: &str,
) -> Result<FederationSubscribeClaims, FederationTokenError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| FederationTokenError::InvalidToken)?;
    if decoded.len() != FST_TOKEN_LEN {
        return Err(FederationTokenError::InvalidToken);
    }
    if decoded[0] != FST_VERSION {
        return Err(FederationTokenError::InvalidToken);
    }

    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| FederationTokenError::InvalidHmacKey)?;
    mac.update(&decoded[..73]);
    let expected = mac.finalize().into_bytes();
    if !constant_time_eq(&decoded[73..], &expected) {
        return Err(FederationTokenError::InvalidToken);
    }

    let expected_domain_hash = Sha256::digest(canonicalize_domain(peer_domain).as_bytes());
    if !constant_time_eq(&decoded[33..65], &expected_domain_hash) {
        return Err(FederationTokenError::InvalidToken);
    }

    let expiry = u64::from_be_bytes(
        decoded[65..73]
            .try_into()
            .map_err(|_| FederationTokenError::InvalidToken)?,
    );
    if expiry > i64::MAX as u64 {
        return Err(FederationTokenError::InvalidToken);
    }

    let expires_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(expiry))
        .ok_or(FederationTokenError::InvalidToken)?;
    if SystemTime::now() > expires_at {
        return Err(FederationTokenError::ExpiredToken);
    }

    let space_id =
        Uuid::from_slice(&decoded[17..33]).map_err(|_| FederationTokenError::InvalidToken)?;

    Ok(FederationSubscribeClaims {
        space_id,
        expires_at,
    })
}

pub fn verify_fst_dual_key(
    primary_key: &[u8],
    old_key: Option<&[u8]>,
    token: &str,
    peer_domain: &str,
) -> Result<FederationSubscribeClaims, FederationTokenError> {
    match verify_fst(primary_key, token, peer_domain) {
        Ok(claims) => Ok(claims),
        Err(primary_error) => {
            if let Some(old_key) = old_key {
                verify_fst(old_key, token, peer_domain)
            } else {
                Err(primary_error)
            }
        }
    }
}

#[must_use]
pub fn canonicalize_domain(domain: &str) -> String {
    let without_scheme = if let Some(index) = domain.find("://") {
        &domain[index + 3..]
    } else {
        domain
    };
    let without_path = if let Some(index) = without_scheme.find('/') {
        &without_scheme[..index]
    } else {
        without_scheme
    };
    without_path
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .trim_end_matches(":443")
        .to_owned()
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
    use std::time::{Duration, SystemTime};

    use uuid::Uuid;

    use super::{
        canonicalize_domain, create_fst, derive_fst_key, verify_fst, verify_fst_dual_key,
        FederationTokenError,
    };

    fn test_key() -> [u8; 32] {
        *b"01234567890123456789012345678901"
    }

    #[test]
    fn fst_round_trip() {
        let fst_key = derive_fst_key(&test_key());
        let space_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").expect("valid uuid");
        let domain = "peer.example.com";

        let token = create_fst(&fst_key, space_id, domain, None).expect("create fst");
        let claims = verify_fst(&fst_key, &token, domain).expect("verify fst");

        assert_eq!(claims.space_id, space_id);
        let ttl = claims
            .expires_at
            .duration_since(SystemTime::now())
            .expect("expiry should be in the future");
        assert!(ttl >= Duration::from_secs(23 * 60 * 60));
        assert!(ttl <= Duration::from_secs(25 * 60 * 60));
    }

    #[test]
    fn fst_caps_expiry_to_ucan_expiry() {
        let fst_key = derive_fst_key(&test_key());
        let space_id = Uuid::new_v4();
        let ucan_expiry = SystemTime::now() + Duration::from_secs(60 * 60);

        let token = create_fst(&fst_key, space_id, "peer.example.com", Some(ucan_expiry))
            .expect("create fst");
        let claims = verify_fst(&fst_key, &token, "peer.example.com").expect("verify fst");

        let ttl = claims
            .expires_at
            .duration_since(SystemTime::now())
            .expect("expiry should be in the future");
        assert!(ttl >= Duration::from_secs(50 * 60));
        assert!(ttl <= Duration::from_secs(70 * 60));
    }

    #[test]
    fn fst_rejects_wrong_peer() {
        let fst_key = derive_fst_key(&test_key());
        let token =
            create_fst(&fst_key, Uuid::new_v4(), "peer-a.example.com", None).expect("create fst");

        let error =
            verify_fst(&fst_key, &token, "peer-b.example.com").expect_err("expected rejection");
        assert_eq!(error, FederationTokenError::InvalidToken);
    }

    #[test]
    fn fst_rejects_wrong_key() {
        let key_one = derive_fst_key(&test_key());
        let key_two = derive_fst_key(b"abcdefghijklmnopqrstuvwxyz012345");
        let token =
            create_fst(&key_one, Uuid::new_v4(), "peer.example.com", None).expect("create fst");

        let error =
            verify_fst(&key_two, &token, "peer.example.com").expect_err("expected rejection");
        assert_eq!(error, FederationTokenError::InvalidToken);
    }

    #[test]
    fn fst_rejects_expired() {
        let fst_key = derive_fst_key(&test_key());
        let token = create_fst(
            &fst_key,
            Uuid::new_v4(),
            "peer.example.com",
            Some(SystemTime::now() - Duration::from_secs(60 * 60)),
        )
        .expect("create fst");

        let error =
            verify_fst(&fst_key, &token, "peer.example.com").expect_err("expected expiration");
        assert_eq!(error, FederationTokenError::ExpiredToken);
    }

    #[test]
    fn fst_rejects_tampered() {
        let fst_key = derive_fst_key(&test_key());
        let token =
            create_fst(&fst_key, Uuid::new_v4(), "peer.example.com", None).expect("create fst");

        let mut raw = token.into_bytes();
        raw[10] = if raw[10] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(raw).expect("base64 token should remain utf-8");

        let error =
            verify_fst(&fst_key, &tampered, "peer.example.com").expect_err("expected rejection");
        assert_eq!(error, FederationTokenError::InvalidToken);
    }

    #[test]
    fn fst_rejects_empty_and_garbage() {
        let fst_key = derive_fst_key(&test_key());
        for candidate in ["", "not-base64!", "abc123"] {
            let error = verify_fst(&fst_key, candidate, "peer.example.com")
                .expect_err("expected rejection");
            assert_eq!(error, FederationTokenError::InvalidToken);
        }
    }

    #[test]
    fn fst_dual_key_verification() {
        let old_key = derive_fst_key(&test_key());
        let new_key = derive_fst_key(b"abcdefghijklmnopqrstuvwxyz012345");
        let space_id = Uuid::new_v4();
        let domain = "peer.example.com";
        let token = create_fst(&old_key, space_id, domain, None).expect("create fst");

        let error =
            verify_fst(&new_key, &token, domain).expect_err("new key should reject old token");
        assert_eq!(error, FederationTokenError::InvalidToken);

        let claims =
            verify_fst_dual_key(&new_key, Some(&old_key), &token, domain).expect("dual-key verify");
        assert_eq!(claims.space_id, space_id);
    }

    #[test]
    fn fst_is_non_deterministic() {
        let fst_key = derive_fst_key(&test_key());
        let space_id = Uuid::new_v4();

        let token_one =
            create_fst(&fst_key, space_id, "peer.example.com", None).expect("token one");
        let token_two =
            create_fst(&fst_key, space_id, "peer.example.com", None).expect("token two");
        assert_ne!(token_one, token_two);
    }

    #[test]
    fn canonicalize_domain_cases() {
        let cases = [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("example.com.", "example.com"),
            ("example.com:443", "example.com"),
            ("example.com:8443", "example.com:8443"),
            ("https://example.com", "example.com"),
            ("https://EXAMPLE.COM:443/path", "example.com"),
            ("http://example.com:8080/foo", "example.com:8080"),
        ];

        for (input, expected) in cases {
            assert_eq!(canonicalize_domain(input), expected, "{input}");
        }
    }
}
