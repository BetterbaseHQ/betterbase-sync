#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::{Digest, Sha256};

use crate::{
    compress_public_key, decode_did_key, parse_permission, DidKeyError, ParsePermissionError,
    Permission,
};

pub const MAX_CHAIN_DEPTH: usize = 8;
pub const MAX_TOKENS_PER_CHAIN: usize = 32;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UcanClaims {
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: Option<AudienceClaim>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub cmd: String,
    #[serde(rename = "with", default)]
    pub with_resource: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub prf: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl UcanClaims {
    fn first_audience(&self) -> Option<&str> {
        match self.aud.as_ref() {
            Some(AudienceClaim::One(value)) => Some(value.as_str()),
            Some(AudienceClaim::Many(values)) => values.first().map(String::as_str),
            None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedUcan {
    pub claims: UcanClaims,
    pub public_key: PublicKey,
    pub raw: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UcanError {
    #[error("invalid UCAN")]
    InvalidUcan,
    #[error("UCAN expired")]
    UcanExpired,
    #[error("UCAN chain too deep")]
    ChainTooDeep,
    #[error("UCAN attenuation violation")]
    AttenuationViolation,
    #[error("UCAN resource mismatch")]
    ResourceMismatch,
    #[error("UCAN root key mismatch")]
    RootMismatch,
    #[error("UCAN identity mismatch")]
    IdentityMismatch,
    #[error("UCAN revoked")]
    UcanRevoked,
    #[error("revocation check failed")]
    RevocationCheckFailed,
}

#[derive(Clone, Copy)]
pub struct ValidateChainParams<'a> {
    pub token: &'a str,
    pub expected_audience: &'a str,
    pub required_permission: Permission,
    pub space_id: &'a str,
    pub root_public_key: &'a [u8],
    pub is_revoked: Option<&'a RevocationCheck>,
    pub now: Option<SystemTime>,
}

pub type RevocationCheck = dyn Fn(&str, &str) -> Result<bool, UcanError> + Send + Sync;

pub fn parse_ucan(raw: &str) -> Result<ParsedUcan, UcanError> {
    let header = decode_header(raw).map_err(|_| UcanError::InvalidUcan)?;
    if header.alg != Algorithm::ES256 {
        return Err(UcanError::InvalidUcan);
    }

    let issuer = extract_unverified_issuer(raw)?;
    let public_key = decode_did_key(&issuer).map_err(map_did_key_error)?;
    let decoding_key = decoding_key_from_public_key(&public_key)?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let token_data = decode::<UcanClaims>(raw, &decoding_key, &validation)
        .map_err(|_| UcanError::InvalidUcan)?;

    if token_data.claims.iss.is_empty() {
        return Err(UcanError::InvalidUcan);
    }

    Ok(ParsedUcan {
        claims: token_data.claims,
        public_key,
        raw: raw.to_owned(),
    })
}

#[must_use]
pub fn compute_ucan_cid(raw_token: &str) -> String {
    let hash = Sha256::digest(raw_token.as_bytes());
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn validate_chain(params: ValidateChainParams<'_>) -> Result<(), UcanError> {
    let now = params.now.unwrap_or_else(SystemTime::now);
    let expected_resource = format!("space:{}", params.space_id);

    let mut visited = HashSet::new();
    let mut tokens_parsed = 0usize;

    validate_chain_recursive(
        params.token,
        None,
        params.expected_audience,
        params.required_permission,
        &expected_resource,
        params.root_public_key,
        params.is_revoked,
        params.space_id,
        now,
        0,
        &mut visited,
        &mut tokens_parsed,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_chain_recursive(
    raw_token: &str,
    pre_parsed: Option<&ParsedUcan>,
    expected_audience: &str,
    required_permission: Permission,
    expected_resource: &str,
    root_public_key: &[u8],
    is_revoked: Option<&RevocationCheck>,
    space_id: &str,
    now: SystemTime,
    depth: usize,
    visited: &mut HashSet<String>,
    tokens_parsed: &mut usize,
) -> Result<(), UcanError> {
    if depth >= MAX_CHAIN_DEPTH {
        return Err(UcanError::ChainTooDeep);
    }
    if *tokens_parsed >= MAX_TOKENS_PER_CHAIN {
        return Err(UcanError::InvalidUcan);
    }
    if !visited.insert(raw_token.to_owned()) {
        return Err(UcanError::InvalidUcan);
    }
    *tokens_parsed += 1;

    let parsed_storage;
    let parsed = if let Some(parsed) = pre_parsed {
        parsed
    } else {
        parsed_storage = parse_ucan(raw_token)?;
        &parsed_storage
    };

    let claims = &parsed.claims;

    if depth == 0 && claims.first_audience() != Some(expected_audience) {
        return Err(UcanError::IdentityMismatch);
    }

    if claims.with_resource != expected_resource {
        return Err(UcanError::ResourceMismatch);
    }

    let permission = parse_permission(&claims.cmd).map_err(map_permission_error)?;
    if !permission.attenuates(required_permission) {
        return Err(UcanError::AttenuationViolation);
    }

    let exp = claims.exp.ok_or(UcanError::InvalidUcan)?;
    if unix_seconds(now)? > exp {
        return Err(UcanError::UcanExpired);
    }
    if let Some(nbf) = claims.nbf {
        if unix_seconds(now)? < nbf {
            return Err(UcanError::InvalidUcan);
        }
    }
    if claims.nonce.is_empty() {
        return Err(UcanError::InvalidUcan);
    }

    let cid = compute_ucan_cid(raw_token);
    if let Some(check_revoked) = is_revoked {
        let revoked =
            check_revoked(space_id, &cid).map_err(|_| UcanError::RevocationCheckFailed)?;
        if revoked {
            return Err(UcanError::UcanRevoked);
        }
    }

    if claims.prf.len() > 1 {
        return Err(UcanError::InvalidUcan);
    }
    if claims.prf.is_empty() {
        if constant_time_eq(&compress_public_key(&parsed.public_key), root_public_key) {
            return Ok(());
        }
        return Err(UcanError::RootMismatch);
    }

    let proof_token = &claims.prf[0];
    let proof = parse_ucan(proof_token)?;
    if proof.claims.first_audience() != Some(claims.iss.as_str()) {
        return Err(UcanError::IdentityMismatch);
    }

    let proof_permission = parse_permission(&proof.claims.cmd).map_err(map_permission_error)?;
    if !proof_permission.attenuates(permission) {
        return Err(UcanError::AttenuationViolation);
    }

    if let (Some(proof_exp), Some(child_exp)) = (proof.claims.exp, claims.exp) {
        if child_exp > proof_exp {
            return Err(UcanError::AttenuationViolation);
        }
    }

    validate_chain_recursive(
        proof_token,
        Some(&proof),
        "",
        required_permission,
        expected_resource,
        root_public_key,
        is_revoked,
        space_id,
        now,
        depth + 1,
        visited,
        tokens_parsed,
    )
}

fn extract_unverified_issuer(token: &str) -> Result<String, UcanError> {
    let payload = token.split('.').nth(1).ok_or(UcanError::InvalidUcan)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| UcanError::InvalidUcan)?;
    let claims: UnverifiedIssuerClaims =
        serde_json::from_slice(&payload).map_err(|_| UcanError::InvalidUcan)?;
    claims.iss.ok_or(UcanError::InvalidUcan)
}

fn decoding_key_from_public_key(public_key: &PublicKey) -> Result<DecodingKey, UcanError> {
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let x = URL_SAFE_NO_PAD.encode(&bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&bytes[33..65]);
    DecodingKey::from_ec_components(&x, &y).map_err(|_| UcanError::InvalidUcan)
}

fn map_permission_error(_: ParsePermissionError) -> UcanError {
    UcanError::InvalidUcan
}

fn map_did_key_error(_: DidKeyError) -> UcanError {
    UcanError::InvalidUcan
}

fn unix_seconds(now: SystemTime) -> Result<u64, UcanError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| UcanError::InvalidUcan)
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

#[derive(Debug, serde::Deserialize)]
struct UnverifiedIssuerClaims {
    iss: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{Algorithm, Header};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::rand_core::OsRng;

    use super::{
        compute_ucan_cid, parse_ucan, validate_chain, AudienceClaim, UcanClaims, UcanError,
        ValidateChainParams, MAX_CHAIN_DEPTH,
    };
    use crate::{compress_public_key, encode_did_key, Permission};

    #[derive(Clone)]
    struct TestIssuer {
        key: SigningKey,
        did: String,
    }

    impl TestIssuer {
        fn public_key(&self) -> p256::PublicKey {
            p256::PublicKey::from_sec1_bytes(
                self.key.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .expect("public key should decode")
        }

        fn new() -> Self {
            let key = SigningKey::random(&mut OsRng);
            let public_key = p256::PublicKey::from_sec1_bytes(
                key.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .expect("public key should decode");
            let did = encode_did_key(&public_key);
            Self { key, did }
        }

        fn compressed_public_key(&self) -> [u8; 33] {
            compress_public_key(&self.public_key())
        }

        fn issue(&self, opts: UcanOpts) -> String {
            let issuer = opts.iss.unwrap_or_else(|| self.did.clone());
            let claims = UcanClaims {
                iss: issuer,
                aud: Some(AudienceClaim::One(opts.aud)),
                exp: Some(to_unix(opts.exp)),
                nbf: opts.nbf.map(to_unix),
                cmd: opts.cmd,
                with_resource: opts.with_resource,
                nonce: opts.nonce,
                prf: opts.prf,
            };

            sign_es256_token(&claims, &self.key)
        }
    }

    struct UcanOpts {
        iss: Option<String>,
        aud: String,
        cmd: String,
        with_resource: String,
        nonce: String,
        prf: Vec<String>,
        exp: SystemTime,
        nbf: Option<SystemTime>,
    }

    const TEST_SPACE_ID: &str = "11111111-1111-1111-1111-111111111111";
    const TEST_RESOURCE: &str = "space:11111111-1111-1111-1111-111111111111";

    fn to_unix(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_secs()
    }

    fn sign_es256_token(claims: &UcanClaims, key: &SigningKey) -> String {
        let header = Header {
            alg: Algorithm::ES256,
            typ: Some("JWT".to_owned()),
            ..Header::default()
        };
        let header = serde_json::to_vec(&header).expect("serialize header");
        let claims = serde_json::to_vec(claims).expect("serialize claims");
        let header = URL_SAFE_NO_PAD.encode(header);
        let claims = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = key.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{signature}")
    }

    #[test]
    fn parse_ucan_valid() {
        let issuer = TestIssuer::new();
        let bearer = TestIssuer::new();

        let raw = issuer.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "abc123".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let parsed = parse_ucan(&raw).expect("parse ucan");
        assert_eq!(parsed.claims.iss, issuer.did);
        assert_eq!(parsed.raw, raw);
    }

    #[test]
    fn parse_ucan_invalid_signature() {
        let issuer = TestIssuer::new();
        let other = TestIssuer::new();
        let bearer = TestIssuer::new();

        let claims = UcanClaims {
            iss: issuer.did.clone(),
            aud: Some(AudienceClaim::One(bearer.did)),
            exp: Some(to_unix(SystemTime::now() + Duration::from_secs(60 * 60))),
            nbf: None,
            cmd: "/space/read".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "abc".to_owned(),
            prf: Vec::new(),
        };
        let signed = sign_es256_token(&claims, &other.key);
        let error = parse_ucan(&signed).expect_err("expected invalid signature");
        assert_eq!(error, UcanError::InvalidUcan);
    }

    #[test]
    fn compute_ucan_cid_deterministic() {
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test.payload";
        let cid1 = compute_ucan_cid(token);
        let cid2 = compute_ucan_cid(token);

        assert_eq!(cid1, cid2);
        assert_eq!(cid1.len(), 64);
    }

    #[test]
    fn compute_ucan_cid_different_tokens() {
        assert_ne!(compute_ucan_cid("token-a"), compute_ucan_cid("token-b"));
    }

    #[test]
    fn validate_chain_self_issued_root() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "nonce1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect("validate chain");
    }

    #[test]
    fn validate_chain_two_link() {
        let root = TestIssuer::new();
        let delegate = TestIssuer::new();
        let bearer = TestIssuer::new();

        let root_token = root.issue(UcanOpts {
            iss: None,
            aud: delegate.did.clone(),
            cmd: "/space/admin".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "root-nonce".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: None,
        });
        let leaf_token = delegate.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "leaf-nonce".to_owned(),
            prf: vec![root_token],
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        validate_chain(ValidateChainParams {
            token: &leaf_token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect("validate chain");
    }

    #[test]
    fn validate_chain_three_link() {
        let root = TestIssuer::new();
        let mid = TestIssuer::new();
        let delegate = TestIssuer::new();
        let bearer = TestIssuer::new();

        let root_token = root.issue(UcanOpts {
            iss: None,
            aud: mid.did.clone(),
            cmd: "/space/admin".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(3 * 60 * 60),
            nbf: None,
        });
        let mid_token = mid.issue(UcanOpts {
            iss: None,
            aud: delegate.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n2".to_owned(),
            prf: vec![root_token],
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: None,
        });
        let leaf_token = delegate.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/read".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n3".to_owned(),
            prf: vec![mid_token],
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        validate_chain(ValidateChainParams {
            token: &leaf_token,
            expected_audience: &bearer.did,
            required_permission: Permission::Read,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect("validate chain");
    }

    #[test]
    fn validate_chain_depth_exceeded() {
        let mut issuers = Vec::new();
        for _ in 0..(MAX_CHAIN_DEPTH + 2) {
            issuers.push(TestIssuer::new());
        }

        let mut tokens = Vec::new();
        tokens.push(issuers[0].issue(UcanOpts {
            iss: None,
            aud: issuers[1].did.clone(),
            cmd: "/space/admin".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n0".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(10 * 60 * 60),
            nbf: None,
        }));

        for index in 1..(issuers.len() - 1) {
            tokens.push(issuers[index].issue(UcanOpts {
                iss: None,
                aud: issuers[index + 1].did.clone(),
                cmd: "/space/admin".to_owned(),
                with_resource: TEST_RESOURCE.to_owned(),
                nonce: format!("n{index}"),
                prf: vec![tokens[index - 1].clone()],
                exp: SystemTime::now() + Duration::from_secs((10 - index) as u64 * 60 * 60),
                nbf: None,
            }));
        }

        let leaf = tokens.last().expect("leaf token");
        let bearer = issuers.last().expect("bearer");
        let error = validate_chain(ValidateChainParams {
            token: leaf,
            expected_audience: &bearer.did,
            required_permission: Permission::Read,
            space_id: TEST_SPACE_ID,
            root_public_key: &issuers[0].compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected chain too deep");
        assert_eq!(error, UcanError::ChainTooDeep);
    }

    #[test]
    fn validate_chain_attenuation_violation() {
        let root = TestIssuer::new();
        let delegate = TestIssuer::new();
        let bearer = TestIssuer::new();

        let root_token = root.issue(UcanOpts {
            iss: None,
            aud: delegate.did.clone(),
            cmd: "/space/read".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: None,
        });
        let leaf_token = delegate.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n2".to_owned(),
            prf: vec![root_token],
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &leaf_token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected attenuation violation");
        assert_eq!(error, UcanError::AttenuationViolation);
    }

    #[test]
    fn validate_chain_resource_mismatch() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: "space:99999999-9999-9999-9999-999999999999".to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected mismatch");
        assert_eq!(error, UcanError::ResourceMismatch);
    }

    #[test]
    fn validate_chain_expired() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() - Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected expiration");
        assert_eq!(error, UcanError::UcanExpired);
    }

    #[test]
    fn validate_chain_not_yet_valid() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: Some(SystemTime::now() + Duration::from_secs(60 * 60)),
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected not-yet-valid");
        assert_eq!(error, UcanError::InvalidUcan);
    }

    #[test]
    fn validate_chain_child_exp_exceeds_parent() {
        let root = TestIssuer::new();
        let delegate = TestIssuer::new();
        let bearer = TestIssuer::new();

        let root_token = root.issue(UcanOpts {
            iss: None,
            aud: delegate.did.clone(),
            cmd: "/space/admin".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let leaf_token = delegate.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/read".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n2".to_owned(),
            prf: vec![root_token],
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &leaf_token,
            expected_audience: &bearer.did,
            required_permission: Permission::Read,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected attenuation");
        assert_eq!(error, UcanError::AttenuationViolation);
    }

    #[test]
    fn validate_chain_revoked() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let revoked = |_: &str, _: &str| -> Result<bool, UcanError> { Ok(true) };
        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: Some(&revoked),
            now: None,
        })
        .expect_err("expected revoked");
        assert_eq!(error, UcanError::UcanRevoked);
    }

    #[test]
    fn validate_chain_root_mismatch() {
        let root = TestIssuer::new();
        let wrong_root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &wrong_root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected root mismatch");
        assert_eq!(error, UcanError::RootMismatch);
    }

    #[test]
    fn validate_chain_identity_mismatch() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();
        let wrong_bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &wrong_bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected identity mismatch");
        assert_eq!(error, UcanError::IdentityMismatch);
    }

    #[test]
    fn validate_chain_missing_nonce() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: String::new(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected invalid nonce");
        assert_eq!(error, UcanError::InvalidUcan);
    }

    #[test]
    fn validate_chain_prf_with_multiple_entries() {
        let root = TestIssuer::new();
        let delegate = TestIssuer::new();
        let bearer = TestIssuer::new();

        let root_token = root.issue(UcanOpts {
            iss: None,
            aud: delegate.did.clone(),
            cmd: "/space/admin".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
            nbf: None,
        });
        let leaf_token = delegate.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/write".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n2".to_owned(),
            prf: vec![root_token.clone(), root_token],
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &leaf_token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected invalid prf");
        assert_eq!(error, UcanError::InvalidUcan);
    }

    #[test]
    fn validate_chain_insufficient_permission() {
        let root = TestIssuer::new();
        let bearer = TestIssuer::new();

        let token = root.issue(UcanOpts {
            iss: None,
            aud: bearer.did.clone(),
            cmd: "/space/read".to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce: "n1".to_owned(),
            prf: Vec::new(),
            exp: SystemTime::now() + Duration::from_secs(60 * 60),
            nbf: None,
        });

        let error = validate_chain(ValidateChainParams {
            token: &token,
            expected_audience: &bearer.did,
            required_permission: Permission::Write,
            space_id: TEST_SPACE_ID,
            root_public_key: &root.compressed_public_key(),
            is_revoked: None,
            now: None,
        })
        .expect_err("expected insufficient permission");
        assert_eq!(error, UcanError::AttenuationViolation);
    }
}
