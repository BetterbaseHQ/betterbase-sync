use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use jsonwebtoken::{Algorithm, Header};
use less_sync_auth::{
    compress_public_key, encode_did_key, validate_chain, AudienceClaim, Permission, UcanClaims,
    ValidateChainParams,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;

const TEST_SPACE_ID: &str = "11111111-1111-1111-1111-111111111111";
const TEST_RESOURCE: &str = "space:11111111-1111-1111-1111-111111111111";

#[derive(Clone)]
struct Issuer {
    key: SigningKey,
    did: String,
}

impl Issuer {
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
        let public_key = p256::PublicKey::from_sec1_bytes(
            self.key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .expect("public key should decode");
        compress_public_key(&public_key)
    }

    fn issue(
        &self,
        audience: &str,
        permission: Permission,
        nonce: String,
        proofs: Vec<String>,
    ) -> String {
        let claims = UcanClaims {
            iss: self.did.clone(),
            aud: Some(AudienceClaim::One(audience.to_owned())),
            exp: Some(unix_seconds(
                SystemTime::now() + Duration::from_secs(60 * 60),
            )),
            nbf: None,
            cmd: permission.as_cmd().to_owned(),
            with_resource: TEST_RESOURCE.to_owned(),
            nonce,
            prf: proofs,
        };

        sign_es256_token(&claims, &self.key)
    }
}

struct ChainFixture {
    leaf_token: String,
    expected_audience: String,
    root_public_key: [u8; 33],
}

impl ChainFixture {
    fn new(depth: usize) -> Self {
        assert!(depth >= 1, "depth must be >= 1");

        let issuers = (0..depth).map(|_| Issuer::new()).collect::<Vec<_>>();
        let bearer = Issuer::new();
        let root_public_key = issuers[0].compressed_public_key();

        let mut previous_token: Option<String> = None;
        for index in 0..depth {
            let audience = if index + 1 < depth {
                issuers[index + 1].did.as_str()
            } else {
                bearer.did.as_str()
            };
            let token = issuers[index].issue(
                audience,
                Permission::Write,
                format!("n{index}"),
                previous_token.into_iter().collect(),
            );
            previous_token = Some(token);
        }

        Self {
            leaf_token: previous_token.expect("leaf token should exist"),
            expected_audience: bearer.did,
            root_public_key,
        }
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
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

fn bench_validate_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_chain");
    for depth in [1_usize, 3, 8] {
        let fixture = ChainFixture::new(depth);
        group.bench_with_input(BenchmarkId::new("depth", depth), &fixture, |b, fixture| {
            b.iter(|| {
                validate_chain(ValidateChainParams {
                    token: black_box(&fixture.leaf_token),
                    expected_audience: black_box(&fixture.expected_audience),
                    required_permission: Permission::Write,
                    space_id: TEST_SPACE_ID,
                    root_public_key: black_box(&fixture.root_public_key),
                    is_revoked: None,
                    now: None,
                })
                .expect("benchmark chain should validate");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_validate_chain);
criterion_main!(benches);
