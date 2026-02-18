#![forbid(unsafe_code)]

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

const DID_KEY_PREFIX: &str = "did:key:z";
const P256_MULTICODEC: u64 = 0x1200;
const MAX_BASE58_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum DidKeyError {
    #[error("invalid did:key: missing did:key:z prefix")]
    MissingPrefix,
    #[error("invalid did:key: base58 input too long: {0}")]
    InputTooLong(usize),
    #[error("invalid did:key: base58 decode failed")]
    Base58Decode(#[from] bs58::decode::Error),
    #[error("invalid did:key: varint decode failed: {0}")]
    InvalidVarint(&'static str),
    #[error("invalid did:key: expected P-256 multicodec 0x1200, got 0x{0:x}")]
    WrongMulticodec(u64),
    #[error("invalid did:key: expected 33-byte compressed point, got {0}")]
    WrongPointLength(usize),
    #[error("invalid did:key: point not on P-256 curve")]
    InvalidPoint,
}

pub fn decode_did_key(did: &str) -> Result<PublicKey, DidKeyError> {
    if did.len() <= DID_KEY_PREFIX.len() || !did.starts_with(DID_KEY_PREFIX) {
        return Err(DidKeyError::MissingPrefix);
    }

    let payload = &did[DID_KEY_PREFIX.len()..];
    if payload.len() > MAX_BASE58_LEN {
        return Err(DidKeyError::InputTooLong(payload.len()));
    }

    let bytes = bs58::decode(payload).into_vec()?;
    let (codec, consumed) = varint_decode(&bytes)?;
    if codec != P256_MULTICODEC {
        return Err(DidKeyError::WrongMulticodec(codec));
    }

    let compressed = &bytes[consumed..];
    if compressed.len() != 33 {
        return Err(DidKeyError::WrongPointLength(compressed.len()));
    }

    PublicKey::from_sec1_bytes(compressed).map_err(|_| DidKeyError::InvalidPoint)
}

#[must_use]
pub fn encode_did_key(public_key: &PublicKey) -> String {
    let compressed = compress_public_key(public_key);
    let varint = varint_encode(P256_MULTICODEC);

    let mut multicodec = Vec::with_capacity(varint.len() + compressed.len());
    multicodec.extend_from_slice(&varint);
    multicodec.extend_from_slice(&compressed);

    let encoded = bs58::encode(multicodec).into_string();
    format!("{DID_KEY_PREFIX}{encoded}")
}

#[must_use]
pub fn compress_public_key(public_key: &PublicKey) -> [u8; 33] {
    let encoded = public_key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0_u8; 33];
    out.copy_from_slice(bytes);
    out
}

fn varint_encode(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }

    let mut out = Vec::new();
    while value > 0 {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }

    out
}

fn varint_decode(bytes: &[u8]) -> Result<(u64, usize), DidKeyError> {
    let mut value = 0_u64;
    let mut shift = 0_u32;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if index >= 10 {
            return Err(DidKeyError::InvalidVarint("too long"));
        }

        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }

        shift += 7;
    }

    Err(DidKeyError::InvalidVarint("truncated"))
}

#[cfg(test)]
mod tests {
    use super::{compress_public_key, decode_did_key, encode_did_key};
    use p256::{elliptic_curve::rand_core::OsRng, SecretKey};

    #[test]
    fn decode_known_vector_roundtrips() {
        let did = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
        let public_key = decode_did_key(did).expect("decode known vector");

        assert_eq!(encode_did_key(&public_key), did);
    }

    #[test]
    fn decode_invalid_inputs() {
        let cases = [
            "",
            "did:web:example.com",
            "did:key:abc",
            "did:key:z",
            "did:key:z0OOOl",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt",
        ];

        for did in cases {
            assert!(
                decode_did_key(did).is_err(),
                "expected decode error for {did}"
            );
        }
    }

    #[test]
    fn random_key_roundtrip() {
        let secret = SecretKey::random(&mut OsRng);
        let public_key = secret.public_key();

        let did = encode_did_key(&public_key);
        let decoded = decode_did_key(&did).expect("decode generated did:key");

        assert_eq!(decoded, public_key);
    }

    #[test]
    fn compressed_public_key_shape() {
        let secret = SecretKey::random(&mut OsRng);
        let public_key = secret.public_key();

        let compressed = compress_public_key(&public_key);
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }
}
