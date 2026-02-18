#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::DecodingKey;
use p256::PublicKey;
use reqwest::StatusCode;
use tokio::sync::{Mutex, RwLock};

pub const MAX_JWKS_SIZE: usize = 1 << 20;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct JWKS {
    pub keys: Vec<JWK>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct JWK {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
}

#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error("failed to fetch JWKS: {0}")]
    Fetch(#[from] reqwest::Error),
    #[error("JWKS endpoint returned status {0}")]
    Status(StatusCode),
    #[error("JWKS payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("failed to decode JWKS: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("key {0:?} not found in JWKS")]
    KeyNotFound(String),
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("unsupported curve: {0}")]
    UnsupportedCurve(String),
    #[error("failed to decode X coordinate: {0}")]
    InvalidXCoordinate(#[source] base64::DecodeError),
    #[error("failed to decode Y coordinate: {0}")]
    InvalidYCoordinate(#[source] base64::DecodeError),
    #[error("invalid EC point: coordinate larger than 32 bytes")]
    CoordinateTooLarge,
    #[error("invalid EC point: not on curve")]
    PointNotOnCurve,
    #[error("failed to construct decoding key: {0}")]
    InvalidDecodingKey(#[source] jsonwebtoken::errors::Error),
}

#[derive(Default)]
struct JwksCacheState {
    keys: HashMap<String, Arc<DecodingKey>>,
    last_fetch: Option<Instant>,
}

pub struct JwksClient {
    url: String,
    http_client: reqwest::Client,
    refresh_ttl: Duration,
    cache: RwLock<JwksCacheState>,
    refresh_lock: Mutex<()>,
}

impl JwksClient {
    #[must_use]
    pub fn new(url: impl Into<String>, refresh_ttl: Duration) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            url: url.into(),
            http_client,
            refresh_ttl,
            cache: RwLock::new(JwksCacheState::default()),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn set_http_client(&mut self, http_client: reqwest::Client) {
        self.http_client = http_client;
    }

    pub async fn get_key(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        let (cached_key, needs_refresh) = {
            let cache = self.cache.read().await;
            let cached_key = cache.keys.get(kid).cloned();
            let needs_refresh = is_stale(cache.last_fetch, self.refresh_ttl);
            (cached_key, needs_refresh)
        };

        if let Some(cached_key) = cached_key {
            if !needs_refresh {
                return Ok(cached_key);
            }
        }

        let _guard = self.refresh_lock.lock().await;
        let (cached_key, needs_refresh) = {
            let cache = self.cache.read().await;
            let cached_key = cache.keys.get(kid).cloned();
            let needs_refresh = is_stale(cache.last_fetch, self.refresh_ttl);
            (cached_key, needs_refresh)
        };
        if let Some(cached_key) = cached_key {
            if !needs_refresh {
                return Ok(cached_key);
            }
        }

        let refresh_error = self.refresh().await.err();
        if let Some(error) = refresh_error {
            let fallback = {
                let cache = self.cache.read().await;
                cache.keys.get(kid).cloned()
            };
            if let Some(fallback) = fallback {
                return Ok(fallback);
            }
            return Err(error);
        }

        let cache = self.cache.read().await;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| JwksError::KeyNotFound(kid.to_owned()))
    }

    async fn refresh(&self) -> Result<(), JwksError> {
        let response = self.http_client.get(&self.url).send().await?;
        if response.status() != StatusCode::OK {
            return Err(JwksError::Status(response.status()));
        }

        let payload = response.bytes().await?;
        if payload.len() > MAX_JWKS_SIZE {
            return Err(JwksError::PayloadTooLarge(payload.len()));
        }

        let jwks: JWKS = serde_json::from_slice(&payload)?;
        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            match parse_jwk(&jwk) {
                Ok(key) => {
                    keys.insert(jwk.kid, Arc::new(key));
                }
                Err(_) => {
                    // Skip malformed keys to match Go behavior.
                }
            }
        }

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.last_fetch = Some(Instant::now());
        Ok(())
    }
}

pub fn parse_jwk(jwk: &JWK) -> Result<DecodingKey, JwksError> {
    if jwk.kty != "EC" {
        return Err(JwksError::UnsupportedKeyType(jwk.kty.clone()));
    }
    if jwk.crv != "P-256" {
        return Err(JwksError::UnsupportedCurve(jwk.crv.clone()));
    }

    let x_bytes = URL_SAFE_NO_PAD
        .decode(jwk.x.as_bytes())
        .map_err(JwksError::InvalidXCoordinate)?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(jwk.y.as_bytes())
        .map_err(JwksError::InvalidYCoordinate)?;
    let x_bytes = pad_coordinate(&x_bytes)?;
    let y_bytes = pad_coordinate(&y_bytes)?;

    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x_bytes);
    sec1[33..65].copy_from_slice(&y_bytes);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| JwksError::PointNotOnCurve)?;

    DecodingKey::from_ec_components(&jwk.x, &jwk.y).map_err(JwksError::InvalidDecodingKey)
}

fn is_stale(last_fetch: Option<Instant>, refresh_ttl: Duration) -> bool {
    if let Some(last_fetch) = last_fetch {
        last_fetch.elapsed() > refresh_ttl
    } else {
        true
    }
}

fn pad_coordinate(coord: &[u8]) -> Result<[u8; 32], JwksError> {
    if coord.len() > 32 {
        return Err(JwksError::CoordinateTooLarge);
    }
    let mut out = [0_u8; 32];
    let offset = 32 - coord.len();
    out[offset..].copy_from_slice(coord);
    Ok(out)
}
