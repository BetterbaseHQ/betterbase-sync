use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use betterbase_sync_api::{
    ApiState, FederationJwk, FederationJwks, FederationPeerManager, FederationQuotaLimits,
    FederationTokenKeys, HttpSignatureFederationAuthenticator,
};
use betterbase_sync_auth::{canonicalize_domain, derive_fst_key, extract_domain_from_key_id};
use betterbase_sync_storage::{FederationStorage, PostgresStorage};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FederationRuntimeConfig {
    pub trusted_domains: Vec<String>,
    pub trusted_keys: HashMap<String, [u8; 32]>,
    pub fst_secret: Option<String>,
    pub fst_previous_secret: Option<String>,
    pub quota_limits: FederationQuotaLimits,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FederationEnv {
    pub trusted_domains: Option<String>,
    pub trusted_keys: Option<String>,
    pub fst_secret: Option<String>,
    pub fst_previous_secret: Option<String>,
    pub max_spaces: Option<String>,
    pub max_records_per_hour: Option<String>,
    pub max_bytes_per_hour: Option<String>,
    pub max_invitations_per_hour: Option<String>,
    pub max_connections: Option<String>,
}

impl FederationEnv {
    pub(crate) fn from_env() -> Self {
        Self {
            trusted_domains: std::env::var("FEDERATION_TRUSTED_DOMAINS").ok(),
            trusted_keys: std::env::var("FEDERATION_TRUSTED_KEYS").ok(),
            fst_secret: std::env::var("FEDERATION_FST_SECRET").ok(),
            fst_previous_secret: std::env::var("FEDERATION_FST_PREVIOUS_SECRET").ok(),
            max_spaces: std::env::var("FEDERATION_MAX_SPACES").ok(),
            max_records_per_hour: std::env::var("FEDERATION_MAX_RECORDS_PER_HOUR").ok(),
            max_bytes_per_hour: std::env::var("FEDERATION_MAX_BYTES_PER_HOUR").ok(),
            max_invitations_per_hour: std::env::var("FEDERATION_MAX_INVITATIONS_PER_HOUR").ok(),
            max_connections: std::env::var("FEDERATION_MAX_CONNECTIONS").ok(),
        }
    }
}

pub(crate) fn parse_federation_runtime_config(
    env: FederationEnv,
) -> anyhow::Result<FederationRuntimeConfig> {
    let quota_limits = parse_quota_limits(&env)?;
    let mut trusted_domains = parse_trusted_domains(env.trusted_domains)?;
    let trusted_keys = parse_trusted_keys(env.trusted_keys.as_deref())?;

    let key_domains = trusted_keys
        .keys()
        .map(|key_id| {
            extract_domain_from_key_id(key_id)
                .map(|domain| canonicalize_domain(&domain))
                .map_err(|_| anyhow::anyhow!("invalid federation key id {key_id:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if trusted_domains.is_empty() {
        trusted_domains = key_domains.clone();
        trusted_domains.sort_unstable();
        trusted_domains.dedup();
    }

    if !trusted_domains.is_empty() {
        let trusted = trusted_domains.iter().cloned().collect::<HashSet<_>>();
        for key_domain in key_domains {
            if !trusted.contains(&key_domain) {
                return Err(anyhow::anyhow!(
                    "FEDERATION_TRUSTED_KEYS domain {key_domain:?} is not listed in FEDERATION_TRUSTED_DOMAINS"
                ));
            }
        }
    }

    Ok(FederationRuntimeConfig {
        trusted_domains,
        trusted_keys,
        fst_secret: normalize_optional_secret(env.fst_secret),
        fst_previous_secret: normalize_optional_secret(env.fst_previous_secret),
        quota_limits,
    })
}

pub(crate) async fn apply_federation_runtime_config(
    mut api_state: ApiState,
    storage: Arc<PostgresStorage>,
    config: &FederationRuntimeConfig,
) -> anyhow::Result<ApiState> {
    api_state = api_state
        .with_federation_quota_limits(config.quota_limits)
        .with_federation_trusted_domains(config.trusted_domains.clone());

    let jwks = load_jwks(storage.as_ref()).await?;
    api_state = api_state.with_federation_jwks(jwks);

    if let Some((key_id, signing_key)) = load_primary_signing_key(storage.as_ref()).await? {
        let forwarder = FederationPeerManager::new(key_id, signing_key);
        api_state = api_state.with_federation_forwarder(Arc::new(forwarder));
    }

    if !config.trusted_keys.is_empty() {
        let keys_by_id = config
            .trusted_keys
            .iter()
            .map(|(key_id, key_bytes)| {
                VerifyingKey::from_bytes(key_bytes)
                    .map(|key| (key_id.clone(), key))
                    .map_err(|_| anyhow::anyhow!("invalid federation key bytes for {key_id:?}"))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        let authenticator =
            HttpSignatureFederationAuthenticator::new(config.trusted_domains.clone(), keys_by_id);
        api_state = api_state.with_federation_authenticator(Arc::new(authenticator));
    }

    if let Some(secret) = config.fst_secret.as_deref() {
        let mut keys = FederationTokenKeys::new(derive_fst_key(secret.as_bytes()));
        if let Some(previous_secret) = config.fst_previous_secret.as_deref() {
            keys = keys.with_previous_key(derive_fst_key(previous_secret.as_bytes()));
        }
        api_state = api_state.with_federation_token_keys(keys);
    }

    Ok(api_state)
}

fn parse_trusted_domains(value: Option<String>) -> anyhow::Result<Vec<String>> {
    let domains = value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(canonicalize_domain)
        .collect::<Vec<_>>();

    if domains.is_empty() {
        return Ok(Vec::new());
    }

    let mut deduped = domains;
    deduped.sort_unstable();
    deduped.dedup();
    Ok(deduped)
}

fn parse_trusted_keys(value: Option<&str>) -> anyhow::Result<HashMap<String, [u8; 32]>> {
    let Some(value) = value else {
        return Ok(HashMap::new());
    };

    let mut keys = HashMap::new();
    for entry in value.split_whitespace() {
        let (key_id, key_value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid FEDERATION_TRUSTED_KEYS entry {entry:?}"))?;
        let domain = extract_domain_from_key_id(key_id)
            .map(|domain| canonicalize_domain(&domain))
            .map_err(|_| anyhow::anyhow!("invalid federation key id {key_id:?}"))?;
        if domain.is_empty() {
            return Err(anyhow::anyhow!("invalid federation key id {key_id:?}"));
        }

        let key_bytes = URL_SAFE_NO_PAD
            .decode(key_value.as_bytes())
            .with_context(|| format!("invalid federation key payload for {key_id:?}"))?;
        let key_bytes: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("federation key for {key_id:?} must be 32 bytes"))?;
        keys.insert(key_id.to_owned(), key_bytes);
    }

    Ok(keys)
}

fn parse_quota_limits(env: &FederationEnv) -> anyhow::Result<FederationQuotaLimits> {
    let defaults = FederationQuotaLimits::default();
    Ok(FederationQuotaLimits {
        max_spaces: parse_nonzero_usize(env.max_spaces.as_deref(), "FEDERATION_MAX_SPACES")?
            .unwrap_or(defaults.max_spaces),
        max_records_per_hour: parse_nonzero_u64(
            env.max_records_per_hour.as_deref(),
            "FEDERATION_MAX_RECORDS_PER_HOUR",
        )?
        .unwrap_or(defaults.max_records_per_hour),
        max_bytes_per_hour: parse_nonzero_u64(
            env.max_bytes_per_hour.as_deref(),
            "FEDERATION_MAX_BYTES_PER_HOUR",
        )?
        .unwrap_or(defaults.max_bytes_per_hour),
        max_invitations_per_hour: parse_nonzero_u64(
            env.max_invitations_per_hour.as_deref(),
            "FEDERATION_MAX_INVITATIONS_PER_HOUR",
        )?
        .unwrap_or(defaults.max_invitations_per_hour),
        max_connections: parse_nonzero_usize(
            env.max_connections.as_deref(),
            "FEDERATION_MAX_CONNECTIONS",
        )?
        .unwrap_or(defaults.max_connections),
    })
}

fn parse_nonzero_usize(value: Option<&str>, name: &str) -> anyhow::Result<Option<usize>> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<usize>()
        .map_err(|error| anyhow::anyhow!("invalid {name} value {raw:?}: {error}"))?;
    if parsed == 0 {
        return Err(anyhow::anyhow!("{name} must be greater than zero"));
    }
    Ok(Some(parsed))
}

fn parse_nonzero_u64(value: Option<&str>, name: &str) -> anyhow::Result<Option<u64>> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<u64>()
        .map_err(|error| anyhow::anyhow!("invalid {name} value {raw:?}: {error}"))?;
    if parsed == 0 {
        return Err(anyhow::anyhow!("{name} must be greater than zero"));
    }
    Ok(Some(parsed))
}

fn normalize_optional_secret(value: Option<String>) -> Option<String> {
    value.and_then(|secret| {
        let trimmed = secret.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

async fn load_jwks(storage: &PostgresStorage) -> anyhow::Result<FederationJwks> {
    let keys = storage.list_federation_public_keys().await?;
    let mut jwks = Vec::with_capacity(keys.len());

    for key in keys {
        let bytes: [u8; 32] = key.public_key.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "stored federation public key {0:?} is not 32 bytes",
                key.kid
            )
        })?;
        let verifying_key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            anyhow::anyhow!("stored federation public key {0:?} is invalid", key.kid)
        })?;
        jwks.push(FederationJwk::ed25519(key.kid, &verifying_key));
    }

    Ok(FederationJwks { keys: jwks })
}

async fn load_primary_signing_key(
    storage: &PostgresStorage,
) -> anyhow::Result<Option<(String, SigningKey)>> {
    let Some(primary) = storage.get_federation_signing_key().await? else {
        return Ok(None);
    };

    let private_key: [u8; 32] = primary.private_key.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "stored federation private key {0:?} is not 32 bytes",
            primary.kid
        )
    })?;

    let signing_key = SigningKey::from_bytes(&private_key);
    if signing_key.verifying_key().as_bytes() != primary.public_key.as_slice() {
        return Err(anyhow::anyhow!(
            "stored federation key pair mismatch for {0:?}",
            primary.kid
        ));
    }

    Ok(Some((primary.kid.clone(), signing_key)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        apply_federation_runtime_config, load_primary_signing_key, parse_federation_runtime_config,
        FederationEnv, FederationRuntimeConfig,
    };
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use betterbase_sync_api::{router, ApiState};
    use betterbase_sync_storage::{migrate_with_pool, FederationStorage, PostgresStorage};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    fn test_public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn parse_federation_runtime_config_defaults() {
        let config =
            parse_federation_runtime_config(FederationEnv::default()).expect("parse federation");
        assert!(config.trusted_domains.is_empty());
        assert!(config.trusted_keys.is_empty());
        assert!(config.fst_secret.is_none());
        assert!(config.fst_previous_secret.is_none());
    }

    #[test]
    fn parse_federation_runtime_config_parses_domains_and_keys() {
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let key = URL_SAFE_NO_PAD.encode(test_public_key());
        let config = parse_federation_runtime_config(FederationEnv {
            trusted_domains: Some("PEER.example.com,other.example.com".to_owned()),
            trusted_keys: Some(format!("{key_id}={key}")),
            fst_secret: Some("secret-1".to_owned()),
            fst_previous_secret: Some("secret-0".to_owned()),
            max_spaces: Some("11".to_owned()),
            max_records_per_hour: Some("12".to_owned()),
            max_bytes_per_hour: Some("13".to_owned()),
            max_invitations_per_hour: Some("14".to_owned()),
            max_connections: Some("15".to_owned()),
        })
        .expect("parse federation");

        assert_eq!(
            config.trusted_domains,
            vec![
                "other.example.com".to_owned(),
                "peer.example.com".to_owned()
            ]
        );
        assert_eq!(config.trusted_keys.len(), 1);
        assert_eq!(config.fst_secret.as_deref(), Some("secret-1"));
        assert_eq!(config.fst_previous_secret.as_deref(), Some("secret-0"));
        assert_eq!(config.quota_limits.max_spaces, 11);
        assert_eq!(config.quota_limits.max_records_per_hour, 12);
        assert_eq!(config.quota_limits.max_bytes_per_hour, 13);
        assert_eq!(config.quota_limits.max_invitations_per_hour, 14);
        assert_eq!(config.quota_limits.max_connections, 15);
    }

    #[test]
    fn parse_federation_runtime_config_derives_domains_from_keys() {
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let key = URL_SAFE_NO_PAD.encode(test_public_key());
        let config = parse_federation_runtime_config(FederationEnv {
            trusted_domains: None,
            trusted_keys: Some(format!("{key_id}={key}")),
            ..FederationEnv::default()
        })
        .expect("parse federation");

        assert_eq!(config.trusted_domains, vec!["peer.example.com".to_owned()]);
    }

    #[test]
    fn parse_federation_runtime_config_rejects_untrusted_key_domain() {
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let key = URL_SAFE_NO_PAD.encode(test_public_key());
        let error = parse_federation_runtime_config(FederationEnv {
            trusted_domains: Some("other.example.com".to_owned()),
            trusted_keys: Some(format!("{key_id}={key}")),
            ..FederationEnv::default()
        })
        .expect_err("mismatched trusted domain should fail");

        assert!(error.to_string().contains("FEDERATION_TRUSTED_KEYS domain"));
    }

    #[test]
    fn parse_federation_runtime_config_rejects_invalid_quota_values() {
        let error = parse_federation_runtime_config(FederationEnv {
            max_connections: Some("0".to_owned()),
            ..FederationEnv::default()
        })
        .expect_err("zero limit should fail");

        assert!(error.to_string().contains("FEDERATION_MAX_CONNECTIONS"));
    }

    #[tokio::test]
    async fn apply_federation_runtime_config_handles_empty_key_state() {
        let Some(storage) = isolated_storage().await else {
            return;
        };
        let api_state = ApiState::new(Arc::new(storage.clone()));
        let configured = apply_federation_runtime_config(
            api_state,
            Arc::new(storage.clone()),
            &FederationRuntimeConfig::default(),
        )
        .await
        .expect("apply federation config");

        let primary = load_primary_signing_key(&storage)
            .await
            .expect("load primary key");
        assert!(primary.is_none());

        let kids = jwks_kids(configured).await;
        assert!(kids.is_empty());
    }

    #[tokio::test]
    async fn apply_federation_runtime_config_uses_primary_key_and_publishes_active_jwks() {
        let Some(storage) = isolated_storage().await else {
            return;
        };

        let key_a = SigningKey::from_bytes(&[11_u8; 32]);
        let key_b = SigningKey::from_bytes(&[22_u8; 32]);
        let kid_a = "https://sync.example.com/.well-known/jwks.json#fed-a";
        let kid_b = "https://sync.example.com/.well-known/jwks.json#fed-b";

        storage
            .ensure_federation_key(kid_a, &key_a.to_bytes(), key_a.verifying_key().as_bytes())
            .await
            .expect("store key a");
        storage
            .ensure_federation_key(kid_b, &key_b.to_bytes(), key_b.verifying_key().as_bytes())
            .await
            .expect("store key b");
        storage
            .set_federation_primary_key(kid_b)
            .await
            .expect("promote key b");

        let (selected_kid, selected_signing_key) = load_primary_signing_key(&storage)
            .await
            .expect("load primary key")
            .expect("primary key should exist");
        assert_eq!(selected_kid, kid_b);
        assert_eq!(selected_signing_key.to_bytes(), key_b.to_bytes());

        let api_state = ApiState::new(Arc::new(storage.clone()));
        let configured = apply_federation_runtime_config(
            api_state,
            Arc::new(storage.clone()),
            &FederationRuntimeConfig::default(),
        )
        .await
        .expect("apply federation config");

        let mut kids = jwks_kids(configured).await;
        kids.sort_unstable();
        assert_eq!(kids, vec![kid_a.to_owned(), kid_b.to_owned()]);

        storage
            .deactivate_federation_key(kid_a)
            .await
            .expect("deactivate key a");
        let api_state = ApiState::new(Arc::new(storage.clone()));
        let configured = apply_federation_runtime_config(
            api_state,
            Arc::new(storage.clone()),
            &FederationRuntimeConfig::default(),
        )
        .await
        .expect("re-apply federation config");
        assert_eq!(jwks_kids(configured).await, vec![kid_b.to_owned()]);
    }

    #[tokio::test]
    async fn apply_federation_runtime_config_rejects_mismatched_primary_keypair() {
        let Some(storage) = isolated_storage().await else {
            return;
        };

        let key = SigningKey::from_bytes(&[33_u8; 32]);
        let mismatched_public = SigningKey::from_bytes(&[44_u8; 32]).verifying_key();
        let kid = "https://sync.example.com/.well-known/jwks.json#fed-mismatch";
        storage
            .ensure_federation_key(kid, &key.to_bytes(), key.verifying_key().as_bytes())
            .await
            .expect("store key");

        sqlx::query("UPDATE federation_signing_keys SET public_key = $2 WHERE kid = $1")
            .bind(kid)
            .bind(mismatched_public.as_bytes())
            .execute(storage.pool())
            .await
            .expect("corrupt public key");

        let api_state = ApiState::new(Arc::new(storage.clone()));
        let result = apply_federation_runtime_config(
            api_state,
            Arc::new(storage.clone()),
            &FederationRuntimeConfig::default(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("mismatched keypair should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("mismatch"));
    }

    async fn isolated_storage() -> Option<PostgresStorage> {
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => return None,
        };

        // Create pool with search_path set to isolated schema.
        let schema = format!("app_fed_{}", unique_suffix());
        let mut opts: sqlx::postgres::PgConnectOptions =
            database_url.parse().expect("parse DATABASE_URL");
        opts = opts.options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("connect test database");
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&pool)
            .await
            .expect("create isolated schema");
        migrate_with_pool(&pool).await.expect("apply migrations");

        Some(PostgresStorage::from_pool(pool))
    }

    fn unique_suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    async fn jwks_kids(state: ApiState) -> Vec<String> {
        #[derive(serde::Deserialize)]
        struct JwksPayload {
            keys: Vec<JwkPayload>,
        }
        #[derive(serde::Deserialize)]
        struct JwkPayload {
            kid: String,
        }

        let app = router(state);
        let request: Request<Body> = Request::builder()
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .expect("jwks request");
        let response = app.oneshot(request).await.expect("jwks response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read jwks body");
        let parsed: JwksPayload = serde_json::from_slice(&body).expect("decode jwks response");
        parsed.keys.into_iter().map(|key| key.kid).collect()
    }
}
