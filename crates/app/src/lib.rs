#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use betterbase_sync_api::ApiState;
use betterbase_sync_auth::{normalize_issuer, MultiValidator, MultiValidatorConfig};
use betterbase_sync_core::protocol::{WsPresenceLeaveData, RPC_NOTIFICATION};
use betterbase_sync_realtime::broker::{BrokerConfig, MultiBroker};
use betterbase_sync_storage::{migrate_with_pool, PostgresStorage};
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::ObjectStore;
use serde::Serialize;
use url::Url;

mod federation;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub trusted_issuers: HashMap<String, String>,
    pub audiences: Vec<String>,
    pub file_storage: FileStorageConfig,
    pub identity_hash_key: Option<Vec<u8>>,
    federation: federation::FederationRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStorageConfig {
    Disabled,
    Local {
        path: PathBuf,
    },
    S3 {
        endpoint: String,
        access_key: String,
        secret_key: String,
        bucket: String,
        region: String,
        use_ssl: bool,
    },
}

#[derive(Debug, Clone, Default)]
struct FileStorageEnv {
    backend: Option<String>,
    path: Option<String>,
    s3_endpoint: Option<String>,
    s3_access_key: Option<String>,
    s3_secret_key: Option<String>,
    s3_bucket: Option<String>,
    s3_region: Option<String>,
    s3_use_ssl: Option<String>,
}

impl FileStorageEnv {
    fn from_env() -> Self {
        Self {
            backend: std::env::var("FILE_STORAGE_BACKEND")
                .ok()
                .or_else(|| std::env::var("FILE_STORAGE").ok()),
            path: std::env::var("FILE_STORAGE_PATH")
                .ok()
                .or_else(|| std::env::var("FILE_FS_PATH").ok()),
            s3_endpoint: std::env::var("FILE_S3_ENDPOINT").ok(),
            s3_access_key: std::env::var("FILE_S3_ACCESS_KEY").ok(),
            s3_secret_key: std::env::var("FILE_S3_SECRET_KEY").ok(),
            s3_bucket: std::env::var("FILE_S3_BUCKET").ok(),
            s3_region: std::env::var("FILE_S3_REGION").ok(),
            s3_use_ssl: std::env::var("FILE_S3_USE_SSL").ok(),
        }
    }
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config = Self::from_values(
            Some(std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:5379".to_string())),
            std::env::var("DATABASE_URL").ok(),
            std::env::var("TRUSTED_ISSUERS").ok(),
            std::env::var("AUDIENCES").ok(),
        )?;
        config.file_storage = parse_file_storage(FileStorageEnv::from_env())?;
        config.identity_hash_key =
            parse_identity_hash_key(std::env::var("IDENTITY_HASH_KEY").ok())?;
        config.federation =
            federation::parse_federation_runtime_config(federation::FederationEnv::from_env())?;
        Ok(config)
    }

    fn from_values(
        listen_addr: Option<String>,
        database_url: Option<String>,
        trusted_issuers: Option<String>,
        audiences: Option<String>,
    ) -> anyhow::Result<Self> {
        let listen_addr = SocketAddr::from_str(listen_addr.as_deref().unwrap_or("0.0.0.0:5379"))?;
        let database_url =
            database_url.ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set"))?;
        let trusted_issuers = parse_trusted_issuers(trusted_issuers)?;
        let audiences = parse_audiences(audiences);

        Ok(Self {
            listen_addr,
            database_url,
            trusted_issuers,
            audiences,
            file_storage: FileStorageConfig::Disabled,
            identity_hash_key: None,
            federation: federation::FederationRuntimeConfig::default(),
        })
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let storage = Arc::new(PostgresStorage::connect(&config.database_url).await?);
    migrate_with_pool(storage.pool()).await?;
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let validator = Arc::new(MultiValidator::new(MultiValidatorConfig {
        trusted_issuers: config.trusted_issuers.clone(),
        audiences: config.audiences.clone(),
        ..MultiValidatorConfig::default()
    }));
    let mut api_state = ApiState::new(storage.clone())
        .with_websocket(validator)
        .with_realtime_broker(broker)
        .with_sync_storage(storage.clone());

    if let Some(key) = config.identity_hash_key {
        api_state = api_state.with_identity_hash_key(key);
    }

    if let Some(file_storage) = build_file_object_store(&config.file_storage)? {
        api_state = api_state.with_file_object_store(file_storage);
    }
    api_state =
        federation::apply_federation_runtime_config(api_state, storage, &config.federation).await?;

    if let (Some(presence_registry), Some(broker)) =
        (api_state.presence_registry(), api_state.realtime_broker())
    {
        tokio::spawn(presence_cleanup_loop(presence_registry, broker));
    }

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "server listening");
    axum::serve(listener, betterbase_sync_api::router(api_state)).await?;
    Ok(())
}

/// Periodically remove stale presence entries and broadcast leave notifications.
async fn presence_cleanup_loop(
    registry: Arc<betterbase_sync_api::PresenceRegistry>,
    broker: Arc<MultiBroker>,
) {
    const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    interval.tick().await; // first tick fires immediately, skip it
    loop {
        interval.tick().await;
        let stale: Vec<(String, String)> = registry.cleanup_stale_entries().await;
        for (space_id, pseudonym) in &stale {
            broadcast_presence_leave(&broker, space_id, pseudonym).await;
        }
        if !stale.is_empty() {
            tracing::debug!(count = stale.len(), "cleaned up stale presence entries");
        }
    }
}

async fn broadcast_presence_leave(broker: &MultiBroker, space_id: &str, pseudonym: &str) {
    #[derive(Serialize)]
    struct NotificationFrame<'a, T: Serialize> {
        #[serde(rename = "type")]
        frame_type: i32,
        #[serde(rename = "method")]
        method: &'a str,
        #[serde(rename = "params")]
        params: T,
    }

    let frame = NotificationFrame {
        frame_type: RPC_NOTIFICATION,
        method: "presence.leave",
        params: WsPresenceLeaveData {
            space: space_id.to_owned(),
            peer: pseudonym.to_owned(),
        },
    };
    let Ok(encoded) = minicbor_serde::to_vec(&frame) else {
        return;
    };
    // Empty exclude_id: cleanup timer has no connection identity.
    broker.broadcast_space(space_id, "", &encoded).await;
}

fn build_file_object_store(
    config: &FileStorageConfig,
) -> anyhow::Result<Option<Arc<dyn ObjectStore>>> {
    match config {
        FileStorageConfig::Disabled => Ok(None),
        FileStorageConfig::Local { path } => {
            std::fs::create_dir_all(path)?;
            let storage = LocalFileSystem::new_with_prefix(path)?;
            Ok(Some(Arc::new(storage)))
        }
        FileStorageConfig::S3 {
            endpoint,
            access_key,
            secret_key,
            bucket,
            region,
            use_ssl,
        } => {
            let endpoint = normalize_s3_endpoint(endpoint, *use_ssl);
            let mut builder = AmazonS3Builder::new()
                .with_endpoint(endpoint.clone())
                .with_access_key_id(access_key)
                .with_secret_access_key(secret_key)
                .with_bucket_name(bucket)
                .with_region(region)
                .with_virtual_hosted_style_request(false);
            if endpoint.starts_with("http://") {
                builder = builder.with_allow_http(true);
            }
            let storage = builder.build().map_err(|error| {
                anyhow::anyhow!("failed to initialize S3 object store: {error}")
            })?;
            Ok(Some(Arc::new(storage)))
        }
    }
}

fn parse_trusted_issuers(value: Option<String>) -> anyhow::Result<HashMap<String, String>> {
    let raw = value.ok_or_else(|| anyhow::anyhow!("TRUSTED_ISSUERS must be set"))?;
    let mut issuers = HashMap::new();

    for entry in raw.split_whitespace() {
        let (issuer_raw, explicit_jwks) = match entry.split_once('=') {
            Some((issuer, jwks_url)) => (issuer, Some(jwks_url)),
            None => (entry, None),
        };

        validate_http_url(issuer_raw, "issuer")?;
        let normalized = normalize_issuer(issuer_raw);
        let jwks_url = match explicit_jwks {
            Some(url) => {
                validate_http_url(url, "jwks_url")?;
                url.to_owned()
            }
            None => format!("{normalized}/.well-known/jwks.json"),
        };
        issuers.insert(normalized, jwks_url);
    }

    if issuers.is_empty() {
        return Err(anyhow::anyhow!("TRUSTED_ISSUERS must be set"));
    }

    Ok(issuers)
}

fn parse_audiences(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_identity_hash_key(value: Option<String>) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let key =
        hex::decode(raw).map_err(|_| anyhow::anyhow!("IDENTITY_HASH_KEY must be valid hex"))?;
    if key.len() != 32 {
        return Err(anyhow::anyhow!(
            "IDENTITY_HASH_KEY must be 64 hex characters (32 bytes), got {} bytes",
            key.len()
        ));
    }
    Ok(Some(key))
}

fn parse_file_storage(env: FileStorageEnv) -> anyhow::Result<FileStorageConfig> {
    let backend = env.backend.unwrap_or_else(|| "none".to_owned());
    match backend.as_str() {
        "none" => Ok(FileStorageConfig::Disabled),
        "local" | "fs" => Ok(FileStorageConfig::Local {
            path: PathBuf::from(env.path.unwrap_or_else(|| "./data/files".to_owned())),
        }),
        "s3" => {
            let endpoint = required_s3_var(env.s3_endpoint, "FILE_S3_ENDPOINT")?;
            let access_key = required_s3_var(env.s3_access_key, "FILE_S3_ACCESS_KEY")?;
            let secret_key = required_s3_var(env.s3_secret_key, "FILE_S3_SECRET_KEY")?;
            let bucket = required_s3_var(env.s3_bucket, "FILE_S3_BUCKET")?;
            let region = env.s3_region.unwrap_or_else(|| "us-east-1".to_owned());
            let use_ssl = env.s3_use_ssl.as_deref() != Some("false");

            Ok(FileStorageConfig::S3 {
                endpoint,
                access_key,
                secret_key,
                bucket,
                region,
                use_ssl,
            })
        }
        _ => Err(anyhow::anyhow!(
            "invalid FILE_STORAGE_BACKEND {:?}: expected \"none\", \"local\", or \"s3\"",
            backend
        )),
    }
}

fn required_s3_var(value: Option<String>, name: &str) -> anyhow::Result<String> {
    let Some(value) = value.map(|value| value.trim().to_owned()) else {
        return Err(anyhow::anyhow!(
            "{name} is required when FILE_STORAGE_BACKEND=s3"
        ));
    };
    if value.is_empty() {
        return Err(anyhow::anyhow!(
            "{name} is required when FILE_STORAGE_BACKEND=s3"
        ));
    }
    Ok(value)
}

fn normalize_s3_endpoint(endpoint: &str, use_ssl: bool) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_owned()
    } else if use_ssl {
        format!("https://{endpoint}")
    } else {
        format!("http://{endpoint}")
    }
}

fn validate_http_url(raw: &str, label: &str) -> anyhow::Result<()> {
    let parsed =
        Url::parse(raw).map_err(|error| anyhow::anyhow!("invalid {label} URL {raw:?}: {error}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(anyhow::anyhow!(
            "invalid {label} URL {raw:?}: must use http or https"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        build_file_object_store, parse_file_storage, AppConfig, FileStorageConfig, FileStorageEnv,
    };

    #[test]
    fn from_values_uses_default_listen_addr() {
        let config = AppConfig::from_values(
            None,
            Some("postgres://localhost/less-sync".to_owned()),
            Some("https://accounts.less.so".to_owned()),
            None,
        )
        .expect("parse config");

        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:5379");
        assert_eq!(config.database_url, "postgres://localhost/less-sync");
        assert_eq!(
            config
                .trusted_issuers
                .get("https://accounts.less.so")
                .expect("issuer"),
            "https://accounts.less.so/.well-known/jwks.json"
        );
    }

    #[test]
    fn from_values_requires_database_url() {
        let error = AppConfig::from_values(
            Some("127.0.0.1:5379".to_owned()),
            None,
            Some("https://accounts.less.so".to_owned()),
            None,
        )
        .expect_err("missing DATABASE_URL should fail");

        assert!(error.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn from_values_validates_listen_addr() {
        let error = AppConfig::from_values(
            Some("not-an-address".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
            Some("https://accounts.less.so".to_owned()),
            None,
        )
        .expect_err("invalid listen address should fail");

        assert!(error.to_string().contains("invalid"));
    }

    #[test]
    fn from_values_requires_trusted_issuers() {
        let error = AppConfig::from_values(
            Some("127.0.0.1:5379".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
            None,
            None,
        )
        .expect_err("missing trusted issuers should fail");

        assert!(error.to_string().contains("TRUSTED_ISSUERS"));
    }

    #[test]
    fn from_values_parses_explicit_jwks_urls() {
        let config = AppConfig::from_values(
            Some("127.0.0.1:5379".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
            Some("https://accounts.less.so=http://auth.internal/.well-known/jwks.json".to_owned()),
            None,
        )
        .expect("parse config");

        assert_eq!(
            config
                .trusted_issuers
                .get("https://accounts.less.so")
                .expect("issuer"),
            "http://auth.internal/.well-known/jwks.json"
        );
    }

    #[test]
    fn from_values_parses_comma_separated_audiences() {
        let config = AppConfig::from_values(
            Some("127.0.0.1:5379".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
            Some("https://accounts.less.so".to_owned()),
            Some("betterbase-sync, less-sync-local ,".to_owned()),
        )
        .expect("parse config");

        assert_eq!(config.audiences, vec!["betterbase-sync", "betterbase-sync-local"]);
    }

    #[test]
    fn from_values_rejects_invalid_issuer_urls() {
        let error = AppConfig::from_values(
            Some("127.0.0.1:5379".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
            Some("not-a-url".to_owned()),
            None,
        )
        .expect_err("invalid issuer URL should fail");

        assert!(error.to_string().contains("invalid issuer URL"));
    }

    #[test]
    fn parse_file_storage_defaults_to_disabled() {
        let config = parse_file_storage(FileStorageEnv::default()).expect("parse file storage");
        assert_eq!(config, FileStorageConfig::Disabled);
    }

    #[test]
    fn parse_file_storage_local_uses_default_path() {
        let config = parse_file_storage(FileStorageEnv {
            backend: Some("local".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::Local {
                path: PathBuf::from("./data/files"),
            }
        );
    }

    #[test]
    fn parse_file_storage_local_uses_explicit_path() {
        let config = parse_file_storage(FileStorageEnv {
            backend: Some("local".to_owned()),
            path: Some("/tmp/less-sync-files".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::Local {
                path: PathBuf::from("/tmp/less-sync-files"),
            }
        );
    }

    #[test]
    fn parse_file_storage_supports_fs_alias() {
        let config = parse_file_storage(FileStorageEnv {
            backend: Some("fs".to_owned()),
            path: Some("/tmp/less-sync-files".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::Local {
                path: PathBuf::from("/tmp/less-sync-files"),
            }
        );
    }

    #[test]
    fn parse_file_storage_s3_defaults_region_and_ssl() {
        let config = parse_file_storage(FileStorageEnv {
            backend: Some("s3".to_owned()),
            s3_endpoint: Some("minio.internal:9000".to_owned()),
            s3_access_key: Some("access".to_owned()),
            s3_secret_key: Some("secret".to_owned()),
            s3_bucket: Some("betterbase-sync".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::S3 {
                endpoint: "minio.internal:9000".to_owned(),
                access_key: "access".to_owned(),
                secret_key: "secret".to_owned(),
                bucket: "betterbase-sync".to_owned(),
                region: "us-east-1".to_owned(),
                use_ssl: true,
            }
        );
    }

    #[test]
    fn parse_file_storage_s3_supports_region_and_ssl_override() {
        let config = parse_file_storage(FileStorageEnv {
            backend: Some("s3".to_owned()),
            s3_endpoint: Some("minio.internal:9000".to_owned()),
            s3_access_key: Some("access".to_owned()),
            s3_secret_key: Some("secret".to_owned()),
            s3_bucket: Some("betterbase-sync".to_owned()),
            s3_region: Some("auto".to_owned()),
            s3_use_ssl: Some("false".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::S3 {
                endpoint: "minio.internal:9000".to_owned(),
                access_key: "access".to_owned(),
                secret_key: "secret".to_owned(),
                bucket: "betterbase-sync".to_owned(),
                region: "auto".to_owned(),
                use_ssl: false,
            }
        );
    }

    #[test]
    fn parse_file_storage_s3_requires_endpoint() {
        let error = parse_file_storage(FileStorageEnv {
            backend: Some("s3".to_owned()),
            s3_access_key: Some("access".to_owned()),
            s3_secret_key: Some("secret".to_owned()),
            s3_bucket: Some("betterbase-sync".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect_err("missing endpoint should fail");
        assert!(error.to_string().contains("FILE_S3_ENDPOINT"));
    }

    #[test]
    fn parse_file_storage_rejects_invalid_backend() {
        let error = parse_file_storage(FileStorageEnv {
            backend: Some("gcs".to_owned()),
            ..FileStorageEnv::default()
        })
        .expect_err("invalid backend should fail");
        assert!(error.to_string().contains("FILE_STORAGE_BACKEND"));
    }

    #[test]
    fn build_file_object_store_s3_constructs_without_network_calls() {
        let config = FileStorageConfig::S3 {
            endpoint: "localhost:9000".to_owned(),
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            bucket: "betterbase-sync".to_owned(),
            region: "us-east-1".to_owned(),
            use_ssl: false,
        };
        let store = build_file_object_store(&config).expect("build object store");
        assert!(store.is_some());
    }

    #[test]
    fn parse_identity_hash_key_accepts_32_byte_hex() {
        let key = "a".repeat(64);
        let result = super::parse_identity_hash_key(Some(key)).expect("valid key");
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn parse_identity_hash_key_rejects_wrong_length() {
        let key = "aa".repeat(16); // 16 bytes (32 hex chars)
        let error = super::parse_identity_hash_key(Some(key)).expect_err("wrong length");
        assert!(error.to_string().contains("32 bytes"));
    }

    #[test]
    fn parse_identity_hash_key_rejects_non_hex() {
        let error =
            super::parse_identity_hash_key(Some("not-hex".to_owned())).expect_err("invalid hex");
        assert!(error.to_string().contains("IDENTITY_HASH_KEY"));
    }

    #[test]
    fn parse_identity_hash_key_returns_none_when_absent() {
        assert!(super::parse_identity_hash_key(None).unwrap().is_none());
    }

    #[test]
    fn parse_identity_hash_key_returns_none_for_empty_string() {
        assert!(super::parse_identity_hash_key(Some(String::new()))
            .unwrap()
            .is_none());
    }
}
