#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use less_sync_api::{ApiState, ObjectStoreFileBlobStorage};
use less_sync_auth::{normalize_issuer, MultiValidator, MultiValidatorConfig};
use less_sync_realtime::broker::{BrokerConfig, MultiBroker};
use less_sync_storage::PostgresStorage;
use url::Url;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub trusted_issuers: HashMap<String, String>,
    pub audiences: Vec<String>,
    pub file_storage: FileStorageConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStorageConfig {
    Disabled,
    Local { path: PathBuf },
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config = Self::from_values(
            Some(std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5379".to_string())),
            std::env::var("DATABASE_URL").ok(),
            std::env::var("TRUSTED_ISSUERS").ok(),
            std::env::var("AUDIENCES").ok(),
        )?;
        config.file_storage = parse_file_storage(
            std::env::var("FILE_STORAGE_BACKEND").ok(),
            std::env::var("FILE_STORAGE_PATH").ok(),
        )?;
        Ok(config)
    }

    fn from_values(
        listen_addr: Option<String>,
        database_url: Option<String>,
        trusted_issuers: Option<String>,
        audiences: Option<String>,
    ) -> anyhow::Result<Self> {
        let listen_addr = SocketAddr::from_str(listen_addr.as_deref().unwrap_or("127.0.0.1:5379"))?;
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
        })
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let storage = Arc::new(PostgresStorage::connect(&config.database_url).await?);
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

    if let Some(file_storage) = build_file_blob_storage(&config.file_storage)? {
        api_state = api_state.with_object_store_file_storage(file_storage);
    }

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "server listening");
    axum::serve(listener, less_sync_api::router(api_state)).await?;
    Ok(())
}

fn build_file_blob_storage(
    config: &FileStorageConfig,
) -> anyhow::Result<Option<Arc<ObjectStoreFileBlobStorage>>> {
    match config {
        FileStorageConfig::Disabled => Ok(None),
        FileStorageConfig::Local { path } => {
            std::fs::create_dir_all(path)?;
            let storage = ObjectStoreFileBlobStorage::local_filesystem(path)?;
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

fn parse_file_storage(
    backend: Option<String>,
    path: Option<String>,
) -> anyhow::Result<FileStorageConfig> {
    let backend = backend.unwrap_or_else(|| "none".to_owned());
    match backend.as_str() {
        "none" => Ok(FileStorageConfig::Disabled),
        "local" => Ok(FileStorageConfig::Local {
            path: PathBuf::from(path.unwrap_or_else(|| "./data/files".to_owned())),
        }),
        _ => Err(anyhow::anyhow!(
            "invalid FILE_STORAGE_BACKEND {:?}: expected \"none\" or \"local\"",
            backend
        )),
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

    use super::{parse_file_storage, AppConfig, FileStorageConfig};

    #[test]
    fn from_values_uses_default_listen_addr() {
        let config = AppConfig::from_values(
            None,
            Some("postgres://localhost/less-sync".to_owned()),
            Some("https://accounts.less.so".to_owned()),
            None,
        )
        .expect("parse config");

        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:5379");
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
            Some("less-sync, less-sync-local ,".to_owned()),
        )
        .expect("parse config");

        assert_eq!(config.audiences, vec!["less-sync", "less-sync-local"]);
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
        let config = parse_file_storage(None, None).expect("parse file storage");
        assert_eq!(config, FileStorageConfig::Disabled);
    }

    #[test]
    fn parse_file_storage_local_uses_default_path() {
        let config =
            parse_file_storage(Some("local".to_owned()), None).expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::Local {
                path: PathBuf::from("./data/files"),
            }
        );
    }

    #[test]
    fn parse_file_storage_local_uses_explicit_path() {
        let config = parse_file_storage(
            Some("local".to_owned()),
            Some("/tmp/less-sync-files".to_owned()),
        )
        .expect("parse file storage");
        assert_eq!(
            config,
            FileStorageConfig::Local {
                path: PathBuf::from("/tmp/less-sync-files"),
            }
        );
    }

    #[test]
    fn parse_file_storage_rejects_invalid_backend() {
        let error = parse_file_storage(Some("s3".to_owned()), None)
            .expect_err("invalid backend should fail");
        assert!(error.to_string().contains("FILE_STORAGE_BACKEND"));
    }
}
