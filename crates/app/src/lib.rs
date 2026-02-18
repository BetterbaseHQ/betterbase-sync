#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use less_sync_api::ApiState;
use less_sync_storage::PostgresStorage;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub database_url: String,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_values(
            Some(std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5379".to_string())),
            std::env::var("DATABASE_URL").ok(),
        )
    }

    fn from_values(
        listen_addr: Option<String>,
        database_url: Option<String>,
    ) -> anyhow::Result<Self> {
        let listen_addr = SocketAddr::from_str(listen_addr.as_deref().unwrap_or("127.0.0.1:5379"))?;
        let database_url =
            database_url.ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set"))?;
        Ok(Self {
            listen_addr,
            database_url,
        })
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let storage = Arc::new(PostgresStorage::connect(&config.database_url).await?);
    let api_state = ApiState::new(storage);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "server listening");
    axum::serve(listener, less_sync_api::router(api_state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    #[test]
    fn from_values_uses_default_listen_addr() {
        let config =
            AppConfig::from_values(None, Some("postgres://localhost/less-sync".to_owned()))
                .expect("parse config");
        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:5379");
        assert_eq!(config.database_url, "postgres://localhost/less-sync");
    }

    #[test]
    fn from_values_requires_database_url() {
        let error = AppConfig::from_values(Some("127.0.0.1:5379".to_owned()), None)
            .expect_err("missing DATABASE_URL should fail");
        assert!(error.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn from_values_validates_listen_addr() {
        let error = AppConfig::from_values(
            Some("not-an-address".to_owned()),
            Some("postgres://localhost/less-sync".to_owned()),
        )
        .expect_err("invalid listen address should fail");
        assert!(error.to_string().contains("invalid"));
    }
}
