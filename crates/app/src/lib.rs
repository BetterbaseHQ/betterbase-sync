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
        let raw = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5379".to_string());
        let listen_addr = SocketAddr::from_str(&raw)?;
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
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
