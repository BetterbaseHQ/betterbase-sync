#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let raw = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:5379".to_string());
        let listen_addr = SocketAddr::from_str(&raw)?;
        Ok(Self { listen_addr })
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "server listening");
    axum::serve(listener, less_sync_api::router()).await?;
    Ok(())
}
