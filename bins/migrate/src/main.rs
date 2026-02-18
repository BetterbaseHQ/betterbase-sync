#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    less_sync_storage::migrate().await?;
    println!("migrations complete");
    Ok(())
}
