#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    betterbase_sync_storage::migrate().await?;
    println!("migrations complete");
    Ok(())
}
