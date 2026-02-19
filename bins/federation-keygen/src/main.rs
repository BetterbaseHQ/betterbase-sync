#![forbid(unsafe_code)]

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use less_sync_auth::canonicalize_domain;
use less_sync_storage::PostgresStorage;
use rand_core::OsRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = parse_args(env::args())?;
    run(config).await
}

async fn run(config: KeygenConfig) -> anyhow::Result<()> {
    let domain = canonicalize_domain(&config.domain);
    if domain.is_empty() {
        return Err(anyhow::anyhow!("domain must not be empty"));
    }

    let key_fragment = config.kid.unwrap_or_else(default_key_fragment);
    let key_id = format!("https://{domain}/.well-known/jwks.json#{key_fragment}");

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let private_seed = signing_key.to_bytes();
    let public_key = verifying_key.to_bytes();

    if let Some(database_url) = config.database_url.as_deref() {
        let storage = PostgresStorage::connect(database_url).await?;
        storage
            .ensure_federation_key(&key_id, &private_seed, &public_key)
            .await?;
    }

    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key);
    let private_seed_b64 = URL_SAFE_NO_PAD.encode(private_seed);
    println!("Generated federation signing key");
    println!("key_id={key_id}");
    println!("public_key_base64url={public_key_b64}");
    println!("trusted_keys_entry={key_id}={public_key_b64}");
    if config.print_private {
        println!("private_seed_base64url={private_seed_b64}");
    } else {
        println!("private_seed_base64url=<hidden> (pass --print-private to show)");
    }
    if config.database_url.is_some() {
        println!("stored_in_database=true");
    } else {
        println!("stored_in_database=false");
        println!("hint=set --database-url or DATABASE_URL to persist this key");
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeygenConfig {
    domain: String,
    kid: Option<String>,
    database_url: Option<String>,
    print_private: bool,
}

fn parse_args<I>(args: I) -> anyhow::Result<KeygenConfig>
where
    I: IntoIterator<Item = String>,
{
    let mut domain = None;
    let mut kid = None;
    let mut database_url = env::var("DATABASE_URL").ok();
    let mut print_private = false;

    let mut iter = args.into_iter();
    let _program = iter.next();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--domain" => {
                let Some(value) = iter.next() else {
                    return Err(anyhow::anyhow!("--domain requires a value"));
                };
                domain = Some(value);
            }
            "--kid" => {
                let Some(value) = iter.next() else {
                    return Err(anyhow::anyhow!("--kid requires a value"));
                };
                kid = Some(value);
            }
            "--database-url" => {
                let Some(value) = iter.next() else {
                    return Err(anyhow::anyhow!("--database-url requires a value"));
                };
                database_url = Some(value);
            }
            "--print-private" => {
                print_private = true;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            unknown => {
                return Err(anyhow::anyhow!("unknown argument {unknown:?}"));
            }
        }
    }

    let domain = domain.ok_or_else(|| anyhow::anyhow!("--domain is required"))?;
    Ok(KeygenConfig {
        domain,
        kid,
        database_url,
        print_private,
    })
}

fn default_key_fragment() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("fed-{}-{}", now.as_secs(), now.subsec_nanos())
}

fn print_usage() {
    println!(
        "Usage: less-sync-federation-keygen --domain <domain> [--kid <key-fragment>] [--database-url <url>] [--print-private]"
    );
    println!("  --domain: public sync domain used in key id URL");
    println!("  --kid: key fragment appended to #... (default: fed-<time>)");
    println!("  --database-url: Postgres URL to persist generated key (default: DATABASE_URL env)");
    println!("  --print-private: include private seed in output");
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn parse_args_requires_domain() {
        let error = parse_args(vec!["federation-keygen".to_owned()])
            .expect_err("missing domain should fail");
        assert!(error.to_string().contains("--domain is required"));
    }

    #[test]
    fn parse_args_parses_values() {
        let config = parse_args(vec![
            "federation-keygen".to_owned(),
            "--domain".to_owned(),
            "Sync.Example.com".to_owned(),
            "--kid".to_owned(),
            "fed-1".to_owned(),
            "--database-url".to_owned(),
            "postgres://localhost/db".to_owned(),
            "--print-private".to_owned(),
        ])
        .expect("parse args");

        assert_eq!(config.domain, "Sync.Example.com");
        assert_eq!(config.kid.as_deref(), Some("fed-1"));
        assert_eq!(
            config.database_url.as_deref(),
            Some("postgres://localhost/db")
        );
        assert!(config.print_private);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let error = parse_args(vec![
            "federation-keygen".to_owned(),
            "--domain".to_owned(),
            "sync.example.com".to_owned(),
            "--unknown".to_owned(),
        ])
        .expect_err("unknown flag should fail");
        assert!(error.to_string().contains("unknown argument"));
    }
}
