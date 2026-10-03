//! Exercise env-based startup configuration in isolated child processes.
use super::*;
const CONFIG_VARS: &[&str] = &[
    "LISTEN_ADDR",
    "DATABASE_URL",
    "TRUSTED_ISSUERS",
    "AUDIENCES",
    "FILE_STORAGE_BACKEND",
    "FILE_STORAGE",
    "FILE_STORAGE_PATH",
    "FILE_FS_PATH",
    "FILE_S3_ENDPOINT",
    "FILE_S3_ACCESS_KEY",
    "FILE_S3_SECRET_KEY",
    "FILE_S3_BUCKET",
    "FILE_S3_REGION",
    "FILE_S3_USE_SSL",
    "FILE_DELETION_GRACE_SECS",
    "IDENTITY_HASH_KEY",
    "FEDERATION_TRUSTED_DOMAINS",
    "FEDERATION_TRUSTED_KEYS",
    "FEDERATION_FST_SECRET",
    "FEDERATION_FST_PREVIOUS_SECRET",
    "FEDERATION_MAX_SPACES",
    "FEDERATION_MAX_RECORDS_PER_HOUR",
    "FEDERATION_MAX_BYTES_PER_HOUR",
    "FEDERATION_MAX_INVITATIONS_PER_HOUR",
    "FEDERATION_MAX_CONNECTIONS",
    "FEDERATION_TRUST_FORWARDED_PROTO",
];

#[test]
fn environment_configuration_is_read_without_mutating_other_tests() {
    if let Ok(mode) = std::env::var("BB_CONFIG_TEST_CHILD") {
        let config = AppConfig::from_env().expect("environment config");
        assert_eq!(config.database_url, "postgres://config-only");
        assert_eq!(config.trusted_issuers.len(), 1);
        match mode.as_str() {
            "full" => {
                assert_eq!(
                    config.listen_addr,
                    "127.0.0.1:5777".parse().expect("address")
                );
                assert_eq!(config.file_deletion_grace, Duration::from_secs(7));
                assert_eq!(config.identity_hash_key, Some(vec![0xab; 32]));
                assert_eq!(config.audiences, vec!["first", "second"]);
                assert!(
                    matches!(config.file_storage,FileStorageConfig::Local{ref path} if path==&PathBuf::from("config-canonical"))
                );
                assert_eq!(config.federation.trusted_domains, vec!["peer.example"]);
                assert_eq!(config.federation.fst_secret.as_deref(), Some("current"));
                assert_eq!(
                    config.federation.fst_previous_secret.as_deref(),
                    Some("previous")
                );
                assert!(config.federation.trust_forwarded_proto);
                assert_eq!(config.federation.quota_limits.max_connections, 3);
                assert_eq!(config.federation.quota_limits.max_spaces, 4);
                assert_eq!(config.federation.quota_limits.max_records_per_hour, 5);
                assert_eq!(config.federation.quota_limits.max_bytes_per_hour, 6);
                assert_eq!(config.federation.quota_limits.max_invitations_per_hour, 7);
            }
            "legacy" => {
                assert!(
                    matches!(config.file_storage,FileStorageConfig::Local{ref path} if path==&PathBuf::from("config-legacy"))
                );
            }
            "default" => {
                assert_eq!(config.listen_addr, "0.0.0.0:5379".parse().expect("address"));
                assert!(matches!(config.file_storage, FileStorageConfig::Disabled));
                assert_eq!(config.file_deletion_grace, DEFAULT_FILE_DELETION_GRACE);
            }
            _ => panic!("unexpected mode"),
        }
        return;
    }
    for mode in ["full", "legacy", "default"] {
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"));
        child.args([
            "--exact",
            "config_env_tests::environment_configuration_is_read_without_mutating_other_tests",
            "--nocapture",
        ]);
        for key in CONFIG_VARS {
            child.env_remove(key);
        }
        child
            .env("BB_CONFIG_TEST_CHILD", mode)
            .env("DATABASE_URL", "postgres://config-only")
            .env("TRUSTED_ISSUERS", "https://issuer.example");
        if mode == "full" {
            for (key, value) in [
                ("LISTEN_ADDR", "127.0.0.1:5777"),
                ("AUDIENCES", "first,second"),
                ("FILE_STORAGE_BACKEND", "local"),
                ("FILE_STORAGE_PATH", "config-canonical"),
                ("FILE_STORAGE", "none"),
                ("FILE_FS_PATH", "wrong-legacy"),
                ("FILE_DELETION_GRACE_SECS", "7"),
                ("FEDERATION_TRUSTED_DOMAINS", "PEER.example"),
                ("FEDERATION_FST_SECRET", " current "),
                ("FEDERATION_FST_PREVIOUS_SECRET", " previous "),
                ("FEDERATION_MAX_CONNECTIONS", "3"),
                ("FEDERATION_MAX_SPACES", "4"),
                ("FEDERATION_MAX_RECORDS_PER_HOUR", "5"),
                ("FEDERATION_MAX_BYTES_PER_HOUR", "6"),
                ("FEDERATION_MAX_INVITATIONS_PER_HOUR", "7"),
                ("FEDERATION_TRUST_FORWARDED_PROTO", "true"),
            ] {
                child.env(key, value);
            }
            child.env("IDENTITY_HASH_KEY", "ab".repeat(32));
        } else if mode == "legacy" {
            child
                .env("FILE_STORAGE", "fs")
                .env("FILE_FS_PATH", "config-legacy");
        }
        let result = child.output().expect("config child");
        assert!(
            result.status.success(),
            "{mode}: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
