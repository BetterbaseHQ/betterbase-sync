use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_betterbase-sync-federation-keygen"));
    command.env_remove("DATABASE_URL");
    command
}

#[test]
fn help_and_argument_errors_have_appropriate_exit_status() {
    for flag in ["--help", "-h"] {
        let output = command().arg(flag).output().expect("help");
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("--domain"));
    }
    for flag in ["--domain", "--kid", "--database-url"] {
        let output = command().arg(flag).output().expect("missing value");
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains(&format!("{flag} requires a value")));
    }
    let output = command()
        .args(["--domain", ""])
        .output()
        .expect("empty domain");
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("domain must not be empty"));
}

#[test]
fn offline_key_generation_hides_private_seed_unless_explicitly_requested() {
    for reveal in [false, true] {
        let mut cmd = command();
        cmd.args(["--domain", "Sync.Example.com", "--kid", "cli-key"]);
        if reveal {
            cmd.arg("--print-private");
        }
        let output = cmd.output().expect("key generation");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("key_id=https://sync.example.com/.well-known/jwks.json#cli-key"));
        assert!(stdout.contains("stored_in_database=false"));
        let value = |key: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .to_owned()
        };
        let public = URL_SAFE_NO_PAD
            .decode(value("public_key_base64url="))
            .unwrap();
        assert_eq!(public.len(), 32);
        let private = value("private_seed_base64url=");
        if reveal {
            let seed: [u8; 32] = URL_SAFE_NO_PAD.decode(private).unwrap().try_into().unwrap();
            assert_eq!(
                SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                public.as_slice()
            );
        } else {
            assert!(private.starts_with("<hidden>"));
        }
    }
}
