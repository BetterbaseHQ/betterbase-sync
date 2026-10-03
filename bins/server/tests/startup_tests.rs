use std::process::Command;

#[test]
fn server_reports_configuration_and_database_failures() {
    for database in [None, Some("invalid-database-url")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_betterbase-sync-server"));
        command
            .env_remove("DATABASE_URL")
            .env("TRUSTED_ISSUERS", "https://issuer.example");
        if let Some(url) = database {
            command.env("DATABASE_URL", url);
        }
        let output = command.output().expect("run server");
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).expect("stderr");
        assert!(
            error.contains(if database.is_some() {
                "database error"
            } else {
                "DATABASE_URL"
            }),
            "{error}"
        );
    }
}
