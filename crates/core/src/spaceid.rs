use uuid::Uuid;

/// LessNamespace is the root UUID namespace for the Less platform.
/// Computed as UUID5(DNS, "betterbase.dev").
pub fn less_namespace() -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"betterbase.dev")
}

/// Personal computes the deterministic personal space ID for a user.
/// Formula: UUID5(LESS_NS, "{issuer}\0{user_id}\0{client_id}")
pub fn personal(issuer: &str, user_id: &str, client_id: &str) -> Uuid {
    let name = format!("{issuer}\0{user_id}\0{client_id}");
    Uuid::new_v5(&less_namespace(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn less_namespace_matches_expected_value() {
        let expected = Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"betterbase.dev");
        let got = less_namespace();
        assert_eq!(got, expected);
        assert_eq!(got.get_version_num(), 5);
    }

    #[test]
    fn personal_is_deterministic() {
        let id1 = personal("https://accounts.example.com", "user-123", "client-abc");
        let id2 = personal("https://accounts.example.com", "user-123", "client-abc");

        assert_eq!(id1, id2);
        assert_eq!(id1.get_version_num(), 5);
    }

    #[test]
    fn personal_changes_when_inputs_change() {
        let base = personal("https://accounts.example.com", "user-123", "client-abc");

        let different_issuer = personal("https://other.example.com", "user-123", "client-abc");
        let different_user = personal("https://accounts.example.com", "user-456", "client-abc");
        let different_client = personal("https://accounts.example.com", "user-123", "client-def");

        assert_ne!(base, different_issuer);
        assert_ne!(base, different_user);
        assert_ne!(base, different_client);
    }

    #[test]
    fn personal_uses_null_separator() {
        let id1 = personal("issuerA", "user", "client");
        let id2 = personal("issuer", "Auser", "client");
        assert_ne!(id1, id2);
    }

    #[test]
    fn personal_known_vector_matches_go_and_typescript() {
        let expected = "da29e793-3f05-51c3-9f72-63cc953f9c05";
        let got = personal(
            "https://accounts.betterbase.dev",
            "user-1",
            "11111111-1111-1111-1111-111111111111",
        );
        assert_eq!(got.to_string(), expected);
    }
}
