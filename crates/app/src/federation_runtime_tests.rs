use super::*;
use betterbase_sync_realtime::broker::{BrokerConfig, MultiBroker, Subscriber};
use betterbase_sync_storage::FederationStorage;
use std::sync::Arc;

#[test]
fn federation_rejects_each_invalid_quota_and_empty_secrets() {
    for field in 0..5 {
        for invalid in ["0", "-1", "not-a-number", "184467440737095516160"] {
            let mut env = FederationEnv::default();
            let value = Some(invalid.into());
            match field {
                0 => env.max_spaces = value,
                1 => env.max_records_per_hour = value,
                2 => env.max_bytes_per_hour = value,
                3 => env.max_invitations_per_hour = value,
                _ => env.max_connections = value,
            }
            assert!(
                parse_federation_runtime_config(env).is_err(),
                "field {field}: {invalid}"
            );
        }
    }
    let config = parse_federation_runtime_config(FederationEnv {
        fst_secret: Some("  ".into()),
        fst_previous_secret: Some("\n".into()),
        ..FederationEnv::default()
    })
    .expect("empty secrets");
    assert!(config.fst_secret.is_none());
    assert!(config.fst_previous_secret.is_none());
    assert!(parse_trusted_keys(Some("https://peer.example/.well-known/jwks.json#=abc")).is_err());
}
#[tokio::test]
async fn runtime_wires_signatures_rotating_fst_keys_and_broker() {
    let Some(storage) = tests::isolated_storage().await else {
        return;
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let kid = "https://local.example/.well-known/jwks.json#primary";
    storage
        .ensure_federation_key(kid, &key.to_bytes(), &key.verifying_key().to_bytes())
        .await
        .expect("key");
    let peer_key = SigningKey::from_bytes(&[9; 32]);
    let config = FederationRuntimeConfig {
        trusted_domains: vec!["peer.example".into()],
        trusted_keys: HashMap::from([(
            "https://peer.example/.well-known/jwks.json#peer".into(),
            peer_key.verifying_key().to_bytes(),
        )]),
        fst_secret: Some("current".into()),
        fst_previous_secret: Some("previous".into()),
        ..FederationRuntimeConfig::default()
    };
    let state = ApiState::new(Arc::new(storage.clone()))
        .with_realtime_broker(Arc::new(MultiBroker::new(BrokerConfig::default())));
    let state = apply_federation_runtime_config(state, Arc::new(storage.clone()), &config)
        .await
        .expect("runtime");
    let kids = load_jwks(&storage)
        .await
        .expect("JWKS")
        .keys
        .into_iter()
        .map(|key| key.kid)
        .collect::<Vec<_>>();
    assert_eq!(kids, vec![kid]);
    // The public route verifies runtime wiring without exposing private API state.
    let response = betterbase_sync_api::router(state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/.well-known/jwks.json")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("JWKS route");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    storage.close().await;
}

#[tokio::test]
async fn malformed_persisted_keys_fail_startup_instead_of_publishing_invalid_jwks() {
    let Some(storage) = tests::isolated_storage().await else {
        return;
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let kid = "https://local.example/.well-known/jwks.json#bad";
    storage
        .ensure_federation_key(kid, &key.to_bytes(), &key.verifying_key().to_bytes())
        .await
        .expect("key");
    sqlx::query("UPDATE federation_signing_keys SET public_key=$1")
        .bind(vec![1_u8; 31])
        .execute(storage.pool())
        .await
        .expect("corrupt public length");
    assert!(load_jwks(&storage)
        .await
        .expect_err("bad public key length")
        .to_string()
        .contains("32 bytes"));
    let invalid = (0..=255)
        .map(|b| [b; 32])
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .expect("invalid compressed point");
    sqlx::query("UPDATE federation_signing_keys SET public_key=$1")
        .bind(invalid.as_slice())
        .execute(storage.pool())
        .await
        .expect("corrupt public point");
    assert!(load_jwks(&storage)
        .await
        .expect_err("bad public point")
        .to_string()
        .contains("invalid"));
    sqlx::query("UPDATE federation_signing_keys SET public_key=$1,private_key=$2")
        .bind(key.verifying_key().to_bytes().as_slice())
        .bind(vec![7_u8; 31])
        .execute(storage.pool())
        .await
        .expect("corrupt private length");
    assert!(load_primary_signing_key(&storage)
        .await
        .expect_err("bad private length")
        .to_string()
        .contains("32 bytes"));
    let config = FederationRuntimeConfig {
        trusted_domains: vec!["peer.example".into()],
        trusted_keys: HashMap::from([(
            "https://peer.example/.well-known/jwks.json#bad".into(),
            invalid,
        )]),
        ..FederationRuntimeConfig::default()
    };
    sqlx::query("UPDATE federation_signing_keys SET private_key=$1")
        .bind(key.to_bytes().as_slice())
        .execute(storage.pool())
        .await
        .expect("restore private");
    let result = apply_federation_runtime_config(
        ApiState::new(Arc::new(storage.clone())),
        Arc::new(storage.clone()),
        &config,
    )
    .await;
    let error = match result {
        Ok(_) => panic!("invalid trusted key must fail"),
        Err(e) => e,
    };
    assert!(error.to_string().contains("invalid federation key bytes"));
    storage.close().await;
}
struct Watcher(tokio::sync::mpsc::UnboundedSender<Arc<[u8]>>);
impl Subscriber for Watcher {
    fn send(&self, payload: Arc<[u8]>) -> bool {
        self.0.send(payload).is_ok()
    }
    fn exclude_id(&self) -> &str {
        "watcher"
    }
    fn mailbox_id(&self) -> &str {
        "watcher"
    }
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}
#[tokio::test]
async fn peer_notification_sink_rebroadcasts_only_matching_spaces() {
    let broker = Arc::new(MultiBroker::new(BrokerConfig::default()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    broker
        .register_subscriber(Arc::new(Watcher(tx)), &["space".into()])
        .await
        .expect("watcher");
    let sink = broadcast_peer_notification(broker);
    let params = betterbase_sync_core::protocol::CborValue::from_serializable(
        &serde_json::json!({"space":"space","cursor":8}),
    )
    .expect("params");
    sink("sync", &params);
    let frame = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("notification deadline")
        .expect("notification");
    let decoded: serde_json::Value = minicbor_serde::from_slice(&frame).expect("frame");
    assert_eq!(decoded["type"], 2);
    assert_eq!(decoded["method"], "sync");
    assert_eq!(decoded["params"]["cursor"], 8);
    sink("sync", &betterbase_sync_core::protocol::CborValue::Null);
    let other = betterbase_sync_core::protocol::CborValue::from_serializable(
        &serde_json::json!({"space":"other","cursor":9}),
    )
    .expect("other");
    sink("sync", &other);
    tokio::task::yield_now().await;
    assert!(rx.try_recv().is_err());
}
use tower::ServiceExt;
