#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http::{header::HeaderValue, Request};
use url::Url;

pub const DEFAULT_SIGNATURE_MAX_AGE: Duration = Duration::from_secs(5 * 60);

const REQUIRED_COMPONENTS: [&str; 3] = ["@method", "@target-uri", "host"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSignatureParams {
    pub key_id: String,
    pub algorithm: String,
    pub created: SystemTime,
    pub covered_components: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpSignatureError {
    #[error("missing Signature-Input header")]
    MissingSignatureInput,
    #[error("missing Signature header")]
    MissingSignature,
    #[error("invalid Signature-Input: {0}")]
    InvalidSignatureInput(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("signature expired")]
    SignatureExpired,
    #[error("required component {0:?} not covered")]
    MissingRequiredComponent(String),
    #[error("invalid Signature header: {0}")]
    InvalidSignatureHeader(String),
    #[error("key lookup failed: {0}")]
    KeyLookupFailed(String),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid keyid: {0}")]
    InvalidKeyId(String),
}

pub fn sign_http_request(request: &mut Request<()>, private_key: &SigningKey, key_id: &str) {
    let created = unix_now();
    let sig_base = build_signature_base(request, &REQUIRED_COMPONENTS, key_id, created);
    let signature = private_key.sign(sig_base.as_bytes());

    let components = REQUIRED_COMPONENTS
        .iter()
        .map(|component| format!("\"{component}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let signature_input =
        format!("sig=({components});keyid=\"{key_id}\";alg=\"ed25519\";created={created}");
    let signature_header = format!("sig=:{}:", STANDARD.encode(signature.to_bytes()));

    request.headers_mut().insert(
        "Signature-Input",
        HeaderValue::from_str(&signature_input).expect("signature-input is valid ascii"),
    );
    request.headers_mut().insert(
        "Signature",
        HeaderValue::from_str(&signature_header).expect("signature is valid ascii"),
    );
}

pub fn verify_http_signature(
    request: &Request<()>,
    get_key: impl Fn(&str) -> Result<VerifyingKey, HttpSignatureError>,
) -> Result<HttpSignatureParams, HttpSignatureError> {
    verify_http_signature_with_max_age(request, DEFAULT_SIGNATURE_MAX_AGE, get_key)
}

pub fn verify_http_signature_with_max_age(
    request: &Request<()>,
    max_age: Duration,
    get_key: impl Fn(&str) -> Result<VerifyingKey, HttpSignatureError>,
) -> Result<HttpSignatureParams, HttpSignatureError> {
    let sig_input = request
        .headers()
        .get("Signature-Input")
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpSignatureError::MissingSignatureInput)?;
    let signature_header = request
        .headers()
        .get("Signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpSignatureError::MissingSignature)?;

    let params =
        parse_signature_input(sig_input).map_err(HttpSignatureError::InvalidSignatureInput)?;

    if params.algorithm != "ed25519" {
        return Err(HttpSignatureError::UnsupportedAlgorithm(params.algorithm));
    }

    let age = signed_duration_between(params.created, SystemTime::now());
    if age > max_age {
        return Err(HttpSignatureError::SignatureExpired);
    }

    for component in REQUIRED_COMPONENTS {
        if !params
            .covered_components
            .iter()
            .any(|found| found == component)
        {
            return Err(HttpSignatureError::MissingRequiredComponent(
                component.to_owned(),
            ));
        }
    }

    let signature_bytes = parse_signature_value(signature_header)
        .map_err(HttpSignatureError::InvalidSignatureHeader)?;
    let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| {
        HttpSignatureError::InvalidSignatureHeader("malformed signature bytes".to_owned())
    })?;

    let public_key = get_key(&params.key_id)?;
    let base = build_signature_base(
        request,
        &params
            .covered_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &params.key_id,
        system_time_to_unix_seconds(params.created)
            .map_err(|message| HttpSignatureError::InvalidSignatureInput(message.to_owned()))?,
    );

    public_key
        .verify(base.as_bytes(), &signature)
        .map_err(|_| HttpSignatureError::VerificationFailed)?;

    Ok(params)
}

pub fn extract_kid_from_key_id(key_id: &str) -> Result<(String, String), HttpSignatureError> {
    let (jwks_url, kid) = key_id.rsplit_once('#').ok_or_else(|| {
        HttpSignatureError::InvalidKeyId(format!("keyid {key_id:?} has no fragment"))
    })?;
    Ok((jwks_url.to_owned(), kid.to_owned()))
}

pub fn extract_domain_from_key_id(key_id: &str) -> Result<String, HttpSignatureError> {
    let base = key_id
        .rsplit_once('#')
        .map(|(prefix, _)| prefix)
        .unwrap_or(key_id);
    let url =
        Url::parse(base).map_err(|error| HttpSignatureError::InvalidKeyId(error.to_string()))?;

    match url.scheme() {
        "https" | "http" => {}
        _ => {
            return Err(HttpSignatureError::InvalidKeyId(
                "keyid must use http(s) scheme".to_owned(),
            ));
        }
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpSignatureError::InvalidKeyId(
            "keyid must not contain userinfo".to_owned(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| HttpSignatureError::InvalidKeyId("keyid has no host".to_owned()))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host.is_empty() || host.starts_with('.') {
        return Err(HttpSignatureError::InvalidKeyId(
            "keyid has no host".to_owned(),
        ));
    }
    Ok(host)
}

fn build_signature_base(
    request: &Request<()>,
    components: &[&str],
    key_id: &str,
    created: i64,
) -> String {
    let mut base = String::new();
    for component in components {
        base.push_str(&format!("\"{component}\": "));
        match *component {
            "@method" => base.push_str(request.method().as_str()),
            "@target-uri" => base.push_str(&request_target_uri(request)),
            "host" => base.push_str(&request_host(request)),
            header => base.push_str(
                request
                    .headers()
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default(),
            ),
        }
        base.push('\n');
    }

    let quoted_components = components
        .iter()
        .map(|component| format!("\"{component}\""))
        .collect::<Vec<_>>()
        .join(" ");
    base.push_str(&format!(
        "\"@signature-params\": ({quoted_components});keyid=\"{key_id}\";alg=\"ed25519\";created={created}"
    ));
    base
}

fn request_target_uri(request: &Request<()>) -> String {
    let uri = request.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        return uri.to_string();
    }

    let host = request_host(request);
    if host.is_empty() {
        return uri.to_string();
    }
    format!("https://{host}{uri}")
}

fn request_host(request: &Request<()>) -> String {
    request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .unwrap_or_default()
}

fn parse_signature_input(input: &str) -> Result<HttpSignatureParams, String> {
    let input = input
        .strip_prefix("sig=")
        .ok_or_else(|| "expected sig= prefix".to_owned())?;
    let Some(input) = input.strip_prefix('(') else {
        return Err("expected ( after sig=".to_owned());
    };

    let close_index = input
        .find(')')
        .ok_or_else(|| "unclosed component list".to_owned())?;
    let component_str = &input[..close_index];
    let covered_components = component_str
        .split_whitespace()
        .map(|part| part.trim_matches('"'))
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    let mut key_id = None;
    let mut algorithm = None;
    let mut created = None;
    for pair in input[close_index + 1..].split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "keyid" => key_id = Some(value.trim_matches('"').to_owned()),
            "alg" => algorithm = Some(value.trim_matches('"').to_owned()),
            "created" => {
                let timestamp = value
                    .parse::<i64>()
                    .map_err(|error| format!("invalid created timestamp: {error}"))?;
                let timestamp = u64::try_from(timestamp)
                    .map_err(|_| "invalid created timestamp: negative value".to_owned())?;
                created = Some(UNIX_EPOCH + Duration::from_secs(timestamp));
            }
            _ => {}
        }
    }

    let key_id = key_id.ok_or_else(|| "missing keyid parameter".to_owned())?;
    let algorithm = algorithm.ok_or_else(|| "missing alg parameter".to_owned())?;
    let created = created.ok_or_else(|| "missing created parameter".to_owned())?;

    Ok(HttpSignatureParams {
        key_id,
        algorithm,
        created,
        covered_components,
    })
}

fn parse_signature_value(header: &str) -> Result<Vec<u8>, String> {
    let header = header
        .strip_prefix("sig=:")
        .ok_or_else(|| "expected sig=: prefix".to_owned())?;
    let header = header
        .strip_suffix(':')
        .ok_or_else(|| "expected trailing colon".to_owned())?;
    STANDARD
        .decode(header.as_bytes())
        .map_err(|error| error.to_string())
}

fn unix_now() -> i64 {
    system_time_to_unix_seconds(SystemTime::now()).expect("system clock should be >= unix epoch")
}

fn system_time_to_unix_seconds(time: SystemTime) -> Result<i64, &'static str> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "created timestamp is before unix epoch")?;
    i64::try_from(duration.as_secs()).map_err(|_| "created timestamp exceeds i64")
}

fn signed_duration_between(a: SystemTime, b: SystemTime) -> Duration {
    if a <= b {
        b.duration_since(a).unwrap_or_default()
    } else {
        a.duration_since(b).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use http::Request;
    use rand_core::OsRng;

    use super::{
        extract_domain_from_key_id, extract_kid_from_key_id, parse_signature_input,
        sign_http_request, verify_http_signature, verify_http_signature_with_max_age,
        HttpSignatureError,
    };

    fn test_request() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("https://server.example.com/api/v1/federation/ws")
            .header("host", "server.example.com")
            .body(())
            .expect("request")
    }

    #[test]
    fn http_signature_round_trip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";

        let mut request = test_request();
        sign_http_request(&mut request, &signing_key, key_id);

        assert!(request.headers().contains_key("Signature-Input"));
        assert!(request.headers().contains_key("Signature"));

        let params = verify_http_signature(&request, |received| {
            if received != key_id {
                return Err(HttpSignatureError::KeyLookupFailed(format!(
                    "unexpected keyid: {received}",
                )));
            }
            Ok(verify_key)
        })
        .expect("verify");

        assert_eq!(params.key_id, key_id);
        assert_eq!(params.algorithm, "ed25519");
        assert_eq!(params.covered_components.len(), 3);
    }

    #[test]
    fn http_signature_rejects_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";

        let mut request = test_request();
        sign_http_request(&mut request, &signing_key, key_id);

        let error =
            verify_http_signature(&request, |_| Ok(wrong_key)).expect_err("expected failure");
        assert_eq!(error, HttpSignatureError::VerificationFailed);
    }

    #[test]
    fn http_signature_rejects_expired() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";
        let mut request = test_request();
        sign_http_request(&mut request, &signing_key, key_id);

        let error =
            verify_http_signature_with_max_age(&request, Duration::ZERO, |_| Ok(verify_key))
                .expect_err("expected expiration");
        assert_eq!(error, HttpSignatureError::SignatureExpired);
    }

    #[test]
    fn http_signature_rejects_missing_headers() {
        let request = test_request();
        let error = verify_http_signature(&request, |_| {
            Err(HttpSignatureError::KeyLookupFailed("unused".to_owned()))
        })
        .expect_err("missing headers");
        assert_eq!(error, HttpSignatureError::MissingSignatureInput);
    }

    #[test]
    fn extract_kid_from_key_id_cases() {
        let (jwks_url, kid) =
            extract_kid_from_key_id("https://sync.example.com/.well-known/jwks.json#fed-1")
                .expect("extract kid");
        assert_eq!(jwks_url, "https://sync.example.com/.well-known/jwks.json");
        assert_eq!(kid, "fed-1");

        assert!(extract_kid_from_key_id("https://sync.example.com/.well-known/jwks.json").is_err());
    }

    #[test]
    fn extract_domain_from_key_id_cases() {
        let cases = [
            (
                "https://sync.example.com/.well-known/jwks.json#fed-1",
                "sync.example.com",
            ),
            (
                "http://localhost:5379/.well-known/jwks.json#fed-1",
                "localhost",
            ),
            ("https://[::1]:5379/.well-known/jwks.json#fed-1", "::1"),
        ];
        for (key_id, expected) in cases {
            assert_eq!(
                extract_domain_from_key_id(key_id).expect("extract domain"),
                expected
            );
        }

        for candidate in [
            "https://evil.com@trusted.com/.well-known/jwks.json#fed-1",
            "ftp://sync.example.com/.well-known/jwks.json#fed-1",
            "sync.example.com/.well-known/jwks.json#fed-1",
            "https:///.well-known/jwks.json#fed-1",
        ] {
            assert!(
                extract_domain_from_key_id(candidate).is_err(),
                "{candidate}"
            );
        }
    }

    #[test]
    fn http_signature_rejects_tampered_key_id() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";

        let mut request = test_request();
        sign_http_request(&mut request, &signing_key, key_id);

        let original_input = request
            .headers()
            .get("Signature-Input")
            .and_then(|value| value.to_str().ok())
            .expect("header")
            .to_owned();
        request.headers_mut().insert(
            "Signature-Input",
            original_input
                .replace("peer.example.com", "evil.example.com")
                .parse()
                .expect("header parse"),
        );

        let error =
            verify_http_signature(&request, |_| Ok(verify_key)).expect_err("expected failure");
        assert_eq!(error, HttpSignatureError::VerificationFailed);
    }

    #[test]
    fn http_signature_rejects_tampered_host() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verify_key = signing_key.verifying_key();
        let key_id = "https://peer.example.com/.well-known/jwks.json#fed-1";

        let mut request = test_request();
        sign_http_request(&mut request, &signing_key, key_id);
        request
            .headers_mut()
            .insert("host", "evil.example.com".parse().expect("header"));

        let error =
            verify_http_signature(&request, |_| Ok(verify_key)).expect_err("expected failure");
        assert_eq!(error, HttpSignatureError::VerificationFailed);
    }

    #[test]
    fn http_signature_recent_timestamp_is_valid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verify_key: VerifyingKey = signing_key.verifying_key();
        let mut request = test_request();
        sign_http_request(
            &mut request,
            &signing_key,
            "https://peer.example.com/.well-known/jwks.json#fed-1",
        );

        verify_http_signature(&request, |_| Ok(verify_key))
            .expect("recent signature should verify");
    }

    #[test]
    fn parse_signature_input_invalid_shapes() {
        assert_eq!(
            parse_signature_input("sig=").expect_err("expected error"),
            "expected ( after sig="
        );
        assert_eq!(
            parse_signature_input("").expect_err("expected error"),
            "expected sig= prefix"
        );
        assert_eq!(
            parse_signature_input("sig=no-paren").expect_err("expected error"),
            "expected ( after sig="
        );
        assert_eq!(
            parse_signature_input("sig=(@method @target-uri").expect_err("expected error"),
            "unclosed component list"
        );
        assert_eq!(
            parse_signature_input("sig=(@method);alg=\"ed25519\";created=1234567890")
                .expect_err("expected error"),
            "missing keyid parameter"
        );
        assert_eq!(
            parse_signature_input(
                "sig=(@method);keyid=\"https://example.com#k1\";created=1234567890"
            )
            .expect_err("expected error"),
            "missing alg parameter"
        );
        assert_eq!(
            parse_signature_input("sig=(@method);keyid=\"https://example.com#k1\";alg=\"ed25519\"")
                .expect_err("expected error"),
            "missing created parameter"
        );
        assert!(parse_signature_input(
            "sig=(@method);keyid=\"https://example.com#k1\";alg=\"ed25519\";created=not-a-number"
        )
        .is_err());
    }
}
