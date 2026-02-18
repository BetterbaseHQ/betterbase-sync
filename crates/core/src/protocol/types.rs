use serde::{Deserialize, Serialize};

/// Space represents a sync namespace for records.
/// Personal spaces have root_public_key = None (JWT-only auth).
/// Shared spaces have root_public_key set (JWT + UCAN auth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Space {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "root_public_key", skip_serializing_if = "Option::is_none")]
    pub root_public_key: Option<Vec<u8>>,
    #[serde(rename = "key_generation")]
    pub key_generation: i32,
    #[serde(rename = "min_key_generation")]
    pub min_key_generation: i32,
    #[serde(rename = "metadata_version")]
    pub metadata_version: i32,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "rewrap_epoch", skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i32>,
    #[serde(rename = "home_server", skip_serializing_if = "Option::is_none")]
    pub home_server: Option<String>,
}

/// Change represents a record in storage and push/pull streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "blob")]
    pub blob: Option<Vec<u8>>,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "dek", skip_serializing_if = "Option::is_none")]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(skip)]
    pub deleted: bool, // storage-only; not part of wire format
}

impl Change {
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}

/// ErrorResponse represents an error response from HTTP JSON APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(rename = "error")]
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_cbor_roundtrip() {
        let change = Change {
            id: "test-id".to_string(),
            blob: Some(b"hello".to_vec()),
            cursor: 42,
            wrapped_dek: None,
            deleted: false,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded.id, change.id);
        assert_eq!(decoded.blob, change.blob);
        assert_eq!(decoded.cursor, change.cursor);
    }

    #[test]
    fn change_cbor_tombstone() {
        let change = Change {
            id: "deleted-record".to_string(),
            blob: None,
            cursor: 5,
            wrapped_dek: None,
            deleted: true,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded.blob, None);
        assert!(!decoded.deleted);
    }

    #[test]
    fn change_is_deleted() {
        let deleted = Change {
            id: "d".to_string(),
            blob: None,
            cursor: 0,
            wrapped_dek: None,
            deleted: true,
        };
        assert!(deleted.is_deleted());

        let live = Change {
            id: "l".to_string(),
            blob: Some(b"data".to_vec()),
            cursor: 0,
            wrapped_dek: None,
            deleted: false,
        };
        assert!(!live.is_deleted());

        let nil_blob = Change {
            id: "n".to_string(),
            blob: None,
            cursor: 0,
            wrapped_dek: None,
            deleted: false,
        };
        assert!(!nil_blob.is_deleted());
    }

    #[test]
    fn change_cbor_empty_blob() {
        let change = Change {
            id: "empty".to_string(),
            blob: Some(Vec::new()),
            cursor: 1,
            wrapped_dek: None,
            deleted: false,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");

        assert_eq!(decoded.blob, Some(Vec::new()));
        assert!(!decoded.is_deleted());
    }

    #[test]
    fn change_cbor_binary_data() {
        let binary_blob: Vec<u8> = (0u16..256).map(|i| i as u8).collect();
        let change = Change {
            id: "binary".to_string(),
            blob: Some(binary_blob.clone()),
            cursor: 1,
            wrapped_dek: None,
            deleted: false,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");

        let blob = decoded.blob.expect("blob");
        assert_eq!(blob.len(), 256);
        assert_eq!(blob, binary_blob);
    }

    #[test]
    fn change_cbor_zero_cursor() {
        let change = Change {
            id: "new-record".to_string(),
            blob: Some(b"data".to_vec()),
            cursor: 0,
            wrapped_dek: None,
            deleted: false,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.cursor, 0);
    }

    #[test]
    fn change_cbor_large_cursor() {
        let change = Change {
            id: "rec".to_string(),
            blob: Some(b"data".to_vec()),
            cursor: i64::MAX,
            wrapped_dek: None,
            deleted: false,
        };

        let encoded = serde_cbor::to_vec(&change).expect("encode");
        let decoded: Change = serde_cbor::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.cursor, i64::MAX);
    }

    #[test]
    fn error_response_json_roundtrip() {
        let resp = ErrorResponse {
            error: "something went wrong".to_string(),
        };
        let encoded = serde_json::to_vec(&resp).expect("json encode");
        let decoded: ErrorResponse = serde_json::from_slice(&encoded).expect("json decode");
        assert_eq!(decoded.error, "something went wrong");
    }

    #[test]
    fn error_response_json_empty_error() {
        let decoded: ErrorResponse = serde_json::from_str(r#"{"error":""}"#).expect("json decode");
        assert_eq!(decoded.error, "");
    }
}
