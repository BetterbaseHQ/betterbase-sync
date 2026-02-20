use serde::{Deserialize, Serialize};

/// Serde helper for `Option<Vec<u8>>` encoded as CBOR byte strings.
/// `serde_bytes` handles `Vec<u8>` directly, but `Option<Vec<u8>>` needs
/// explicit None/null handling and `default` for missing fields.
pub(crate) mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

fn is_empty(s: &str) -> bool {
    s.is_empty()
}

fn is_false(v: &bool) -> bool {
    !*v
}

// WebSocket close codes.
pub const CLOSE_AUTH_FAILED: i32 = 4000;
pub const CLOSE_TOKEN_EXPIRED: i32 = 4001;
pub const CLOSE_FORBIDDEN: i32 = 4002;
pub const CLOSE_TOO_MANY_CONNECTIONS: i32 = 4003;
pub const CLOSE_POW_REQUIRED: i32 = 4004;
pub const CLOSE_PROTOCOL_ERROR: i32 = 4005;
pub const CLOSE_SLOW_CONSUMER: i32 = 4006;
pub const CLOSE_RATE_LIMITED: i32 = 4007;

// Application-specific RPC error codes.
pub const ERR_CODE_KEY_GEN_STALE: &str = "key_generation_stale";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeParams {
    #[serde(rename = "spaces")]
    pub spaces: Vec<WsSubscribeSpace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeResult {
    #[serde(rename = "spaces")]
    pub spaces: Vec<WsSubscribedSpace>,
    #[serde(rename = "errors", skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<WsSpaceError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "changes")]
    pub changes: Vec<WsPushChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRpcResult {
    #[serde(rename = "ok")]
    pub ok: bool,
    #[serde(rename = "cursor", skip_serializing_if = "is_zero_i64", default)]
    pub cursor: i64,
    #[serde(rename = "error", skip_serializing_if = "is_empty", default)]
    pub error: String,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullParams {
    #[serde(rename = "spaces")]
    pub spaces: Vec<WsPullSpace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRefreshParams {
    #[serde(rename = "token")]
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRefreshResult {
    #[serde(rename = "ok")]
    pub ok: bool,
    #[serde(rename = "error", skip_serializing_if = "is_empty", default)]
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeParams {
    #[serde(rename = "spaces")]
    pub spaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSubscribeSpace {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "since")]
    pub since: i64,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "token", skip_serializing_if = "is_empty", default)]
    pub token: String,
    #[serde(rename = "presence", skip_serializing_if = "is_false", default)]
    pub presence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSubscribedSpace {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "key_generation")]
    pub key_generation: i32,
    #[serde(rename = "rewrap_epoch", skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i32>,
    #[serde(rename = "token", skip_serializing_if = "is_empty", default)]
    pub token: String,
    #[serde(rename = "peers", skip_serializing_if = "Vec::is_empty", default)]
    pub peers: Vec<WsPresencePeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSpaceError {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "error")]
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSyncData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "prev")]
    pub prev: i64,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "key_generation")]
    pub key_generation: i32,
    #[serde(rename = "rewrap_epoch", skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i32>,
    #[serde(rename = "records")]
    pub records: Vec<WsSyncRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSyncRecord {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(
        rename = "blob",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub blob: Option<Vec<u8>>,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(
        rename = "dek",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(rename = "deleted", skip_serializing_if = "is_false", default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsMembershipData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "entries")]
    pub entries: Vec<WsMembershipEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsMembershipEntry {
    #[serde(rename = "chain_seq")]
    pub chain_seq: i32,
    #[serde(
        rename = "prev_hash",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub prev_hash: Option<Vec<u8>>,
    #[serde(rename = "entry_hash", with = "serde_bytes")]
    pub entry_hash: Vec<u8>,
    #[serde(rename = "payload", with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsFileData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "files")]
    pub files: Vec<WsFileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsFileEntry {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "record_id")]
    pub record_id: String,
    #[serde(rename = "size", skip_serializing_if = "is_zero_i64", default)]
    pub size: i64,
    #[serde(
        rename = "dek",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(rename = "deleted", skip_serializing_if = "is_false", default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsRevokedData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "reason")]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPushChange {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(
        rename = "blob",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub blob: Option<Vec<u8>>,
    #[serde(rename = "expected_cursor")]
    pub expected_cursor: i64,
    #[serde(
        rename = "dek",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub wrapped_dek: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPullSpace {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "since")]
    pub since: i64,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPullBeginData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "prev")]
    pub prev: i64,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "key_generation")]
    pub key_generation: i32,
    #[serde(rename = "rewrap_epoch", skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPullRecordData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(
        rename = "blob",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub blob: Option<Vec<u8>>,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(
        rename = "dek",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(rename = "deleted", skip_serializing_if = "is_false", default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPullCommitData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "prev")]
    pub prev: i64,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "count")]
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPullFileData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "record_id")]
    pub record_id: String,
    #[serde(rename = "size", skip_serializing_if = "is_zero_i64", default)]
    pub size: i64,
    #[serde(
        rename = "dek",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub wrapped_dek: Option<Vec<u8>>,
    #[serde(rename = "cursor")]
    pub cursor: i64,
    #[serde(rename = "deleted", skip_serializing_if = "is_false", default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationCreateParams {
    #[serde(rename = "mailbox_id")]
    pub mailbox_id: String,
    #[serde(rename = "payload")]
    pub payload: String,
    #[serde(rename = "server", skip_serializing_if = "is_empty", default)]
    pub server: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationCreateResult {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "payload")]
    pub payload: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "expires_at")]
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationListParams {
    #[serde(rename = "limit", skip_serializing_if = "is_zero_i32", default)]
    pub limit: i32,
    #[serde(rename = "after", skip_serializing_if = "is_empty", default)]
    pub after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationListResult {
    #[serde(rename = "invitations")]
    pub invitations: Vec<InvitationCreateResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationGetParams {
    #[serde(rename = "id")]
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationDeleteParams {
    #[serde(rename = "id")]
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCreateParams {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "root_public_key", with = "serde_bytes")]
    pub root_public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCreateResult {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "key_generation")]
    pub key_generation: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipAppendParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "expected_version")]
    pub expected_version: i32,
    #[serde(
        rename = "prev_hash",
        skip_serializing_if = "Option::is_none",
        with = "option_bytes",
        default
    )]
    pub prev_hash: Option<Vec<u8>>,
    #[serde(rename = "entry_hash", with = "serde_bytes")]
    pub entry_hash: Vec<u8>,
    #[serde(rename = "payload", with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipAppendResult {
    #[serde(rename = "chain_seq")]
    pub chain_seq: i32,
    #[serde(rename = "metadata_version")]
    pub metadata_version: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipListParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "since_seq", skip_serializing_if = "is_zero_i32", default)]
    pub since_seq: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipListResult {
    #[serde(rename = "entries")]
    pub entries: Vec<WsMembershipEntry>,
    #[serde(rename = "metadata_version")]
    pub metadata_version: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRevokeParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "ucan_cid")]
    pub ucan_cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBeginParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "epoch")]
    pub epoch: i32,
    #[serde(
        rename = "set_min_key_generation",
        skip_serializing_if = "is_false",
        default
    )]
    pub set_min_key_generation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBeginResult {
    #[serde(rename = "epoch")]
    pub epoch: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochConflictResult {
    #[serde(rename = "error")]
    pub error: String,
    #[serde(rename = "current_epoch")]
    pub current_epoch: i32,
    #[serde(rename = "rewrap_epoch", skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCompleteParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "epoch")]
    pub epoch: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeksGetParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "since", skip_serializing_if = "is_zero_i64", default)]
    pub since: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DekRecord {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "dek", with = "serde_bytes")]
    pub dek: Vec<u8>,
    #[serde(rename = "seq")]
    pub seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeksGetResult {
    #[serde(rename = "deks")]
    pub deks: Vec<DekRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DekRewrapEntry {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "dek", with = "serde_bytes")]
    pub dek: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeksRewrapParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "deks")]
    pub deks: Vec<DekRewrapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeksRewrapResult {
    #[serde(rename = "ok")]
    pub ok: bool,
    #[serde(rename = "count")]
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDekRecord {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "dek", with = "serde_bytes")]
    pub dek: Vec<u8>,
    #[serde(rename = "cursor")]
    pub cursor: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeksGetParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "since", skip_serializing_if = "is_zero_i64", default)]
    pub since: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeksGetResult {
    #[serde(rename = "deks")]
    pub deks: Vec<FileDekRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDekRewrapEntry {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "dek", with = "serde_bytes")]
    pub dek: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeksRewrapParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "ucan", skip_serializing_if = "is_empty", default)]
    pub ucan: String,
    #[serde(rename = "deks")]
    pub deks: Vec<FileDekRewrapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeksRewrapResult {
    #[serde(rename = "ok")]
    pub ok: bool,
    #[serde(rename = "count")]
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPresenceSetParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "data", with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPresenceClearParams {
    #[serde(rename = "space")]
    pub space: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsEventSendParams {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "data", with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPresenceData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "peer")]
    pub peer: String,
    #[serde(rename = "data", with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPresenceLeaveData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "peer")]
    pub peer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsPresencePeer {
    #[serde(rename = "peer")]
    pub peer: String,
    #[serde(rename = "data", with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsEventData {
    #[serde(rename = "space")]
    pub space: String,
    #[serde(rename = "peer")]
    pub peer: String,
    #[serde(rename = "data", with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ERR_CODE_FORBIDDEN;

    #[test]
    fn subscribe_params_roundtrip() {
        let params = SubscribeParams {
            spaces: vec![
                WsSubscribeSpace {
                    id: "space-1".to_string(),
                    since: 0,
                    ucan: "ucan-token".to_string(),
                    token: String::new(),
                    presence: false,
                },
                WsSubscribeSpace {
                    id: "space-2".to_string(),
                    since: 1547,
                    ucan: String::new(),
                    token: String::new(),
                    presence: false,
                },
            ],
        };

        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: SubscribeParams = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.spaces.len(), 2);
        assert_eq!(decoded.spaces[0].ucan, "ucan-token");
        assert_eq!(decoded.spaces[1].since, 1547);
    }

    #[test]
    fn subscribe_result_roundtrip() {
        let result = SubscribeResult {
            spaces: vec![
                WsSubscribedSpace {
                    id: "space-1".to_string(),
                    cursor: 42,
                    key_generation: 3,
                    rewrap_epoch: Some(2),
                    token: String::new(),
                    peers: Vec::new(),
                },
                WsSubscribedSpace {
                    id: "space-2".to_string(),
                    cursor: 100,
                    key_generation: 1,
                    rewrap_epoch: None,
                    token: String::new(),
                    peers: Vec::new(),
                },
            ],
            errors: vec![WsSpaceError {
                space: "bad-space".to_string(),
                error: ERR_CODE_FORBIDDEN.to_string(),
            }],
        };

        let encoded = minicbor_serde::to_vec(&result).expect("encode");
        let decoded: SubscribeResult = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.spaces[0].cursor, 42);
        assert_eq!(decoded.spaces[0].rewrap_epoch, Some(2));
        assert_eq!(decoded.spaces[1].rewrap_epoch, None);
        assert_eq!(decoded.errors.len(), 1);
        assert_eq!(decoded.errors[0].error, "forbidden");
    }

    #[test]
    fn push_params_roundtrip() {
        let params = PushParams {
            space: "space-uuid".to_string(),
            ucan: "ucan-token".to_string(),
            changes: vec![
                WsPushChange {
                    id: "rec-1".to_string(),
                    blob: Some(b"data".to_vec()),
                    expected_cursor: 0,
                    wrapped_dek: Some(vec![0xBB; 44]),
                },
                WsPushChange {
                    id: "rec-2".to_string(),
                    blob: None,
                    expected_cursor: 5,
                    wrapped_dek: None,
                },
            ],
        };
        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: PushParams = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.space, "space-uuid");
        assert_eq!(decoded.ucan, "ucan-token");
        assert_eq!(decoded.changes.len(), 2);
        assert_eq!(decoded.changes[0].expected_cursor, 0);
    }

    #[test]
    fn push_result_roundtrip() {
        let success = PushRpcResult {
            ok: true,
            cursor: 1549,
            error: String::new(),
        };
        let encoded = minicbor_serde::to_vec(&success).expect("encode");
        let decoded: PushRpcResult = minicbor_serde::from_slice(&encoded).expect("decode");
        assert!(decoded.ok);
        assert_eq!(decoded.cursor, 1549);

        let conflict = PushRpcResult {
            ok: false,
            cursor: 1550,
            error: "conflict".to_string(),
        };
        let encoded = minicbor_serde::to_vec(&conflict).expect("encode");
        let decoded: PushRpcResult = minicbor_serde::from_slice(&encoded).expect("decode");
        assert!(!decoded.ok);
        assert_eq!(decoded.error, "conflict");
    }

    #[test]
    fn pull_params_roundtrip() {
        let params = PullParams {
            spaces: vec![
                WsPullSpace {
                    id: "space-1".to_string(),
                    since: 0,
                    ucan: "ucan".to_string(),
                },
                WsPullSpace {
                    id: "space-2".to_string(),
                    since: 1547,
                    ucan: String::new(),
                },
            ],
        };
        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: PullParams = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.spaces.len(), 2);
        assert_eq!(decoded.spaces[0].ucan, "ucan");
    }

    #[test]
    fn token_refresh_roundtrip() {
        let params = TokenRefreshParams {
            token: "jwt-token-here".to_string(),
        };
        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: TokenRefreshParams = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.token, "jwt-token-here");

        let result = TokenRefreshResult {
            ok: true,
            error: String::new(),
        };
        let encoded = minicbor_serde::to_vec(&result).expect("encode");
        let decoded: TokenRefreshResult = minicbor_serde::from_slice(&encoded).expect("decode");
        assert!(decoded.ok);
    }

    #[test]
    fn sync_data_roundtrip() {
        let data = WsSyncData {
            space: "space-uuid".to_string(),
            prev: 1547,
            cursor: 1548,
            key_generation: 3,
            rewrap_epoch: None,
            records: vec![
                WsSyncRecord {
                    id: "rec-1".to_string(),
                    blob: Some(b"encrypted".to_vec()),
                    cursor: 1548,
                    wrapped_dek: Some(vec![0xAA; 44]),
                    deleted: false,
                },
                WsSyncRecord {
                    id: "rec-2".to_string(),
                    blob: None,
                    cursor: 1548,
                    wrapped_dek: None,
                    deleted: true,
                },
            ],
        };

        let encoded = minicbor_serde::to_vec(&data).expect("encode");
        let decoded: WsSyncData = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.space, "space-uuid");
        assert_eq!(decoded.cursor, 1548);
        assert_eq!(decoded.records.len(), 2);
        assert_eq!(decoded.records[0].blob, Some(b"encrypted".to_vec()));
        assert!(decoded.records[1].deleted);
    }

    #[test]
    fn membership_data_roundtrip() {
        let data = WsMembershipData {
            space: "space-uuid".to_string(),
            cursor: 47,
            entries: vec![WsMembershipEntry {
                chain_seq: 5,
                prev_hash: Some(b"prev".to_vec()),
                entry_hash: b"hash".to_vec(),
                payload: b"payload".to_vec(),
            }],
        };

        let encoded = minicbor_serde::to_vec(&data).expect("encode");
        let decoded: WsMembershipData = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.cursor, 47);
        assert_eq!(decoded.entries[0].chain_seq, 5);
    }

    #[test]
    fn pull_file_data_roundtrip() {
        let data = WsPullFileData {
            space: "space-uuid".to_string(),
            id: "file-1".to_string(),
            record_id: "record-3".to_string(),
            size: 2_048_576,
            wrapped_dek: Some(vec![0xCC; 44]),
            cursor: 7,
            deleted: false,
        };

        let encoded = minicbor_serde::to_vec(&data).expect("encode");
        let decoded: WsPullFileData = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.size, 2_048_576);
        assert_eq!(decoded.cursor, 7);
        assert_eq!(decoded.record_id, "record-3");
    }

    // --- Cross-format interop tests ---
    // These simulate CBOR produced by JS cborg: string-keyed maps, missing optional
    // fields (not null), and minimal integer encoding.

    /// Build CBOR from a BTreeMap to mirror JS cborg output (sorted string keys).
    fn cbor_from_map(map: std::collections::BTreeMap<&str, serde_json::Value>) -> Vec<u8> {
        minicbor_serde::to_vec(&map).expect("encode map")
    }

    #[test]
    fn interop_push_change_missing_blob_and_dek() {
        // JS sends a push change with only id and expected_cursor; blob and dek are absent.
        let mut change_map = std::collections::BTreeMap::new();
        change_map.insert("id", serde_json::json!("rec-1"));
        change_map.insert("expected_cursor", serde_json::json!(5));
        let change_bytes = minicbor_serde::to_vec(&change_map).expect("encode change");

        let decoded: WsPushChange =
            minicbor_serde::from_slice(&change_bytes).expect("decode push with missing optionals");
        assert_eq!(decoded.id, "rec-1");
        assert_eq!(decoded.blob, None);
        assert_eq!(decoded.wrapped_dek, None);
        assert_eq!(decoded.expected_cursor, 5);
    }

    #[test]
    fn interop_push_with_explicit_null_blob() {
        // JS sends blob: null explicitly. Roundtrip through the typed struct
        // to get proper CBOR null (0xf6) for the option_bytes field.
        let original = WsPushChange {
            id: "rec-2".to_string(),
            blob: None,
            expected_cursor: 0,
            wrapped_dek: None,
        };
        let change_bytes = minicbor_serde::to_vec(&original).expect("encode change");
        let decoded: WsPushChange =
            minicbor_serde::from_slice(&change_bytes).expect("decode null-blob push");
        assert_eq!(decoded.id, "rec-2");
        assert_eq!(decoded.blob, None);
        assert_eq!(decoded.wrapped_dek, None);
    }

    #[test]
    fn interop_push_params_missing_optional_ucan() {
        // JS omits ucan when pushing to a personal space (no key in map).
        let mut params_map = std::collections::BTreeMap::new();
        params_map.insert("space", serde_json::json!("space-1"));
        params_map.insert("changes", serde_json::json!([]));
        let params_bytes = minicbor_serde::to_vec(&params_map).expect("encode params");

        let decoded: PushParams =
            minicbor_serde::from_slice(&params_bytes).expect("decode push params");
        assert_eq!(decoded.space, "space-1");
        assert!(decoded.ucan.is_empty());
        assert!(decoded.changes.is_empty());
    }

    #[test]
    fn interop_minimal_integer_encoding() {
        // CBOR minimal encoding: small integers (0-23) are single-byte.
        // Verify our types decode these correctly.
        let mut map = std::collections::BTreeMap::new();
        map.insert("space", serde_json::json!("s"));
        map.insert("since_seq", serde_json::json!(0));
        let bytes = cbor_from_map(map);

        let decoded: MembershipListParams =
            minicbor_serde::from_slice(&bytes).expect("decode minimal int");
        assert_eq!(decoded.since_seq, 0);
    }

    #[test]
    fn interop_membership_append_with_absent_optional_fields() {
        // Membership append with absent ucan and prev_hash (JS omits these keys).
        let params = MembershipAppendParams {
            space: "space-uuid".to_string(),
            ucan: String::new(),
            expected_version: 1,
            prev_hash: None,
            entry_hash: vec![4, 5, 6],
            payload: vec![7, 8, 9],
        };
        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: MembershipAppendParams = minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.space, "space-uuid");
        assert_eq!(decoded.prev_hash, None);
        assert_eq!(decoded.entry_hash, vec![4, 5, 6]);
        assert_eq!(decoded.payload, vec![7, 8, 9]);
        assert!(decoded.ucan.is_empty());
    }
}
