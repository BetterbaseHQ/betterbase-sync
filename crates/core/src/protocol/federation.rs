use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationInvitationParams {
    #[serde(rename = "mailbox_id")]
    pub mailbox_id: String,
    #[serde(rename = "payload")]
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationInvitationResult {
    #[serde(rename = "ok")]
    pub ok: bool,
}

#[cfg(test)]
mod tests {
    use super::{FederationInvitationParams, FederationInvitationResult};

    #[test]
    fn federation_invitation_params_cbor_roundtrip() {
        let params = FederationInvitationParams {
            mailbox_id: "abc123".to_owned(),
            payload: "ciphertext".to_owned(),
        };
        let encoded = minicbor_serde::to_vec(&params).expect("encode");
        let decoded: FederationInvitationParams =
            minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, params);
    }

    #[test]
    fn federation_invitation_result_cbor_roundtrip() {
        let result = FederationInvitationResult { ok: true };
        let encoded = minicbor_serde::to_vec(&result).expect("encode");
        let decoded: FederationInvitationResult =
            minicbor_serde::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, result);
    }
}
