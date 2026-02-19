use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use less_sync_core::protocol::{
    FederationInvitationParams, FederationInvitationResult, PushParams, PushRpcResult,
    SubscribeParams, SubscribeResult, WsSubscribeSpace,
};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

mod peer;
mod wire;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum FederationPeerError {
    #[error("invalid peer websocket url {url:?}: {message}")]
    InvalidPeerUrl { url: String, message: String },
    #[error("failed to encode federation frame: {0}")]
    Encode(String),
    #[error("failed to decode federation frame: {0}")]
    Decode(String),
    #[error("federation websocket connect failed: {0}")]
    Connect(String),
    #[error("federation websocket closed before a response")]
    Closed,
    #[error("unexpected federation websocket subprotocol {0:?}")]
    UnexpectedSubprotocol(Option<String>),
    #[error("federation RPC failed: {0}")]
    Rpc(#[from] less_sync_core::protocol::RpcError),
    #[error("peer {0} rejected federation invitation")]
    InvitationRejected(String),
}

pub struct FederationPeerManager {
    key_id: String,
    signing_key: SigningKey,
    peers: Mutex<HashMap<String, Arc<peer::PeerConnection>>>,
    request_id_counter: AtomicU64,
}

impl FederationPeerManager {
    #[must_use]
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key,
            peers: Mutex::new(HashMap::new()),
            request_id_counter: AtomicU64::new(1),
        }
    }

    pub async fn subscribe(
        &self,
        peer_domain: &str,
        peer_ws_url: &str,
        spaces: &[WsSubscribeSpace],
    ) -> Result<(), FederationPeerError> {
        let peer = self.get_or_create_peer(peer_domain, peer_ws_url).await;
        let value = self
            .call_method(
                &peer,
                "subscribe",
                &SubscribeParams {
                    spaces: spaces.to_vec(),
                },
            )
            .await?;

        // Keep parity with Go behavior: if the response can't be decoded,
        // still track subscribed spaces with empty FST tokens.
        if let Ok(result) = decode_cbor_value::<SubscribeResult>(value) {
            let mut token_by_space = HashMap::with_capacity(result.spaces.len());
            for space in &result.spaces {
                token_by_space.insert(space.id.clone(), space.token.clone());
            }
            peer.set_space_tokens(token_by_space).await;
            return Ok(());
        }

        let mut fallback_tokens = HashMap::with_capacity(spaces.len());
        for space in spaces {
            fallback_tokens.insert(space.id.clone(), String::new());
        }
        peer.set_space_tokens(fallback_tokens).await;
        Ok(())
    }

    pub async fn forward_push(
        &self,
        peer_domain: &str,
        peer_ws_url: &str,
        params: &PushParams,
    ) -> Result<PushRpcResult, FederationPeerError> {
        let peer = self.get_or_create_peer(peer_domain, peer_ws_url).await;
        let value = self.call_method(&peer, "push", params).await?;
        decode_cbor_value(value)
    }

    pub async fn forward_invitation(
        &self,
        peer_domain: &str,
        peer_ws_url: &str,
        params: &FederationInvitationParams,
    ) -> Result<(), FederationPeerError> {
        let peer = self.get_or_create_peer(peer_domain, peer_ws_url).await;
        let value = self.call_method(&peer, "fed.invitation", params).await?;
        let result: FederationInvitationResult = decode_cbor_value(value)?;
        if result.ok {
            Ok(())
        } else {
            Err(FederationPeerError::InvitationRejected(
                peer_domain.to_owned(),
            ))
        }
    }

    pub async fn close(&self) {
        let peers = {
            let mut peers = self.peers.lock().await;
            peers.drain().map(|(_, peer)| peer).collect::<Vec<_>>()
        };

        for peer in peers {
            peer.close().await;
        }
    }

    async fn get_or_create_peer(&self, domain: &str, ws_url: &str) -> Arc<peer::PeerConnection> {
        let mut peers = self.peers.lock().await;
        if let Some(existing) = peers.get(domain) {
            return Arc::clone(existing);
        }

        let peer = Arc::new(peer::PeerConnection::new(
            domain.to_owned(),
            ws_url.to_owned(),
        ));
        peers.insert(domain.to_owned(), Arc::clone(&peer));
        peer
    }

    async fn call_method<P>(
        &self,
        peer: &peer::PeerConnection,
        method: &str,
        params: &P,
    ) -> Result<serde_cbor::Value, FederationPeerError>
    where
        P: serde::Serialize,
    {
        let request_id = format!(
            "fed-{}",
            self.request_id_counter.fetch_add(1, Ordering::Relaxed)
        );
        peer.call_raw(&self.key_id, &self.signing_key, &request_id, method, params)
            .await
    }
}

fn decode_cbor_value<T>(value: serde_cbor::Value) -> Result<T, FederationPeerError>
where
    T: DeserializeOwned,
{
    let encoded = serde_cbor::to_vec(&value)
        .map_err(|error| FederationPeerError::Decode(error.to_string()))?;
    serde_cbor::from_slice(&encoded).map_err(|error| FederationPeerError::Decode(error.to_string()))
}
