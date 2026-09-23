use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use betterbase_sync_auth::{
    compute_ucan_cid, parse_ucan, validate_chain, AuthContext, Permission, UcanError,
    ValidateChainParams, MAX_CHAIN_DEPTH, MAX_TOKENS_PER_CHAIN,
};
use betterbase_sync_core::protocol::{ErrorResponse, Space, WsFileData, WsFileEntry};
use betterbase_sync_storage::{
    FileMetadata, FileStorage as FileStorageTrait, RecordStorage, RevocationStorage, SpaceStorage,
    StorageError,
};
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::{GetOptions, ObjectStore, PutMode, PutOptions};
use uuid::Uuid;

use crate::ApiState;

const WRAPPED_DEK_LENGTH: usize = 44;
const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct FilePathParams {
    pub space_id: String,
    pub id: String,
}

#[derive(Debug, Clone, Copy)]
struct HttpFailure {
    status: StatusCode,
    message: &'static str,
}

impl HttpFailure {
    fn into_response(self) -> Response {
        error_response(self.status, self.message)
    }
}

#[async_trait]
pub(crate) trait FileSyncStorage: Send + Sync {
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError>;
    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<Space, StorageError>;
    async fn record_exists(&self, space_id: Uuid, record_id: Uuid) -> Result<bool, StorageError>;
    async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError>;
    async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError>;
    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> FileSyncStorage for T
where
    T: SpaceStorage + RecordStorage + FileStorageTrait + RevocationStorage + Send + Sync,
{
    async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
        SpaceStorage::get_space(self, space_id).await
    }

    async fn get_or_create_space(
        &self,
        space_id: Uuid,
        client_id: &str,
    ) -> Result<Space, StorageError> {
        SpaceStorage::get_or_create_space(self, space_id, client_id).await
    }

    async fn record_exists(&self, space_id: Uuid, record_id: Uuid) -> Result<bool, StorageError> {
        RecordStorage::record_exists(self, space_id, record_id).await
    }

    async fn record_file(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        size: i64,
        wrapped_dek: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        FileStorageTrait::record_file(self, space_id, file_id, record_id, size, wrapped_dek).await
    }

    async fn get_file_metadata(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<FileMetadata, StorageError> {
        FileStorageTrait::get_file_metadata(self, space_id, file_id).await
    }

    async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
        RevocationStorage::is_revoked(self, space_id, ucan_cid).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBlobStorageError {
    NotFound,
    TooLarge,
    Internal,
}

#[async_trait]
pub trait FileBlobStorage: Send + Sync {
    async fn store(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        payload: &[u8],
    ) -> Result<bool, FileBlobStorageError>;
    async fn get(&self, space_id: Uuid, file_id: Uuid) -> Result<Vec<u8>, FileBlobStorageError>;
    /// Remove the object. Returns `Ok(false)` when it was already gone.
    async fn delete(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, FileBlobStorageError>;
}

pub struct ObjectStoreFileBlobStorage {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreFileBlobStorage {
    #[must_use]
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    pub fn local_filesystem(path: &std::path::Path) -> Result<Self, object_store::Error> {
        let local = LocalFileSystem::new_with_prefix(path)?;
        Ok(Self {
            store: Arc::new(local),
        })
    }
}

#[async_trait]
impl FileBlobStorage for ObjectStoreFileBlobStorage {
    async fn store(
        &self,
        space_id: Uuid,
        file_id: Uuid,
        payload: &[u8],
    ) -> Result<bool, FileBlobStorageError> {
        if payload.len() > MAX_FILE_SIZE {
            return Err(FileBlobStorageError::TooLarge);
        }

        let location = file_object_path(space_id, file_id);
        let put_result = self
            .store
            .put_opts(
                &location,
                payload.to_vec().into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..PutOptions::default()
                },
            )
            .await;

        match put_result {
            Ok(_) => Ok(true),
            Err(error) => {
                let rendered = error.to_string();
                if matches!(error, object_store::Error::AlreadyExists { .. })
                    || rendered.contains("AlreadyExists")
                {
                    Ok(false)
                } else if matches!(error, object_store::Error::NotFound { .. }) {
                    Err(FileBlobStorageError::NotFound)
                } else {
                    Err(FileBlobStorageError::Internal)
                }
            }
        }
    }

    async fn get(&self, space_id: Uuid, file_id: Uuid) -> Result<Vec<u8>, FileBlobStorageError> {
        let location = file_object_path(space_id, file_id);
        let get_result = self
            .store
            .get_opts(&location, GetOptions::default())
            .await
            .map_err(|error| {
                if matches!(error, object_store::Error::NotFound { .. }) {
                    FileBlobStorageError::NotFound
                } else {
                    FileBlobStorageError::Internal
                }
            })?;

        let bytes = get_result
            .bytes()
            .await
            .map_err(|_| FileBlobStorageError::Internal)?;
        Ok(bytes.to_vec())
    }

    async fn delete(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, FileBlobStorageError> {
        let location = file_object_path(space_id, file_id);
        match object_store::ObjectStoreExt::delete(&*self.store, &location).await {
            Ok(_) => Ok(true),
            Err(error) => {
                if matches!(error, object_store::Error::NotFound { .. }) {
                    Ok(false)
                } else {
                    Err(FileBlobStorageError::Internal)
                }
            }
        }
    }
}

enum FileCommitError {
    /// The wrapped DEK's epoch is below the space's minimum key
    /// generation — the client must re-encrypt under the current epoch.
    EpochStale,
    Storage,
}

/// Deletion-queue view over file storage (AUD-039). Separated from
/// [`FileSyncStorage`] because only the background sweep consumes it.
#[async_trait]
pub trait FileDeletionQueue: Send + Sync {
    /// File objects past their deletion grace period.
    async fn pending_file_deletions(
        &self,
        cutoff: std::time::SystemTime,
        limit: usize,
    ) -> Result<
        Vec<betterbase_sync_storage::PendingFileDeletion>,
        betterbase_sync_storage::StorageError,
    >;
    async fn file_exists(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<bool, betterbase_sync_storage::StorageError>;
    async fn complete_file_deletion(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), betterbase_sync_storage::StorageError>;
}

#[async_trait]
impl<T> FileDeletionQueue for T
where
    T: betterbase_sync_storage::Storage + Send + Sync,
{
    async fn pending_file_deletions(
        &self,
        cutoff: std::time::SystemTime,
        limit: usize,
    ) -> Result<
        Vec<betterbase_sync_storage::PendingFileDeletion>,
        betterbase_sync_storage::StorageError,
    > {
        betterbase_sync_storage::FileStorage::pending_file_deletions(self, cutoff, limit).await
    }

    async fn file_exists(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<bool, betterbase_sync_storage::StorageError> {
        betterbase_sync_storage::FileStorage::file_exists(self, space_id, file_id).await
    }

    async fn complete_file_deletion(
        &self,
        space_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), betterbase_sync_storage::StorageError> {
        betterbase_sync_storage::FileStorage::complete_file_deletion(self, space_id, file_id).await
    }
}

/// One garbage-collection pass over the file-deletion queue (AUD-039).
///
/// Objects whose queued deletion has aged past `cutoff` are removed from
/// the blob store; rows are completed (removed) only after the object is
/// gone, so a failed deletion retries on the next pass. The metadata
/// re-check guards the re-upload race: a client re-creating the same
/// (space, file_id) after its tombstone re-inserted metadata, making the
/// object live again.
///
/// Residual (documented): metadata recreated between the existence check
/// and the object deletion leaves a live row over a deleted object — a
/// millisecond window, once per file, ≥24h after its tombstone; the
/// failure mode is a recoverable GET miss.
pub async fn sweep_file_deletions<S: FileDeletionQueue + ?Sized>(
    storage: &S,
    blobs: &dyn FileBlobStorage,
    cutoff: std::time::SystemTime,
    batch_limit: usize,
) -> Result<usize, betterbase_sync_storage::StorageError> {
    let pending = storage.pending_file_deletions(cutoff, batch_limit).await?;
    let mut removed = 0;
    for item in pending {
        if storage.file_exists(item.space_id, item.file_id).await? {
            // Re-uploaded after the tombstone — the object is live again.
            storage
                .complete_file_deletion(item.space_id, item.file_id)
                .await?;
            continue;
        }
        match blobs.delete(item.space_id, item.file_id).await {
            Ok(_) => {
                storage
                    .complete_file_deletion(item.space_id, item.file_id)
                    .await?;
                removed += 1;
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    space = %item.space_id,
                    file = %item.file_id,
                    "file object deletion failed; will retry next sweep"
                );
            }
        }
    }
    Ok(removed)
}

/// Metadata commit shared by first attempts and retries (AUD-027).
///
/// `record_file` is idempotent: `Ok(None)` means the file was already
/// recorded (full replay — acknowledge with 204 and no broadcast);
/// `Ok(Some(cursor))` means this call committed the metadata, whether or
/// not the object bytes were newly stored. Returning an error must never
/// be acknowledged as success.
async fn commit_uploaded_file<S: FileSyncStorage + ?Sized>(
    storage: &S,
    space_id: Uuid,
    file_id: Uuid,
    record_id: Uuid,
    file_size: i64,
    wrapped_dek: &[u8],
) -> Result<Option<i64>, FileCommitError> {
    storage
        .record_file(space_id, file_id, record_id, file_size, wrapped_dek)
        .await
        .map_err(|error| match error {
            StorageError::EpochStale => FileCommitError::EpochStale,
            _ => FileCommitError::Storage,
        })
}

pub(crate) async fn put_file(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(path): Path<FilePathParams>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !has_scope(&auth.scope, "files") {
        return error_response(StatusCode::FORBIDDEN, "files scope required");
    }

    let (space_id, file_id) = match parse_ids(&path) {
        Ok(ids) => ids,
        Err(error) => return error.into_response(),
    };

    let Some(sync_storage) = state.file_sync_storage() else {
        return error_response(StatusCode::NOT_FOUND, "not found");
    };
    let Some(file_storage) = state.file_blob_storage() else {
        return error_response(StatusCode::NOT_FOUND, "not found");
    };

    if let Err(response) = authorize_space(
        sync_storage.as_ref(),
        &auth,
        &headers,
        space_id,
        Permission::Write,
    )
    .await
    {
        return response.into_response();
    }

    let record_id = match parse_record_id(&headers) {
        Ok(record_id) => record_id,
        Err(error) => return error.into_response(),
    };
    let wrapped_dek = match parse_wrapped_dek(&headers) {
        Ok(wrapped_dek) => wrapped_dek,
        Err(error) => return error.into_response(),
    };
    let file_size = match parse_content_length(&headers, &body) {
        Ok(size) => size,
        Err(error) => return error.into_response(),
    };

    match sync_storage.record_exists(space_id, record_id).await {
        Ok(true) => {}
        Ok(false) => {
            return error_response(StatusCode::BAD_REQUEST, "record not found in this space");
        }
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }

    // Returns whether the object was newly created; the AUD-027 flow below
    // no longer branches on it — both first attempts and retries of an
    // interrupted upload run the same idempotent metadata commit.
    let _created = match file_storage.store(space_id, file_id, &body).await {
        Ok(created) => created,
        Err(FileBlobStorageError::TooLarge) => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds 100 MB limit");
        }
        Err(FileBlobStorageError::Internal) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
        Err(FileBlobStorageError::NotFound) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    // AUD-027: an existing object may be the only survivor of an
    // interrupted attempt — bytes stored, process lost before metadata
    // committed. `!created` must NOT be acknowledged early: fall through
    // to the idempotent commit, which distinguishes "this call newly
    // committed metadata" (Some(cursor) — acknowledge and broadcast) from
    // "already fully recorded" (None — plain idempotent replay).
    let cursor = match commit_uploaded_file(
        sync_storage.as_ref(),
        space_id,
        file_id,
        record_id,
        file_size,
        &wrapped_dek,
    )
    .await
    {
        Ok(Some(cursor)) => cursor,
        Ok(None) => return StatusCode::NO_CONTENT.into_response(),
        Err(FileCommitError::EpochStale) => {
            return error_response(
                StatusCode::CONFLICT,
                "file key generation stale — re-encrypt under the current epoch",
            );
        }
        Err(FileCommitError::Storage) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    if let Some(broker) = state.realtime_broker() {
        let space_hex = space_id.as_simple().to_string();
        crate::ws::broadcast_to_space(
            &broker,
            &space_hex,
            "file",
            WsFileData {
                space: space_hex.clone(),
                cursor,
                files: vec![WsFileEntry {
                    id: file_id.to_string(),
                    record_id: record_id.to_string(),
                    size: file_size,
                    wrapped_dek: Some(wrapped_dek),
                    deleted: false,
                }],
            },
        )
        .await;
    }

    StatusCode::CREATED.into_response()
}

pub(crate) async fn get_file(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(path): Path<FilePathParams>,
    headers: HeaderMap,
) -> Response {
    let ResolvedReadableFile {
        space_id,
        file_id,
        metadata,
        file_storage,
    } = match resolve_readable_file(&state, &auth, &path, &headers).await {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };

    let payload = match file_storage.get(space_id, file_id).await {
        Ok(payload) => payload,
        Err(FileBlobStorageError::NotFound) => {
            return error_response(StatusCode::NOT_FOUND, "file not found");
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    let mut response = payload.into_response();
    write_file_headers(response.headers_mut(), file_id, &metadata);
    response
}

pub(crate) async fn head_file(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(path): Path<FilePathParams>,
    headers: HeaderMap,
) -> Response {
    let ResolvedReadableFile {
        file_id, metadata, ..
    } = match resolve_readable_file(&state, &auth, &path, &headers).await {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };

    let mut response = StatusCode::OK.into_response();
    write_file_headers(response.headers_mut(), file_id, &metadata);
    response
}

struct ResolvedReadableFile {
    space_id: Uuid,
    file_id: Uuid,
    metadata: FileMetadata,
    file_storage: Arc<dyn FileBlobStorage>,
}

async fn resolve_readable_file(
    state: &ApiState,
    auth: &AuthContext,
    path: &FilePathParams,
    headers: &HeaderMap,
) -> Result<ResolvedReadableFile, HttpFailure> {
    if !has_scope(&auth.scope, "files") {
        return Err(HttpFailure {
            status: StatusCode::FORBIDDEN,
            message: "files scope required",
        });
    }

    let (space_id, file_id) = parse_ids(path)?;
    let sync_storage = state.file_sync_storage().ok_or(HttpFailure {
        status: StatusCode::NOT_FOUND,
        message: "file not found",
    })?;
    let file_storage = state.file_blob_storage().ok_or(HttpFailure {
        status: StatusCode::NOT_FOUND,
        message: "file not found",
    })?;

    authorize_space(
        sync_storage.as_ref(),
        auth,
        headers,
        space_id,
        Permission::Read,
    )
    .await
    .map_err(|error| match error.status {
        StatusCode::NOT_FOUND => HttpFailure {
            status: StatusCode::NOT_FOUND,
            message: "file not found",
        },
        _ => error,
    })?;

    let metadata = match sync_storage.get_file_metadata(space_id, file_id).await {
        Ok(metadata) => metadata,
        Err(StorageError::FileNotFound) => {
            return Err(HttpFailure {
                status: StatusCode::NOT_FOUND,
                message: "file not found",
            });
        }
        Err(_) => {
            return Err(HttpFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "internal error",
            });
        }
    };

    Ok(ResolvedReadableFile {
        space_id,
        file_id,
        metadata,
        file_storage,
    })
}

async fn authorize_space(
    sync_storage: &dyn FileSyncStorage,
    auth: &AuthContext,
    headers: &HeaderMap,
    space_id: Uuid,
    permission: Permission,
) -> Result<(), HttpFailure> {
    if is_personal_space(auth, space_id) {
        return sync_storage
            .get_or_create_space(space_id, &auth.client_id)
            .await
            .map(|_| ())
            .map_err(|_| HttpFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "internal error",
            });
    }

    let space = match sync_storage.get_space(space_id).await {
        Ok(space) if space.root_public_key.is_some() => space,
        _ => {
            return Err(HttpFailure {
                status: StatusCode::NOT_FOUND,
                message: "space not found",
            });
        }
    };
    let root_public_key = space.root_public_key.ok_or(HttpFailure {
        status: StatusCode::NOT_FOUND,
        message: "space not found",
    })?;

    let ucan = match header_to_str(headers, "X-UCAN") {
        Some(ucan) if !ucan.is_empty() => ucan,
        _ => {
            return Err(HttpFailure {
                status: StatusCode::UNAUTHORIZED,
                message: "authorization required",
            });
        }
    };
    if auth.did.is_empty() {
        return Err(HttpFailure {
            status: StatusCode::UNAUTHORIZED,
            message: "authorization required",
        });
    }

    ensure_chain_not_revoked(sync_storage, space_id, ucan)
        .await
        .map_err(|_| HttpFailure {
            status: StatusCode::FORBIDDEN,
            message: "access denied",
        })?;

    validate_chain(ValidateChainParams {
        token: ucan,
        expected_audience: &auth.did,
        required_permission: permission,
        space_id: &space_id.to_string(),
        root_public_key: &root_public_key,
        is_revoked: None,
        now: None,
    })
    .map_err(|_| HttpFailure {
        status: StatusCode::FORBIDDEN,
        message: "access denied",
    })
}

async fn ensure_chain_not_revoked(
    sync_storage: &dyn FileSyncStorage,
    space_id: Uuid,
    token: &str,
) -> Result<(), UcanError> {
    let mut visited = HashSet::new();
    let mut stack = vec![(token.to_owned(), 0_usize)];

    while let Some((current, depth)) = stack.pop() {
        if depth >= MAX_CHAIN_DEPTH {
            return Err(UcanError::ChainTooDeep);
        }

        let cid = compute_ucan_cid(&current);
        if !visited.insert(cid.clone()) {
            continue;
        }
        if visited.len() > MAX_TOKENS_PER_CHAIN {
            return Err(UcanError::InvalidUcan);
        }

        let revoked = sync_storage
            .is_revoked(space_id, &cid)
            .await
            .map_err(|_| UcanError::RevocationCheckFailed)?;
        if revoked {
            return Err(UcanError::UcanRevoked);
        }

        let parsed = parse_ucan(&current)?;
        for delegated in parsed
            .claims
            .prf
            .into_iter()
            .filter(|token| !token.is_empty())
        {
            stack.push((delegated, depth + 1));
        }
    }

    Ok(())
}

fn parse_ids(path: &FilePathParams) -> Result<(Uuid, Uuid), HttpFailure> {
    let space_id = Uuid::parse_str(&path.space_id).map_err(|_| HttpFailure {
        status: StatusCode::BAD_REQUEST,
        message: "invalid space ID",
    })?;
    let file_id = Uuid::parse_str(&path.id).map_err(|_| HttpFailure {
        status: StatusCode::BAD_REQUEST,
        message: "invalid file ID",
    })?;
    Ok((space_id, file_id))
}

fn parse_record_id(headers: &HeaderMap) -> Result<Uuid, HttpFailure> {
    let Some(raw_record_id) = header_to_str(headers, "X-Record-ID") else {
        return Err(HttpFailure {
            status: StatusCode::BAD_REQUEST,
            message: "X-Record-ID header required",
        });
    };
    Uuid::parse_str(raw_record_id).map_err(|_| HttpFailure {
        status: StatusCode::BAD_REQUEST,
        message: "X-Record-ID must be a valid UUID",
    })
}

fn parse_wrapped_dek(headers: &HeaderMap) -> Result<Vec<u8>, HttpFailure> {
    let Some(raw_dek) = header_to_str(headers, "X-Wrapped-DEK") else {
        return Err(HttpFailure {
            status: StatusCode::BAD_REQUEST,
            message: "X-Wrapped-DEK header required",
        });
    };
    let decoded = STANDARD.decode(raw_dek).map_err(|_| HttpFailure {
        status: StatusCode::BAD_REQUEST,
        message: "X-Wrapped-DEK must be valid base64",
    })?;
    if decoded.len() != WRAPPED_DEK_LENGTH {
        return Err(HttpFailure {
            status: StatusCode::BAD_REQUEST,
            message: "X-Wrapped-DEK must decode to exactly 44 bytes",
        });
    }
    Ok(decoded)
}

fn parse_content_length(headers: &HeaderMap, body: &Bytes) -> Result<i64, HttpFailure> {
    let Some(raw_content_length) = header_to_str(headers, CONTENT_LENGTH.as_str()) else {
        return Err(HttpFailure {
            status: StatusCode::LENGTH_REQUIRED,
            message: "Content-Length required",
        });
    };

    let declared_size = raw_content_length
        .parse::<usize>()
        .map_err(|_| HttpFailure {
            status: StatusCode::BAD_REQUEST,
            message: "invalid Content-Length header",
        })?;
    if declared_size > MAX_FILE_SIZE {
        return Err(HttpFailure {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: "file exceeds 100 MB limit",
        });
    }
    if declared_size != body.len() {
        return Err(HttpFailure {
            status: StatusCode::BAD_REQUEST,
            message: "Content-Length does not match request body length",
        });
    }

    Ok(declared_size as i64)
}

fn write_file_headers(headers: &mut HeaderMap, file_id: Uuid, metadata: &FileMetadata) {
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(content_length) = HeaderValue::from_str(&metadata.size.to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, content_length);
    }
    if let Ok(etag) = HeaderValue::from_str(&format!("\"{file_id}\"")) {
        headers.insert(axum::http::header::ETAG, etag);
    }
    if let Ok(wrapped_dek) = HeaderValue::from_str(&STANDARD.encode(&metadata.wrapped_dek)) {
        headers.insert("X-Wrapped-DEK", wrapped_dek);
    }
}

fn header_to_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn has_scope(scope: &str, capability: &str) -> bool {
    scope
        .split_whitespace()
        .any(|token| !token.is_empty() && token == capability)
}

fn is_personal_space(auth: &AuthContext, space_id: Uuid) -> bool {
    Uuid::parse_str(&auth.personal_space_id)
        .ok()
        .is_some_and(|personal_space_id| personal_space_id == space_id)
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_owned(),
        }),
    )
        .into_response()
}

fn file_object_path(space_id: Uuid, file_id: Uuid) -> ObjectPath {
    ObjectPath::from(format!("spaces/{space_id}/files/{file_id}"))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH};
    use axum::http::Request;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use betterbase_sync_auth::{
        compress_public_key, compute_ucan_cid, encode_did_key, AudienceClaim, AuthError,
        TokenValidator, UcanClaims,
    };
    use jsonwebtoken::{Algorithm, Header};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::Generate;
    use p256::PublicKey;
    use tower::ServiceExt;

    use crate::{router, ApiState, HealthCheck};

    use super::*;

    #[derive(Default)]
    struct StubHealth;

    #[async_trait]
    impl HealthCheck for StubHealth {
        async fn ping(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct StubValidator {
        tokens: HashMap<String, AuthContext>,
    }

    #[async_trait]
    impl TokenValidator for StubValidator {
        async fn validate_token(&self, token: &str) -> Result<AuthContext, AuthError> {
            self.tokens
                .get(token)
                .cloned()
                .ok_or(AuthError::InvalidToken)
        }
    }

    struct StubFileSyncStorage {
        record_exists: bool,
        metadata: Mutex<HashMap<(Uuid, Uuid), FileMetadata>>,
        personal_spaces: [Uuid; 2],
        shared_spaces: HashMap<Uuid, Vec<u8>>,
        revoked_ucans: HashMap<Uuid, HashSet<String>>,
        /// When set, record_file fails with this error — simulates the
        /// interrupted first attempt (crash / SQL failure) of AUD-027.
        fail_record_file: Mutex<Option<StorageError>>,
    }

    #[async_trait]
    impl FileSyncStorage for StubFileSyncStorage {
        async fn get_space(&self, space_id: Uuid) -> Result<Space, StorageError> {
            if self.personal_spaces.contains(&space_id) {
                return Ok(Space {
                    id: space_id.to_string(),
                    client_id: "client".to_owned(),
                    root_public_key: None,
                    epoch: 1,
                    min_epoch: 0,
                    metadata_version: 0,
                    cursor: 0,
                    rewrap_epoch: None,
                    home_server: None,
                });
            }
            if let Some(root_public_key) = self.shared_spaces.get(&space_id) {
                return Ok(Space {
                    id: space_id.to_string(),
                    client_id: "client".to_owned(),
                    root_public_key: Some(root_public_key.clone()),
                    epoch: 1,
                    min_epoch: 0,
                    metadata_version: 0,
                    cursor: 0,
                    rewrap_epoch: None,
                    home_server: None,
                });
            }
            Err(StorageError::SpaceNotFound)
        }

        async fn get_or_create_space(
            &self,
            space_id: Uuid,
            client_id: &str,
        ) -> Result<Space, StorageError> {
            Ok(Space {
                id: space_id.to_string(),
                client_id: client_id.to_owned(),
                root_public_key: None,
                epoch: 1,
                min_epoch: 0,
                metadata_version: 0,
                cursor: 0,
                rewrap_epoch: None,
                home_server: None,
            })
        }

        async fn record_exists(
            &self,
            _space_id: Uuid,
            _record_id: Uuid,
        ) -> Result<bool, StorageError> {
            Ok(self.record_exists)
        }

        async fn record_file(
            &self,
            space_id: Uuid,
            file_id: Uuid,
            record_id: Uuid,
            size: i64,
            wrapped_dek: &[u8],
        ) -> Result<Option<i64>, StorageError> {
            if let Some(error) = self.fail_record_file.lock().expect("fail lock").clone() {
                return Err(error);
            }
            let mut guard = self.metadata.lock().expect("metadata lock");
            if guard.contains_key(&(space_id, file_id)) {
                return Ok(None);
            }
            let metadata = FileMetadata {
                id: file_id,
                record_id,
                size,
                wrapped_dek: wrapped_dek.to_vec(),
                cursor: 1,
            };
            guard.insert((space_id, file_id), metadata);
            Ok(Some(1))
        }

        async fn get_file_metadata(
            &self,
            space_id: Uuid,
            file_id: Uuid,
        ) -> Result<FileMetadata, StorageError> {
            self.metadata
                .lock()
                .expect("metadata lock")
                .get(&(space_id, file_id))
                .cloned()
                .ok_or(StorageError::FileNotFound)
        }

        async fn is_revoked(&self, space_id: Uuid, ucan_cid: &str) -> Result<bool, StorageError> {
            Ok(self
                .revoked_ucans
                .get(&space_id)
                .is_some_and(|revoked| revoked.contains(ucan_cid)))
        }
    }

    #[derive(Default)]
    struct StubFileBlobStorage {
        files: Mutex<HashMap<(Uuid, Uuid), Vec<u8>>>,
    }

    #[async_trait]
    impl FileBlobStorage for StubFileBlobStorage {
        async fn store(
            &self,
            space_id: Uuid,
            file_id: Uuid,
            payload: &[u8],
        ) -> Result<bool, FileBlobStorageError> {
            let mut files = self.files.lock().expect("blob lock");
            if files.contains_key(&(space_id, file_id)) {
                return Ok(false);
            }
            files.insert((space_id, file_id), payload.to_vec());
            Ok(true)
        }

        async fn get(
            &self,
            space_id: Uuid,
            file_id: Uuid,
        ) -> Result<Vec<u8>, FileBlobStorageError> {
            self.files
                .lock()
                .expect("blob lock")
                .get(&(space_id, file_id))
                .cloned()
                .ok_or(FileBlobStorageError::NotFound)
        }

        async fn delete(
            &self,
            space_id: Uuid,
            file_id: Uuid,
        ) -> Result<bool, FileBlobStorageError> {
            Ok(self
                .files
                .lock()
                .expect("blob lock")
                .remove(&(space_id, file_id))
                .is_some())
        }
    }

    #[derive(Default)]
    struct StubDeletionQueue {
        pending: Mutex<Vec<(Uuid, Uuid, std::time::SystemTime)>>,
        live_files: Mutex<std::collections::HashSet<(Uuid, Uuid)>>,
    }

    #[async_trait]
    impl FileDeletionQueue for StubDeletionQueue {
        async fn pending_file_deletions(
            &self,
            cutoff: std::time::SystemTime,
            limit: usize,
        ) -> Result<Vec<betterbase_sync_storage::PendingFileDeletion>, StorageError> {
            let pending = self.pending.lock().expect("lock pending");
            Ok(pending
                .iter()
                .filter(|(_, _, scheduled_at)| scheduled_at <= &cutoff)
                .take(limit)
                .map(
                    |(space_id, file_id, _)| betterbase_sync_storage::PendingFileDeletion {
                        space_id: *space_id,
                        file_id: *file_id,
                    },
                )
                .collect())
        }

        async fn file_exists(&self, space_id: Uuid, file_id: Uuid) -> Result<bool, StorageError> {
            Ok(self
                .live_files
                .lock()
                .expect("lock live files")
                .contains(&(space_id, file_id)))
        }

        async fn complete_file_deletion(
            &self,
            space_id: Uuid,
            file_id: Uuid,
        ) -> Result<(), StorageError> {
            self.pending
                .lock()
                .expect("lock pending")
                .retain(|(space, file, _)| (*space, *file) != (space_id, file_id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn sweep_removes_due_objects_and_completes_rows() {
        // AUD-039: tombstoned records schedule their file objects for
        // removal; the sweep deletes aged-out objects and clears the queue.
        let storage = StubDeletionQueue::default();
        let blobs = StubFileBlobStorage::default();
        let space_id = Uuid::new_v4();
        let due_file = Uuid::new_v4();
        let future_file = Uuid::new_v4();

        for file_id in [due_file, future_file] {
            storage.pending.lock().expect("lock pending").push((
                space_id,
                file_id,
                if file_id == due_file {
                    std::time::SystemTime::now() - std::time::Duration::from_secs(1)
                } else {
                    std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
                },
            ));
            blobs
                .store(space_id, file_id, b"bytes")
                .await
                .expect("store");
        }

        let removed = sweep_file_deletions(&storage, &blobs, std::time::SystemTime::now(), 100)
            .await
            .expect("sweep");
        assert_eq!(removed, 1);
        assert!(blobs.get(space_id, due_file).await.is_err());
        // Not yet due — untouched.
        assert!(blobs.get(space_id, future_file).await.is_ok());
        // Completed rows are gone from the queue (only the not-yet-due
        // entry remains).
        let remaining = storage
            .pending_file_deletions(cutoff_now(), 100)
            .await
            .expect("remaining");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].file_id, future_file);
    }

    #[tokio::test]
    async fn sweep_spares_reuploaded_files() {
        // The re-upload guard: a file id whose metadata was re-created after
        // the tombstone queued it is live again — the object survives and
        // the queue entry is dropped.
        let storage = StubDeletionQueue::default();
        let blobs = StubFileBlobStorage::default();
        let space_id = Uuid::new_v4();
        let file_id = Uuid::new_v4();

        storage.pending.lock().expect("lock pending").push((
            space_id,
            file_id,
            std::time::UNIX_EPOCH,
        ));
        blobs
            .store(space_id, file_id, b"bytes")
            .await
            .expect("store");
        storage
            .live_files
            .lock()
            .expect("lock live files")
            .insert((space_id, file_id));

        let removed = sweep_file_deletions(&storage, &blobs, std::time::SystemTime::now(), 100)
            .await
            .expect("sweep");
        assert_eq!(removed, 0);
        assert!(blobs.get(space_id, file_id).await.is_ok());
        let remaining = storage
            .pending_file_deletions(cutoff_now(), 100)
            .await
            .expect("remaining");
        assert!(remaining.is_empty());
    }

    fn cutoff_now() -> std::time::SystemTime {
        std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
    }

    #[tokio::test]
    async fn file_routes_are_not_registered_without_file_storage() {
        let app =
            router(ApiState::new(Arc::new(StubHealth)).with_websocket(Arc::new(build_validator())));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_get_and_head_file_succeeds() {
        let app = file_app(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let payload = b"hello world";

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, payload.len().to_string())
                    .header("X-Record-ID", record_id.to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([9u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from(payload.to_vec()))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(get_response.status(), StatusCode::OK);
        assert_eq!(
            get_response
                .headers()
                .get("X-Wrapped-DEK")
                .and_then(|value| value.to_str().ok())
                .expect("wrapped dek header"),
            STANDARD.encode([9u8; WRAPPED_DEK_LENGTH])
        );
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert_eq!(get_body.as_ref(), payload);

        let head_response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(head_response.status(), StatusCode::OK);
        let head_body = axum::body::to_bytes(head_response.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert!(head_body.is_empty());
    }

    #[tokio::test]
    async fn put_file_is_idempotent() {
        let app = file_app(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "3")
                    .header("X-Record-ID", record_id.to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("one"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "3")
                    .header("X-Record-ID", record_id.to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("one"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(second.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_file_requires_files_scope() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer sync-user1")
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_file_rejects_missing_wrapped_dek() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_file_rejects_nonexistent_record() {
        let app = file_app(false);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_file_requires_content_length() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::LENGTH_REQUIRED);
    }

    #[tokio::test]
    async fn put_file_rejects_content_length_mismatch() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "10")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([1u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_file_requires_files_scope() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer sync-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_file_rejects_invalid_file_id() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/spaces/{}/files/invalid",
                        personal_space_user1()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn head_file_requires_files_scope() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/{}",
                        personal_space_user1(),
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer sync-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn head_file_rejects_invalid_file_id() {
        let app = file_app(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!(
                        "/api/v1/spaces/{}/files/invalid",
                        personal_space_user1()
                    ))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_file_from_other_personal_space_returns_not_found() {
        let app = file_app(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user1")
                    .header(CONTENT_LENGTH, "6")
                    .header("X-Record-ID", record_id.to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([9u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("secret"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-user2")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn shared_space_put_get_and_head_with_valid_ucan_succeeds() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let write_ucan =
            root_issuer.issue_space_ucan(&bearer_issuer.did, shared_space_id, Permission::Write);
        let read_ucan =
            root_issuer.issue_space_ucan(&bearer_issuer.did, shared_space_id, Permission::Read);
        let app = file_app_with_shared_space(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
        );

        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let payload = b"shared payload";
        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/spaces/{shared_space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", write_ucan)
                    .header(CONTENT_LENGTH, payload.len().to_string())
                    .header("X-Record-ID", record_id.to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from(payload.to_vec()))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/spaces/{shared_space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", read_ucan.clone())
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert_eq!(get_body.as_ref(), payload);

        let head_response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/api/v1/spaces/{shared_space_id}/files/{file_id}"))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", read_ucan)
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");
        assert_eq!(head_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn shared_space_put_with_delegated_ucan_succeeds() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let delegate_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let proof_ucan =
            root_issuer.issue_space_ucan(&delegate_issuer.did, shared_space_id, Permission::Write);
        let write_ucan = delegate_issuer.issue_space_ucan_with_proofs(
            &bearer_issuer.did,
            shared_space_id,
            Permission::Write,
            vec![proof_ucan],
        );
        let app = file_app_with_shared_space(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", write_ucan)
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn shared_space_put_without_ucan_returns_unauthorized() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let app = file_app_with_shared_space(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn shared_space_put_with_invalid_ucan_returns_forbidden() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let app = file_app_with_shared_space(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", "not-a-valid-ucan")
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn shared_space_put_requires_write_permission() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let read_ucan =
            root_issuer.issue_space_ucan(&bearer_issuer.did, shared_space_id, Permission::Read);
        let app = file_app_with_shared_space(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", read_ucan)
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn shared_space_put_with_revoked_ucan_returns_forbidden() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let write_ucan =
            root_issuer.issue_space_ucan(&bearer_issuer.did, shared_space_id, Permission::Write);
        let mut revoked_ucan_cids = HashSet::new();
        revoked_ucan_cids.insert(compute_ucan_cid(&write_ucan));
        let app = file_app_with_shared_space_and_revocations(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
            revoked_ucan_cids,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", write_ucan)
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn shared_space_put_with_revoked_proof_ucan_returns_forbidden() {
        let shared_space_id =
            Uuid::parse_str("6dfe56d8-7987-439f-b044-ea19e633ef46").expect("uuid");
        let root_issuer = TestIssuer::new();
        let delegate_issuer = TestIssuer::new();
        let bearer_issuer = TestIssuer::new();
        let proof_ucan =
            root_issuer.issue_space_ucan(&delegate_issuer.did, shared_space_id, Permission::Write);
        let write_ucan = delegate_issuer.issue_space_ucan_with_proofs(
            &bearer_issuer.did,
            shared_space_id,
            Permission::Write,
            vec![proof_ucan.clone()],
        );

        let mut revoked_ucan_cids = HashSet::new();
        revoked_ucan_cids.insert(compute_ucan_cid(&proof_ucan));

        let app = file_app_with_shared_space_and_revocations(
            true,
            shared_space_id,
            root_issuer.compressed_public_key().to_vec(),
            bearer_issuer.did,
            revoked_ucan_cids,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/api/v1/spaces/{shared_space_id}/files/{}",
                        Uuid::new_v4()
                    ))
                    .header(AUTHORIZATION, "Bearer files-shared-user")
                    .header("X-UCAN", write_ucan)
                    .header(CONTENT_LENGTH, "4")
                    .header("X-Record-ID", Uuid::new_v4().to_string())
                    .header("X-Wrapped-DEK", STANDARD.encode([3u8; WRAPPED_DEK_LENGTH]))
                    .body(Body::from("test"))
                    .expect("build request"),
            )
            .await
            .expect("dispatch request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    fn file_app_with_handles(
        record_exists: bool,
    ) -> (
        axum::Router,
        Arc<StubFileSyncStorage>,
        Arc<StubFileBlobStorage>,
    ) {
        let sync_storage = Arc::new(StubFileSyncStorage {
            record_exists,
            metadata: Mutex::new(HashMap::new()),
            personal_spaces: [personal_space_user1(), personal_space_user2()],
            shared_spaces: HashMap::new(),
            revoked_ucans: HashMap::new(),
            fail_record_file: Mutex::new(None),
        });
        let blob_storage = Arc::new(StubFileBlobStorage::default());
        let app = router(
            ApiState::new(Arc::new(StubHealth))
                .with_websocket(Arc::new(build_validator()))
                .with_file_sync_storage_adapter(
                    Arc::clone(&sync_storage) as Arc<dyn FileSyncStorage>
                )
                .with_file_blob_storage_adapter(
                    Arc::clone(&blob_storage) as Arc<dyn FileBlobStorage>
                ),
        );
        (app, sync_storage, blob_storage)
    }

    fn file_app(record_exists: bool) -> axum::Router {
        file_app_with(
            record_exists,
            build_default_tokens(),
            HashMap::<Uuid, Vec<u8>>::new(),
            HashMap::<Uuid, HashSet<String>>::new(),
        )
    }

    fn file_app_with_shared_space(
        record_exists: bool,
        shared_space_id: Uuid,
        shared_root_public_key: Vec<u8>,
        auth_did: String,
    ) -> axum::Router {
        file_app_with_shared_space_and_revocations(
            record_exists,
            shared_space_id,
            shared_root_public_key,
            auth_did,
            HashSet::new(),
        )
    }

    fn file_app_with_shared_space_and_revocations(
        record_exists: bool,
        shared_space_id: Uuid,
        shared_root_public_key: Vec<u8>,
        auth_did: String,
        revoked_ucan_cids: HashSet<String>,
    ) -> axum::Router {
        let mut shared_spaces = HashMap::new();
        shared_spaces.insert(shared_space_id, shared_root_public_key);
        let mut revoked_ucans = HashMap::new();
        if !revoked_ucan_cids.is_empty() {
            revoked_ucans.insert(shared_space_id, revoked_ucan_cids);
        }

        let mut tokens = build_default_tokens();
        tokens.insert(
            "files-shared-user".to_owned(),
            auth_context_with_did("sync files", personal_space_user1(), &auth_did),
        );

        file_app_with(record_exists, tokens, shared_spaces, revoked_ucans)
    }

    fn file_app_with(
        record_exists: bool,
        tokens: HashMap<String, AuthContext>,
        shared_spaces: HashMap<Uuid, Vec<u8>>,
        revoked_ucans: HashMap<Uuid, HashSet<String>>,
    ) -> axum::Router {
        let sync_storage = Arc::new(StubFileSyncStorage {
            record_exists,
            metadata: Mutex::new(HashMap::new()),
            personal_spaces: [personal_space_user1(), personal_space_user2()],
            shared_spaces,
            revoked_ucans,
            fail_record_file: Mutex::new(None),
        });
        let blob_storage = Arc::new(StubFileBlobStorage::default());

        router(
            ApiState::new(Arc::new(StubHealth))
                .with_websocket(Arc::new(StubValidator { tokens }))
                .with_file_sync_storage_adapter(sync_storage)
                .with_file_blob_storage_adapter(blob_storage),
        )
    }

    fn build_validator() -> StubValidator {
        StubValidator {
            tokens: build_default_tokens(),
        }
    }

    fn build_default_tokens() -> HashMap<String, AuthContext> {
        let mut tokens = HashMap::new();
        tokens.insert(
            "files-user1".to_owned(),
            auth_context("sync files", personal_space_user1()),
        );
        tokens.insert(
            "sync-user1".to_owned(),
            auth_context("sync", personal_space_user1()),
        );
        tokens.insert(
            "files-user2".to_owned(),
            auth_context("sync files", personal_space_user2()),
        );
        tokens
    }

    fn auth_context(scope: &str, personal_space_id: Uuid) -> AuthContext {
        auth_context_with_did(scope, personal_space_id, "did:key:z6Mkexample")
    }

    fn auth_context_with_did(scope: &str, personal_space_id: Uuid, did: &str) -> AuthContext {
        AuthContext {
            issuer: "https://accounts.betterbase.dev".to_owned(),
            user_id: "user".to_owned(),
            client_id: "client".to_owned(),
            personal_space_id: personal_space_id.to_string(),
            did: did.to_owned(),
            mailbox_id: "mailbox".to_owned(),
            scope: scope.to_owned(),
            expires_at: None,
        }
    }

    #[derive(Clone)]
    struct TestIssuer {
        key: SigningKey,
        did: String,
    }

    impl TestIssuer {
        fn new() -> Self {
            let key = SigningKey::generate();
            let public_key =
                PublicKey::from_sec1_bytes(key.verifying_key().to_sec1_point(false).as_bytes())
                    .expect("public key should decode");
            let did = encode_did_key(&public_key);
            Self { key, did }
        }

        fn compressed_public_key(&self) -> [u8; 33] {
            let public_key = PublicKey::from_sec1_bytes(
                self.key.verifying_key().to_sec1_point(false).as_bytes(),
            )
            .expect("public key should decode");
            compress_public_key(&public_key)
        }

        fn issue_space_ucan(
            &self,
            audience_did: &str,
            space_id: Uuid,
            permission: Permission,
        ) -> String {
            self.issue_space_ucan_with_proofs(audience_did, space_id, permission, Vec::new())
        }

        fn issue_space_ucan_with_proofs(
            &self,
            audience_did: &str,
            space_id: Uuid,
            permission: Permission,
            proofs: Vec<String>,
        ) -> String {
            let claims = UcanClaims {
                iss: self.did.clone(),
                aud: Some(AudienceClaim::One(audience_did.to_owned())),
                exp: Some(
                    (SystemTime::now() + Duration::from_secs(60 * 60))
                        .duration_since(UNIX_EPOCH)
                        .expect("time should be after epoch")
                        .as_secs(),
                ),
                nbf: None,
                cmd: permission.as_cmd().to_owned(),
                with_resource: format!("space:{space_id}"),
                nonce: "test-nonce".to_owned(),
                prf: proofs,
            };
            sign_es256_token(&claims, &self.key)
        }
    }

    fn sign_es256_token(claims: &UcanClaims, key: &SigningKey) -> String {
        let header = Header {
            alg: Algorithm::ES256,
            typ: Some("JWT".to_owned()),
            ..Header::default()
        };
        let header = serde_json::to_vec(&header).expect("serialize header");
        let claims = serde_json::to_vec(claims).expect("serialize claims");
        let header = URL_SAFE_NO_PAD.encode(header);
        let claims = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = key.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{signature}")
    }

    /// AUD-027: an interrupted first attempt (object stored, process lost
    /// before metadata commit) must not be falsely acknowledged on retry —
    /// the retry commits the missing metadata.
    #[tokio::test]
    async fn retry_of_interrupted_upload_commits_metadata() {
        let (app, sync_storage, blob_storage) = file_app_with_handles(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let payload = b"survivor of interrupted attempt";

        // Attempt 1: bytes land in the object store, metadata commit fails.
        *sync_storage.fail_record_file.lock().expect("fail lock") =
            Some(StorageError::Database("simulated crash".to_owned()));
        let first = app
            .clone()
            .oneshot(put_file_request(space_id, file_id, record_id, payload))
            .await
            .expect("dispatch request");
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(blob_storage
            .files
            .lock()
            .expect("blob lock")
            .contains_key(&(space_id, file_id)));

        // Attempt 2 (retry): object already exists — must still commit
        // metadata instead of acknowledging with a bare 204.
        *sync_storage.fail_record_file.lock().expect("fail lock") = None;
        let retry = app
            .oneshot(put_file_request(space_id, file_id, record_id, payload))
            .await
            .expect("dispatch request");
        assert_eq!(retry.status(), StatusCode::CREATED);
        assert!(sync_storage
            .metadata
            .lock()
            .expect("metadata lock")
            .contains_key(&(space_id, file_id)));
    }

    /// AUD-027: a fully-recorded file replays to 204 with no duplicate
    /// metadata write (idempotency preserved — not a behavior change).
    #[tokio::test]
    async fn replay_of_fully_recorded_upload_returns_204() {
        let (app, sync_storage, _blob_storage) = file_app_with_handles(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let payload = b"recorded once";

        let first = app
            .clone()
            .oneshot(put_file_request(space_id, file_id, record_id, payload))
            .await
            .expect("dispatch request");
        assert_eq!(first.status(), StatusCode::CREATED);

        let recorded = sync_storage
            .metadata
            .lock()
            .expect("metadata lock")
            .get(&(space_id, file_id))
            .cloned()
            .expect("metadata recorded");
        let original_cursor = recorded.cursor;

        let replay = app
            .oneshot(put_file_request(space_id, file_id, record_id, payload))
            .await
            .expect("dispatch request");
        assert_eq!(replay.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            sync_storage
                .metadata
                .lock()
                .expect("metadata lock")
                .get(&(space_id, file_id))
                .expect("metadata still present")
                .cursor,
            original_cursor
        );
    }

    /// AUD-027: a retry whose DEK is stale relative to the space's minimum
    /// key generation fails honestly (409) rather than acknowledging.
    #[tokio::test]
    async fn retry_with_stale_generation_conflicts() {
        let (app, sync_storage, _blob_storage) = file_app_with_handles(true);
        let space_id = personal_space_user1();
        let file_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let payload = b"stale dek";

        *sync_storage.fail_record_file.lock().expect("fail lock") = Some(StorageError::EpochStale);
        let response = app
            .oneshot(put_file_request(space_id, file_id, record_id, payload))
            .await
            .expect("dispatch request");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!sync_storage
            .metadata
            .lock()
            .expect("metadata lock")
            .contains_key(&(space_id, file_id)));
    }

    fn put_file_request(
        space_id: Uuid,
        file_id: Uuid,
        record_id: Uuid,
        payload: &[u8],
    ) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/spaces/{space_id}/files/{file_id}"))
            .header(AUTHORIZATION, "Bearer files-user1")
            .header(CONTENT_LENGTH, payload.len().to_string())
            .header("X-Record-ID", record_id.to_string())
            .header("X-Wrapped-DEK", STANDARD.encode([9u8; WRAPPED_DEK_LENGTH]))
            .body(Body::from(payload.to_vec()))
            .expect("build request")
    }

    fn personal_space_user1() -> Uuid {
        Uuid::parse_str("8e4f907f-cdb8-45a4-bb92-6d9c4f6e8b17").expect("uuid")
    }

    fn personal_space_user2() -> Uuid {
        Uuid::parse_str("7a9ecdd6-b4dc-43d2-9f71-da8bf11c3ac4").expect("uuid")
    }
}
