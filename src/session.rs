// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! For sessions, context managements works as follows:
//!
//! 1. `TPM2_ContextSave` transforms an active session into saved session, which
//!    gets a handle from the same address range as HMAC sessions.
//! 2. `TPM2_ContextLoad` transforms a saved session into active session, and
//!    session regains the handle assigned upon creation.
//!
//! Consequences:
//!
//! 1. `TPM2_FlushContext` must not be applied after `TPM2_ContextSave`.
//! 2. `TPM2_FlushContext` can be only applied to a loaded session.

use crate::{
    auth::Auth,
    crypto::{crypto_digest, crypto_hmac, crypto_kdfa, CryptoError},
    device::{Device, DeviceError},
    uri::Uri,
};
use std::{
    collections::{hash_map, HashMap, HashSet},
    num::TryFromIntError,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmRcBase, TpmRh, TpmSe, TpmaSession,
        TpmsAuthCommand, TpmsAuthResponse, TpmsContext,
    },
    message::{TpmAuthResponses, TpmStartAuthSessionResponse},
    tpm_hash_size, TpmBuffer, TpmBuild, TpmErrorKind, TpmHandle, TpmParse, TpmWriter,
};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid auth")]
    InvalidAuth,
    #[error("{0} not found")]
    NotFound(String),
    #[error("trailing data")]
    TrailingData,
    #[error("trailing passwords or sessions")]
    TrailingAuthValues,
}

impl From<TryFromIntError> for SessionError {
    fn from(_err: TryFromIntError) -> Self {
        Self::Device(DeviceError::Tpm(TpmErrorKind::InvalidValue))
    }
}

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct Session {
    pub handle: TpmHandle,
    pub context: TpmsContext,
    pub nonce_tpm: Tpm2bNonce,
    pub attributes: TpmaSession,
    pub hmac_key: Tpm2bAuth,
    pub auth_hash: TpmAlgId,
    pub session_type: TpmSe,
}

impl Session {
    /// Creates a new session from a `StartAuthSession` response.
    ///
    /// # Errors
    ///
    /// Returns a `SessionError` if key derivation for the HMAC key fails or if
    /// other value conversions are not possible.
    pub fn new(
        session_type: TpmSe,
        auth_hash: TpmAlgId,
        nonce_caller: Tpm2bNonce,
        resp: &TpmStartAuthSessionResponse,
        auth_value: &[u8],
    ) -> Result<Self, SessionError> {
        let digest_len =
            tpm_hash_size(&auth_hash).ok_or(DeviceError::Tpm(TpmErrorKind::InvalidValue))?;

        let hmac_key_bytes = if session_type == TpmSe::Hmac {
            if auth_value.is_empty() {
                Vec::new()
            } else {
                let key_bits = u16::try_from(digest_len * 8)?;
                crypto_kdfa(
                    auth_hash,
                    auth_value,
                    "ATH",
                    &resp.nonce_tpm,
                    &nonce_caller,
                    key_bits,
                )
                .map_err(SessionError::Crypto)?
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            handle: resp.session_handle,
            context: TpmsContext {
                sequence: 0,
                saved_handle: resp.session_handle.0.into(),
                hierarchy: TpmRh::Null,
                context_blob: TpmBuffer::default(),
            },
            nonce_tpm: resp.nonce_tpm,
            attributes: TpmaSession::CONTINUE_SESSION,
            hmac_key: Tpm2bAuth::try_from(hmac_key_bytes.as_slice()).map_err(DeviceError::Tpm)?,
            auth_hash,
            session_type,
        })
    }

    /// Saves a session's state to a binary file.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::Io` on I/O failure.
    pub fn save_to_path(&self, path: &Path) -> Result<(), SessionError> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            self.session_type
                .build(&mut writer)
                .map_err(DeviceError::Tpm)?;
            self.context.build(&mut writer).map_err(DeviceError::Tpm)?;
            self.nonce_tpm
                .build(&mut writer)
                .map_err(DeviceError::Tpm)?;
            self.attributes
                .build(&mut writer)
                .map_err(DeviceError::Tpm)?;
            self.hmac_key.build(&mut writer).map_err(DeviceError::Tpm)?;
            self.auth_hash
                .build(&mut writer)
                .map_err(DeviceError::Tpm)?;
            writer.len()
        };
        buf.truncate(len);

        std::fs::write(path, &buf)?;
        Ok(())
    }

    /// Loads a session from a binary file.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::Io` on I/O failure.
    pub fn load_from_path(path: &Path) -> Result<Self, SessionError> {
        let session_bytes = std::fs::read(path)?;

        let (session_type, remainder) = TpmSe::parse(&session_bytes).map_err(DeviceError::Tpm)?;
        let (context, remainder) = TpmsContext::parse(remainder).map_err(DeviceError::Tpm)?;
        let (nonce_tpm, remainder) = Tpm2bNonce::parse(remainder).map_err(DeviceError::Tpm)?;
        let (attributes, remainder) = TpmaSession::parse(remainder).map_err(DeviceError::Tpm)?;
        let (hmac_key, remainder) = Tpm2bAuth::parse(remainder).map_err(DeviceError::Tpm)?;
        let (auth_hash, remainder) = TpmAlgId::parse(remainder).map_err(DeviceError::Tpm)?;

        if !remainder.is_empty() {
            return Err(SessionError::TrailingData);
        }

        Ok(Self {
            handle: TpmHandle(0),
            context,
            nonce_tpm,
            attributes,
            hmac_key,
            auth_hash,
            session_type,
        })
    }
}

#[derive(Debug)]
pub struct SessionCache {
    pub sessions: HashMap<String, Session>,
    pub dirty: HashSet<String>,
    pub sessions_dir: PathBuf,
}

impl<'a> IntoIterator for &'a SessionCache {
    type Item = (&'a String, &'a Session);
    type IntoIter = hash_map::Iter<'a, String, Session>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl SessionCache {
    /// Creates a new, empty `SessionCache`.
    #[must_use]
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            sessions: HashMap::new(),
            dirty: HashSet::new(),
            sessions_dir: cache_dir.join("sessions"),
        }
    }

    /// Populates the session map by reading all available session files from the
    /// cache directory.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` on I/O failure.
    pub fn load_sessions(&mut self) -> Result<(), SessionError> {
        std::fs::create_dir_all(&self.sessions_dir)?;

        let entries = match std::fs::read_dir(&self.sessions_dir) {
            Ok(entries) => entries.filter_map(Result::ok),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("session") {
                continue;
            }

            let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let Ok(handle) = u32::from_str_radix(file_stem, 16) else {
                log::warn!("Invalid session filename format: '{}'", path.display());
                continue;
            };

            let session = match Session::load_from_path(&path) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!(
                        "Failed to load session file '{}': {e}. Deleting.",
                        path.display()
                    );
                    let _ = std::fs::remove_file(path);
                    continue;
                }
            };

            if session.context.saved_handle.0 != handle {
                log::warn!(
                    "Session file '{}' has mismatched handle in its content. Deleting.",
                    path.display()
                );
                let _ = std::fs::remove_file(path);
                continue;
            }

            let uri = Auth::Session(handle).to_string();
            self.sessions.insert(uri, session);
        }
        Ok(())
    }

    /// Validates all sessions at startup, and removes expired sessions from the
    /// previous power cycle.
    ///
    /// # Errors
    ///
    /// Returns an aggregate `DeviceError` if any non-recoverable errors occur.
    /// Individual session failures are logged as warnings.
    pub fn refresh_sessions(&mut self, device: &mut Device) -> Result<(), SessionError> {
        let uris_to_refresh: Vec<String> = self.sessions.keys().cloned().collect();
        for uri in uris_to_refresh {
            let session = match self.get(&uri) {
                Ok(s) => s.clone(),
                Err(_) => continue,
            };

            match device.load_context(session.context.clone()) {
                Ok(live_handle) => match device.save_context(live_handle) {
                    Ok(new_context) => {
                        if let Ok(s) = self.get_mut(&uri) {
                            s.context = new_context;
                        }
                    }
                    Err(e) => log::warn!("{uri}: {e}"),
                },
                Err(DeviceError::TpmRc(rc))
                    if matches!(rc.base(), TpmRcBase::Handle | TpmRcBase::ReferenceH0) =>
                {
                    log::debug!("Removing stale session file for {uri}");
                    if self.remove(&uri).is_err() {
                        log::warn!("Failed to remove stale session for {uri}");
                    }
                }
                Err(e) => log::warn!("{uri}: {e}"),
            }
        }

        Ok(())
    }

    /// Saves all sessions marked as dirty to their respective files.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization or I/O failure.
    pub fn save(&mut self) -> Result<(), SessionError> {
        if self.dirty.is_empty() {
            return Ok(());
        }

        std::fs::create_dir_all(&self.sessions_dir)?;

        for uri in self.dirty.drain() {
            if let Some(session) = self.sessions.get(&uri) {
                let handle = session.context.saved_handle.0;
                let path = self.sessions_dir.join(format!("{handle:x}.session"));
                session.save_to_path(&path)?;
            }
        }
        Ok(())
    }

    /// Adds a new session and returns its URI.
    pub fn add(&mut self, session: Session) -> String {
        let handle = session.context.saved_handle.0;
        let uri = Auth::Session(handle).to_string();
        self.sessions.insert(uri.clone(), session);
        self.dirty.insert(uri.clone());
        uri
    }

    /// Removes a session from the map and deletes its file from disk. This
    /// operation is idempotent.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` on I/O failure (e.g. permissions).
    pub fn remove(&mut self, uri: &str) -> Result<Option<Session>, SessionError> {
        let session = self.sessions.remove(uri);
        self.dirty.remove(uri);

        if let Ok(parsed_uri) = Uri::from_str(uri) {
            if let Ok(handle) = parsed_uri.to_handle() {
                let path = self.sessions_dir.join(format!("{handle:x}.session"));
                if let Err(e) = std::fs::remove_file(path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(session)
    }

    /// Removes all sessions from the map and deletes their files from disk.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::Io` on I/O failure.
    pub fn reset(&mut self) -> Result<(), SessionError> {
        for session in self.sessions.values() {
            let handle = session.context.saved_handle.0;
            let path = self.sessions_dir.join(format!("{handle:x}.session"));
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        self.sessions.clear();
        self.dirty.clear();
        Ok(())
    }

    /// Gets an immutable reference to a session.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::NotFound` if no session is found.
    pub fn get(&self, uri: &str) -> Result<&Session, SessionError> {
        self.sessions
            .get(uri)
            .ok_or_else(|| SessionError::NotFound(uri.to_string()))
    }

    /// Gets a mutable reference to a session, marks it as dirty.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::NotFound` if no session is found.
    pub fn get_mut(&mut self, uri: &str) -> Result<&mut Session, SessionError> {
        self.dirty.insert(uri.to_string());
        self.sessions
            .get_mut(uri)
            .ok_or_else(|| SessionError::NotFound(uri.to_string()))
    }

    /// Returns an iterator over the sessions.
    #[must_use]
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, String, Session> {
        self.sessions.iter()
    }

    /// Loads session contexts if they are not already active.
    ///
    /// # Errors
    ///
    /// Returns a `SessionError` if a session URI is invalid or if loading a TPM
    /// context fails.
    pub fn prepare_sessions(
        &mut self,
        device: &mut Device,
        auth_list: &[Auth],
    ) -> Result<Vec<u32>, SessionError> {
        let mut activated_handles = Vec::new();
        for auth in auth_list {
            if let Auth::Session(handle) = auth {
                let uri = Auth::Session(*handle).to_string();
                let session_is_loaded = {
                    let session = self.get(&uri)?;
                    session.handle.0 != 0
                };
                if !session_is_loaded {
                    let new_handle = {
                        let session = self.get(&uri)?;
                        device.load_context(session.context.clone())?
                    };
                    let session = self.get_mut(&uri)?;
                    session.handle = TpmHandle(new_handle);
                    activated_handles.push(new_handle);
                }
            }
        }
        Ok(activated_handles)
    }

    /// Finalizes sessions after a command executes.
    ///
    /// # Errors
    ///
    /// Returns a `SessionError` if a session URI is not found, or if
    /// saving/flushing the updated TPM context fails.
    pub fn teardown_sessions(
        &mut self,
        device: &mut Device,
        session_handles: &HashSet<u32>,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), SessionError> {
        for (i, handle) in session_handles.iter().enumerate() {
            let uri = Auth::Session(*handle).to_string();
            let session_handle = self.get(&uri)?.handle;
            if session_handle.0 == 0 {
                continue;
            }

            match device.save_context(session_handle.0) {
                Ok(new_context) => {
                    let session = self.get_mut(&uri)?;
                    session.context = new_context;
                    let auth: TpmsAuthResponse = auth_responses[i];
                    session.nonce_tpm = auth.nonce;
                    session.attributes = auth.session_attributes;
                }
                Err(e) => {
                    log::warn!("Failed to save session context for {uri}: {e}. Flushing handle.");

                    if device.flush_context(session_handle.0).is_err() {
                        log::warn!("Failed to flush orphaned session handle {session_handle}.");
                    }

                    if let Ok(session) = self.get_mut(&uri) {
                        session.handle = TpmHandle(0);
                    } else {
                        log::warn!("Session '{uri}' not found during error handling.");
                    }

                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, SessionError> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(DeviceError::Tpm)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_auth(
    device: &mut Device,
    session: &Session,
    nonce_caller: &Tpm2bNonce,
    auth_value: &[u8],
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
    nonce_decrypt: Option<&Tpm2bNonce>,
    nonce_encrypt: Option<&Tpm2bNonce>,
) -> Result<TpmsAuthCommand, SessionError> {
    let handle_names: Vec<Tpm2bName> = handles
        .iter()
        .map(|&handle| device.name_cache_get(handle))
        .collect::<Result<_, _>>()?;

    let command_code_bytes = (command_code as u32).to_be_bytes();

    let mut cp_hash_chunks: Vec<&[u8]> = Vec::with_capacity(2 + handle_names.len());
    cp_hash_chunks.push(&command_code_bytes);
    for name in &handle_names {
        cp_hash_chunks.push(name.as_ref());
    }
    cp_hash_chunks.push(parameters);

    let cp_hash = crypto_digest(session.auth_hash, &cp_hash_chunks)?;

    let hmac_bytes = if session.session_type == TpmSe::Hmac {
        let hmac_key = [session.hmac_key.as_ref(), auth_value].concat();

        let mut hmac_payload: Vec<&[u8]> = Vec::with_capacity(8);
        hmac_payload.push(&cp_hash);
        hmac_payload.push(nonce_caller.as_ref());
        hmac_payload.push(session.nonce_tpm.as_ref());

        if let Some(nonce) = nonce_decrypt {
            hmac_payload.push(nonce.as_ref());
        }
        if let Some(nonce) = nonce_encrypt {
            if nonce_decrypt.map_or(true, |d| d.as_ref() != nonce.as_ref()) {
                hmac_payload.push(nonce.as_ref());
            }
        }

        let attribute_bits = [session.attributes.bits()];
        hmac_payload.push(&attribute_bits);

        crypto_hmac(session.auth_hash, &hmac_key, &hmac_payload)?
    } else {
        Vec::new()
    };

    Ok(TpmsAuthCommand {
        session_handle: session.handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::try_from(hmac_bytes.as_slice()).map_err(DeviceError::Tpm)?,
    })
}
