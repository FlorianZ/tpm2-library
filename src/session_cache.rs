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
    key::Tpm2shAlgId,
};
use std::{
    collections::{hash_map, HashMap, HashSet},
    path::{Path, PathBuf},
};
use thiserror::Error;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmRh, TpmSe, TpmaSession,
        TpmsAuthCommand, TpmsAuthResponse, TpmsContext,
    },
    message::{TpmAuthResponses, TpmStartAuthSessionResponse},
    tpm_hash_size, TpmBuffer, TpmBuild, TpmErrorKind, TpmHandle, TpmParse, TpmWriter,
};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid auth")]
    InvalidAuth,
    #[error("invalid key bits: {0}")]
    InvalidKeyBits(String),
    #[error("{0:08x} not found")]
    NotFound(u32),
    #[error("trailing passwords or sessions")]
    TrailingAuthValues,
    #[error("trailing data")]
    TrailingData,
    #[error("unsupported name algorithm: {0}")]
    UnsupportedNameAlgorithm(Tpm2shAlgId),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TPM: {0}")]
    Tpm(TpmErrorKind),
}

impl From<TpmErrorKind> for SessionError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
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
        let digest_len = tpm_hash_size(&auth_hash).ok_or(
            SessionError::UnsupportedNameAlgorithm(Tpm2shAlgId(auth_hash)),
        )?;

        let hmac_key_bytes = if session_type == TpmSe::Hmac {
            if auth_value.is_empty() {
                Vec::new()
            } else {
                let key_bits = digest_len * 8;
                let Ok(key_bits_u16) = u16::try_from(key_bits) else {
                    return Err(SessionError::InvalidKeyBits(key_bits.to_string()));
                };
                crypto_kdfa(
                    auth_hash,
                    auth_value,
                    "ATH",
                    &resp.nonce_tpm,
                    &nonce_caller,
                    key_bits_u16,
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
            hmac_key: Tpm2bAuth::try_from(hmac_key_bytes.as_slice())?,
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
            self.session_type.build(&mut writer)?;
            self.context.build(&mut writer)?;
            self.nonce_tpm.build(&mut writer)?;
            self.attributes.build(&mut writer)?;
            self.hmac_key.build(&mut writer)?;
            self.auth_hash.build(&mut writer)?;
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

        let (session_type, remainder) = TpmSe::parse(&session_bytes)?;
        let (context, remainder) = TpmsContext::parse(remainder)?;
        let (nonce_tpm, remainder) = Tpm2bNonce::parse(remainder)?;
        let (attributes, remainder) = TpmaSession::parse(remainder)?;
        let (hmac_key, remainder) = Tpm2bAuth::parse(remainder)?;
        let (auth_hash, remainder) = TpmAlgId::parse(remainder)?;

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
    pub sessions: HashMap<u32, Session>,
    pub dirty: HashSet<u32>,
    pub sessions_dir: PathBuf,
}

impl<'a> IntoIterator for &'a SessionCache {
    type Item = (&'a u32, &'a Session);
    type IntoIter = hash_map::Iter<'a, u32, Session>;

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
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                let _ = std::fs::remove_file(path);
                continue;
            }

            let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
                let _ = std::fs::remove_file(path);
                continue;
            };

            let Ok(vhandle) = u32::from_str_radix(file_stem, 16) else {
                let _ = std::fs::remove_file(path);
                continue;
            };

            let session = Session::load_from_path(&path)?;

            if session.context.saved_handle.0 != vhandle {
                let _ = std::fs::remove_file(path);
                continue;
            }

            self.sessions.insert(vhandle, session);
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

        for vhandle in self.dirty.drain() {
            if let Some(session) = self.sessions.get(&vhandle) {
                let handle = session.context.saved_handle.0;
                let path = self.sessions_dir.join(format!("{handle:08x}.bin"));
                session.save_to_path(&path)?;
            }
        }
        Ok(())
    }

    /// Adds a new session and returns its URI.
    pub fn add(&mut self, session: Session) -> u32 {
        let vhandle = session.context.saved_handle.0;
        self.sessions.insert(vhandle, session);
        self.dirty.insert(vhandle);
        vhandle
    }

    /// Removes a session from the map and deletes its file from disk. This
    /// operation is idempotent.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` on I/O failure (e.g. permissions).
    pub fn remove(&mut self, vhandle: u32) -> Result<Option<Session>, SessionError> {
        let session = self.sessions.remove(&vhandle);
        self.dirty.remove(&vhandle);
        let path = self.sessions_dir.join(format!("{vhandle:08x}.bin"));
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(session)
    }

    /// Gets an immutable reference to a session.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::NotFound` if no session is found.
    pub fn get(&self, vhandle: u32) -> Result<&Session, SessionError> {
        self.sessions
            .get(&vhandle)
            .ok_or(SessionError::NotFound(vhandle))
    }

    /// Gets a mutable reference to a session, marks it as dirty.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::NotFound` if no session is found.
    pub fn get_mut(&mut self, vhandle: u32) -> Result<&mut Session, SessionError> {
        self.dirty.insert(vhandle);
        self.sessions
            .get_mut(&vhandle)
            .ok_or(SessionError::NotFound(vhandle))
    }

    /// Returns an iterator over the sessions.
    #[must_use]
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, u32, Session> {
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
                let vhandle = handle.value_raw();
                let session_is_loaded = {
                    let session = self.get(vhandle)?;
                    session.handle.0 != 0
                };
                if !session_is_loaded {
                    let new_handle = {
                        let session = self.get(vhandle)?;
                        device.load_context(session.context.clone())?
                    };
                    let session = self.get_mut(vhandle)?;
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
        session_vhandles: &HashSet<u32>,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), SessionError> {
        for (i, vhandle) in session_vhandles.iter().enumerate() {
            let session_handle = self.get(*vhandle)?.handle;
            if session_handle.0 == 0 {
                continue;
            }

            match device.save_context(session_handle.0) {
                Ok(new_context) => {
                    let session = self.get_mut(*vhandle)?;
                    session.context = new_context;
                    let auth: TpmsAuthResponse = auth_responses[i];
                    session.nonce_tpm = auth.nonce;
                    session.attributes = auth.session_attributes;
                }
                Err(e) => {
                    if let Err(e) = device.flush_context(session_handle) {
                        log::warn!("{session_handle}: {e}");
                    }
                    if let Ok(session) = self.get_mut(*vhandle) {
                        session.handle = TpmHandle(0);
                    } else {
                        log::warn!("unknown {session_handle}");
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
        hmac: Tpm2bAuth::try_from(password)?,
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
        .map(|&handle| device.read_public(handle.into()).map(|(_, name)| name))
        .collect::<Result<_, DeviceError>>()?;

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
        hmac: Tpm2bAuth::try_from(hmac_bytes.as_slice())?,
    })
}
