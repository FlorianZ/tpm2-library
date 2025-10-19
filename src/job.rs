// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    convert::from_tpm_object_to_vec,
    device::{Device, DeviceError, TpmCommandObject},
    key::{AnyKey, KeyError, TpmKey},
    key::{KeyCache, KeyCacheError},
    session::{build_password_session, create_auth, SessionCache, SessionError},
};
use rand::{thread_rng, RngCore};
use std::{cell::RefCell, collections::HashSet, rc::Rc};
use tpm2_protocol::{
    data::{Tpm2bNonce, TpmCc, TpmRh, TpmaNv, TpmaSession, TpmsAuthCommand},
    message::{TpmAuthResponses, TpmNvReadCommand, TpmNvReadPublicCommand, TpmResponseBody},
    tpm_hash_size, TpmErrorKind, TpmHandle,
};

pub struct Job<'a> {
    pub device: Option<Rc<RefCell<Device>>>,
    pub key_cache: KeyCache<'a>,
    pub session_cache: SessionCache,
}

impl<'a> Job<'a> {
    /// Creates a new `Job`.
    #[must_use]
    pub fn new(
        device: Option<Rc<RefCell<Device>>>,
        key_cache: KeyCache<'a>,
        session_cache: SessionCache,
    ) -> Self {
        Self {
            device,
            key_cache,
            session_cache,
        }
    }

    /// Builds the authorization area for a command.
    ///
    /// # Errors
    ///
    /// Returns a `SessionError` if a session URI is not found, or if building
    /// any part of the authorization command fails.
    fn build_auth_area<C: TpmCommandObject>(
        &self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<Vec<TpmsAuthCommand>, SessionError> {
        let mut built_auths = Vec::new();
        let params = from_tpm_object_to_vec(command).map_err(DeviceError::Tpm)?;

        let mut nonce_decrypt: Option<Tpm2bNonce> = None;
        let mut nonce_encrypt: Option<Tpm2bNonce> = None;

        for auth in auth_list {
            if let Auth::Session(session_handle) = auth {
                let uri = Auth::Session(*session_handle).to_string();
                if let Ok(session) = self.session_cache.get(&uri) {
                    if session.attributes.contains(TpmaSession::DECRYPT) {
                        nonce_decrypt = Some(session.nonce_tpm);
                    }
                    if session.attributes.contains(TpmaSession::ENCRYPT) {
                        nonce_encrypt = Some(session.nonce_tpm);
                    }
                }
                if nonce_decrypt.is_some() && nonce_encrypt.is_some() {
                    break;
                }
            }
        }

        for (i, auth) in auth_list.iter().enumerate() {
            let handle = handles.get(i).ok_or(SessionError::TrailingAuthValues)?;

            match auth {
                Auth::Password(password) => {
                    built_auths.push(build_password_session(password)?);
                }
                Auth::Session(session_handle) => {
                    let uri = Auth::Session(*session_handle).to_string();
                    let session = self.session_cache.get(&uri)?;

                    let nonce_size = tpm_hash_size(&session.auth_hash)
                        .ok_or(DeviceError::Tpm(TpmErrorKind::InvalidValue))?;
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce_caller =
                        Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(DeviceError::Tpm)?;
                    let (nonce_decrypt, nonce_encrypt) = if i == 0 {
                        (nonce_decrypt.as_ref(), nonce_encrypt.as_ref())
                    } else {
                        (None, None)
                    };

                    let result = create_auth(
                        device,
                        session,
                        &nonce_caller,
                        &[],
                        C::CC,
                        &[*handle],
                        &params,
                        nonce_decrypt,
                        nonce_encrypt,
                    )?;
                    built_auths.push(result);
                }
                Auth::Policy(_) => return Err(SessionError::InvalidAuth),
            }
        }
        Ok(built_auths)
    }

    /// Executes a TPM command with full authorization session handling.
    ///
    /// This function encapsulates the prepare, build, execute, and teardown
    /// sequence for authorized commands.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` if any stage of the session management or
    /// command execution fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auths: &mut [Auth],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), KeyCacheError> {
        let persistent_auths: Vec<Auth> = auths.to_vec();

        let session_handles = self
            .session_cache
            .prepare_sessions(device, &persistent_auths)?;
        for &handle in &session_handles {
            self.key_cache.track(tpm2_protocol::TpmHandle(handle))?;
        }

        let sessions = self.build_auth_area(device, command, handles, auths)?;
        let (resp, auth_responses) = device.execute(command, &sessions)?;

        let mut persistent_session_handles_used = HashSet::new();
        for auth in &persistent_auths {
            if let Auth::Session(handle) = auth {
                persistent_session_handles_used.insert(*handle);
            }
        }

        self.session_cache.teardown_sessions(
            device,
            &persistent_session_handles_used,
            &auth_responses,
        )?;
        for handle in session_handles {
            self.key_cache.untrack(handle);
        }
        Ok((resp, auth_responses))
    }

    /// Imports an external key under a TPM parent, creating a new `TpmKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM import operation fails.
    pub fn import_key(
        &mut self,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &mut [Auth],
    ) -> Result<TpmKey, KeyCacheError> {
        let external_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(_) => return Err(KeyCacheError::Key(KeyError::InvalidFormat)),
            AnyKey::External(key) => key,
        };
        let mut rng = rand::thread_rng();
        Ok(TpmKey::from_external_key(
            device,
            self,
            parent_handle,
            &external_key,
            &mut rng,
            &[parent_handle.0],
            auths,
        )?)
    }

    /// Reads a certificate from a given NV index.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` if the TPM commands fail or if the response is invalid.
    pub fn read_certificate(
        &mut self,
        device: &mut Device,
        auths: &mut [Auth],
        handle: u32,
        max_read_size: usize,
    ) -> Result<Option<Vec<u8>>, KeyCacheError> {
        let nv_read_public_cmd = TpmNvReadPublicCommand {
            nv_index: handle.into(),
        };
        let (resp, _) = device.execute(&nv_read_public_cmd, &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size as usize;

        if data_size == 0 {
            return Ok(None);
        }

        let auth_handle = if nv_public.attributes.contains(TpmaNv::AUTHREAD) {
            handle
        } else if nv_public.attributes.contains(TpmaNv::PPREAD) {
            TpmRh::Platform as u32
        } else if nv_public.attributes.contains(TpmaNv::OWNERREAD) {
            TpmRh::Owner as u32
        } else {
            handle
        };

        let mut cert_bytes = Vec::with_capacity(data_size);
        let mut offset = 0;
        while offset < data_size {
            let chunk_size = std::cmp::min(max_read_size, data_size - offset);

            let nv_read_cmd = TpmNvReadCommand {
                auth_handle: auth_handle.into(),
                nv_index: handle.into(),
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
            };

            let (resp, _) = self.execute(device, &nv_read_cmd, &[auth_handle], auths)?;

            let read_resp = resp
                .NvRead()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::NvRead))?;
            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += chunk_size;
        }

        Ok(Some(cert_bytes))
    }
}

impl Drop for Job<'_> {
    fn drop(&mut self) {
        self.key_cache.teardown(self.device.clone());
        if let Err(e) = self.session_cache.save() {
            log::error!("teardown: {e:#}");
        }
    }
}
