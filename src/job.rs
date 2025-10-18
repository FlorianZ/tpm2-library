// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    command::CommandError,
    context::{ContextCache, ContextError},
    device::{with_device, Device, DeviceError, TpmCommandObject},
    key::{AnyKey, KeyError, TpmKey},
    session::{Session as SessionData, SessionCache},
};
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{TpmAlgId, TpmCc, TpmRh, TpmSe, TpmaNv},
    message::{TpmAuthResponses, TpmNvReadCommand, TpmNvReadPublicCommand, TpmResponseBody},
    TpmHandle,
};

pub struct Job<'a> {
    pub device: Option<Rc<RefCell<Device>>>,
    pub context_cache: ContextCache<'a>,
    pub session_cache: SessionCache,
    pub temp_session_uris: Vec<String>,
}

impl Job<'_> {
    /// Executes a TPM command with full authorization session handling.
    ///
    /// This function encapsulates the prepare, build, execute, and teardown
    /// sequence for authorized commands.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if any stage of the session management or
    /// command execution fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auths: &[Auth],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), ContextError> {
        let session_handles = self.session_cache.prepare_sessions(device, auths)?;
        for &handle in &session_handles {
            self.context_cache.track(tpm2_protocol::TpmHandle(handle))?;
        }
        let (sessions, session_handles_used) = self
            .session_cache
            .build_auth_area(device, command, handles, auths)?;
        let (resp, auth_responses) = device.execute(command, &sessions)?;
        self.session_cache
            .teardown_sessions(device, &session_handles_used, &auth_responses)?;
        for handle in session_handles {
            self.context_cache.untrack(handle);
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
        auths: &[Auth],
    ) -> Result<TpmKey, ContextError> {
        let external_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(_) => return Err(ContextError::Key(KeyError::InvalidFormat)),
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
    /// Returns a `ContextError` if the TPM commands fail or if the response is invalid.
    pub fn read_certificate(
        &mut self,
        device: &mut Device,
        auths: &[Auth],
        handle: u32,
        max_read_size: usize,
    ) -> Result<Option<Vec<u8>>, ContextError> {
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

    /// Resolves an authorization string, implicitly upgrading non-empty passwords
    /// to temporary HMAC sessions if permitted by the object's attributes.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` on parsing or session creation failures.
    pub fn resolve_auth_session(&mut self, auth_opt: Option<Auth>) -> Result<Auth, CommandError> {
        let Some(auth) = auth_opt else {
            return Ok(Auth::Password(Vec::new()));
        };
        match auth {
            Auth::Password(p) if !p.is_empty() => {
                let temp_session = with_device(self.device.clone(), |device| {
                    let auth_hash = TpmAlgId::Sha256;
                    let (resp, nonce_caller) = device.start_session(TpmSe::Hmac, auth_hash)?;
                    SessionData::new(TpmSe::Hmac, auth_hash, nonce_caller, &resp, &p)
                })?;

                let handle = temp_session.context.saved_handle.0;
                let uri_str = self.session_cache.add(temp_session);
                self.temp_session_uris.push(uri_str);
                Ok(Auth::Session(handle))
            }
            Auth::Password(p) => Ok(Auth::Password(p)),
            Auth::Policy(p) => Ok(Auth::Policy(p)),
            Auth::Session(h) => Ok(Auth::Session(h)),
        }
    }
}

impl Drop for Job<'_> {
    fn drop(&mut self) {
        if !self.temp_session_uris.is_empty() {
            if let Some(dev_rc) = self.device.clone() {
                if let Ok(mut dev) = dev_rc.try_borrow_mut() {
                    for uri in &self.temp_session_uris {
                        if let Ok(session) = self.session_cache.get(uri) {
                            if let Err(e) = dev.flush_session(session.context.clone()) {
                                log::warn!("Failed to flush temporary HMAC session {uri}: {e}");
                            }
                        }
                    }
                }
            }
            for uri in self.temp_session_uris.drain(..) {
                if self.session_cache.remove(&uri).is_err() {
                    log::warn!("Failed to remove temporary HMAC session {uri} from cache.");
                }
            }
        }
        self.context_cache.teardown(self.device.clone());
        if let Err(e) = self.session_cache.save() {
            log::error!("teardown: {e:#}");
        }
    }
}
