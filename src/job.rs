// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::{Auth, AuthClass, AuthError},
    crypto::{crypto_hash_size, CryptoError},
    device::{with_device, Device, DeviceError, TpmCommandObject},
    handle::{Handle, HandleClass},
    key::{AnyKey, KeyError, TpmKey},
    vtpm::{build_password_session, create_auth, VtpmCache, VtpmContext, VtpmError},
    write_object,
};
use rand::{thread_rng, RngCore};
use std::{cell::RefCell, collections::HashSet, io, io::Write, num::TryFromIntError, rc::Rc};
use thiserror::Error;
use tpm2_protocol::{
    data::{
        Tpm2bNonce, Tpm2bPrivate, TpmAlgId, TpmCc, TpmRcBase, TpmRh, TpmaNv, TpmaSession,
        TpmsAuthCommand,
    },
    message::{
        TpmAuthResponses, TpmEvictControlCommand, TpmLoadCommand, TpmNvReadCommand,
        TpmNvReadPublicCommand, TpmResponseBody,
    },
    TpmError, TpmHandle, TpmParse,
};

#[derive(Debug, Error)]
pub enum JobError {
    #[error("handle not found: {0}{1:08x}")]
    HandleNotFound(&'static str, u32),
    #[error("invalid auth")]
    InvalidAuth,
    #[error("invalid key format")]
    InvalidFormat,
    #[error("invalid parent: {0}{1:08x}")]
    InvalidParent(&'static str, u32),
    #[error("malformed data")]
    MalformedData,
    #[error("parent not found")]
    ParentNotFound,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("trailing authorizations")]
    TrailingAuthorizations,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("cache: {0}")]
    Vtpm(#[from] VtpmError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
}

impl From<TpmError> for JobError {
    fn from(err: TpmError) -> Self {
        Self::Device(DeviceError::from(err))
    }
}

pub struct Job<'a> {
    pub device: Option<Rc<RefCell<Device>>>,
    pub cache: &'a mut VtpmCache<'a>,
    pub auth_list: &'a [Auth],
    pub writer: &'a mut dyn Write,
}

impl<'a> Job<'a> {
    /// Creates a new `Job`.
    #[must_use]
    pub fn new(
        device: Option<Rc<RefCell<Device>>>,
        cache: &'a mut VtpmCache<'a>,
        auth_list: &'a [Auth],
        writer: &'a mut dyn Write,
    ) -> Self {
        Self {
            device,
            cache,
            auth_list,
            writer,
        }
    }

    /// Loads a TPM context from a handle, recursively loading its ancestors
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when
    /// the given VTPM handle does not exist.
    /// Returns [`ParentNotFound`](crate::job::JobError::HandleNotFound) when
    /// for the given handle neither VTPM nor persistent parent is found.
    pub fn load_context(
        &mut self,
        device: &mut Device,
        target: &Handle,
        auths: &[Auth],
    ) -> Result<TpmHandle, JobError> {
        if target.class() == HandleClass::Tpm {
            return Ok(TpmHandle(target.value()));
        }

        let mut vhandle = target.value();
        let mut ancestor_list: Vec<(u32, Auth)> = vec![(vhandle, Auth::default())];
        let primary_handle: Option<TpmHandle>;

        loop {
            let key = self.cache.find_by_vhandle(vhandle)?;

            if key.parent.inner.object_type == TpmAlgId::Null {
                primary_handle = None;
                break;
            }

            if let Some(parent_key) = self.cache.find_by_public(&key.parent.inner) {
                let parent_vhandle = parent_key.handle();
                let parent_index = ancestor_list.len();
                let parent_auth = auths.get(parent_index).cloned().unwrap_or_default();

                ancestor_list.push((parent_vhandle, parent_auth));
                vhandle = parent_vhandle;
            } else {
                match device.find_persistent(&key.parent.inner)? {
                    Some((phandle, _)) => {
                        primary_handle = Some(phandle);
                        break;
                    }
                    None => {
                        return Err(JobError::ParentNotFound);
                    }
                }
            }
        }

        if auths.len() > ancestor_list.len() {
            return Err(JobError::TrailingAuthorizations);
        }

        ancestor_list.reverse();

        let mut phandle: Option<TpmHandle> = primary_handle;

        for (vhandle, auth) in ancestor_list {
            let key = self.cache.find_by_vhandle(vhandle)?;

            let loaded_phandle = if let Some(parent_phandle) = phandle {
                let (in_private, _) = Tpm2bPrivate::parse(&key.context.context_blob)?;
                let cmd = TpmLoadCommand {
                    parent_handle: parent_phandle,
                    in_private,
                    in_public: key.public.clone(),
                };
                let (resp_body, _) = self.execute(device, &cmd, &[parent_phandle.0], &[auth])?;
                let resp = resp_body
                    .Load()
                    .map_err(|_| JobError::ResponseMismatch(TpmCc::Load))?;
                resp.object_handle
            } else {
                let handle_val = device.load_context(key.context.clone())?;
                TpmHandle(handle_val)
            };

            self.cache.track(loaded_phandle)?;
            phandle = Some(loaded_phandle);
        }

        phandle.ok_or(JobError::HandleNotFound("vtpm:", target.value()))
    }

    /// Builds the authorization area for a command.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if a session is not found, or if building
    /// any part of the authorization command fails.
    fn build_auth_area<C: TpmCommandObject>(
        &self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<Vec<TpmsAuthCommand>, JobError> {
        let mut built_auths = Vec::new();
        let params = write_object(command).map_err(DeviceError::TpmProtocol)?;

        let mut nonce_decrypt: Option<Tpm2bNonce> = None;
        let mut nonce_encrypt: Option<Tpm2bNonce> = None;

        for auth in auth_list {
            if auth.class() == AuthClass::Session {
                let vhandle = auth.session()?;
                if let Some(session) = self.cache.get_session(vhandle) {
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
            let handle_param = handles.get(i).ok_or(JobError::TrailingAuthorizations)?;

            match auth.class() {
                AuthClass::Password => {
                    built_auths.push(build_password_session(auth.value())?);
                }
                AuthClass::Session => {
                    let vhandle = auth.session()?;
                    let session = self
                        .cache
                        .get_session(vhandle)
                        .ok_or(JobError::HandleNotFound("vtpm:", vhandle))?;
                    let nonce_size =
                        crypto_hash_size(session.auth_hash).ok_or(JobError::MalformedData)?;
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(DeviceError::TpmProtocol)?;
                    let (current_nonce_decrypt, current_nonce_encrypt) = if i == 0 {
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
                        &[*handle_param],
                        &params,
                        current_nonce_decrypt,
                        current_nonce_encrypt,
                    )?;
                    built_auths.push(result);
                }
                AuthClass::Policy => return Err(JobError::InvalidAuth),
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
    /// Returns a [`JobError`] if any stage of the session management or
    /// command execution fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), JobError> {
        let auth_handles = self.cache.prepare_sessions(device, auth_list)?;
        for &handle in &auth_handles {
            self.cache.track(handle)?;
        }

        let sessions = self.build_auth_area(device, command, handles, auth_list)?;
        let (resp, auth_responses) = match device.execute(command, &sessions) {
            Ok((resp, auth_responses)) => (resp, auth_responses),
            Err(DeviceError::TpmRc(rc)) => {
                if rc.base() == TpmRcBase::PolicyFail {
                    for auth in auth_list {
                        if auth.class() == AuthClass::Session {
                            let vhandle = auth.session()?;
                            log::debug!("vtpm:{vhandle} is stale");
                            self.cache.remove(device, vhandle)?;
                        }
                    }
                }
                return Err(JobError::Device(DeviceError::TpmRc(rc)));
            }
            Err(err) => return Err(JobError::Device(err)),
        };

        let mut used_auth_list = HashSet::new();
        for auth in auth_list {
            if auth.class() == AuthClass::Session {
                let handle = auth.session()?;
                used_auth_list.insert(handle);
            }
        }

        self.cache
            .teardown_sessions(device, &used_auth_list, &auth_responses)?;

        for handle in auth_handles {
            self.cache.untrack(handle.0);
        }

        Ok((resp, auth_responses))
    }

    /// Evicts a persistent object or makes a transient object persistent using `Job::execute`.
    ///
    /// # Errors
    ///
    /// Returns a [`JobError`] on authorization building or command execution failure.
    pub fn evict_control(
        &mut self,
        auth_handle: TpmHandle,
        object_to_evict: TpmHandle,
        persistent_handle: TpmHandle,
        auths: &[Auth],
    ) -> Result<(), JobError> {
        with_device(self.device.clone(), |device| {
            let cmd = TpmEvictControlCommand {
                auth: auth_handle,
                object_handle: object_to_evict.0.into(),
                persistent_handle,
            };
            let handles_for_session = [auth_handle.0];

            let (resp, _) = self.execute(device, &cmd, &handles_for_session, auths)?;

            resp.EvictControl()
                .map_err(|_| JobError::ResponseMismatch(TpmCc::EvictControl))?;
            Ok(())
        })
    }

    /// Imports an external key under a TPM parent, creating a new `TpmKey`.
    ///
    /// # Errors
    ///
    /// Returns a [`JobError`] if the TPM import operation fails.
    pub fn import_key(
        &mut self,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
    ) -> Result<TpmKey, JobError> {
        let external_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(_) => {
                return Err(JobError::InvalidFormat);
            }
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
    /// Returns a [`JobError`] if the TPM commands fail or if the response is invalid.
    pub fn read_certificate(
        &mut self,
        device: &mut Device,
        auths: &[Auth],
        handle: u32,
        max_read_size: usize,
    ) -> Result<Option<Vec<u8>>, JobError> {
        let nv_read_public_cmd = TpmNvReadPublicCommand {
            nv_index: handle.into(),
        };
        let (resp, _) = self.execute(device, &nv_read_public_cmd, &[], &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| JobError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size as usize;

        if data_size == 0 {
            return Ok(None);
        }

        let auth_handle_val = if nv_public.attributes.contains(TpmaNv::AUTHREAD) {
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
                auth_handle: auth_handle_val.into(),
                nv_index: handle.into(),
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
            };

            let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
            let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;

            let effective_auths: &[Auth] = if needs_auth { auths } else { &[] };

            let (resp, _) =
                self.execute(device, &nv_read_cmd, &[auth_handle_val], effective_auths)?;

            let read_resp = resp
                .NvRead()
                .map_err(|_| JobError::ResponseMismatch(TpmCc::NvRead))?;
            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += chunk_size;
        }

        Ok(Some(cert_bytes))
    }
}

impl Drop for Job<'_> {
    fn drop(&mut self) {
        self.cache.teardown(self.device.clone());
    }
}
