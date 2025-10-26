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

    /// Finds the ancestor chain for a given VTPM handle.
    ///
    /// Traverses up the parent hierarchy from the target `vhandle`, checking
    /// both the cache and persistent TPM handles, until it finds the root. The
    /// root can be a persistent physical handle or a non-persistent primary key
    /// stored in the VTPM cache.
    ///
    /// Returns a list of `(Handle, Auth)` pairs representing the path from the
    /// root *down* to the target, ready for loading. The first handle in the
    /// vector indicates the root type (`HandleClass::Tpm` or `HandleClass::Vtpm`).
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when the
    /// `target_vhandle` doesn't exist in the cache.
    /// Returns [`ParentNotFound`](crate::job::JobError::ParentNotFound) when an
    /// intermediate parent cannot be found in the cache or as a persistent
    /// handle.
    /// Returns [`TrailingAuthorizations`](crate::job::JobError::TrailingAuthorizations)
    /// when more `Auth` values are provided than needed for the ancestor chain.
    /// Returns [`Device`](crate::job::JobError::Device) when reading persistent
    /// handles fails.
    fn fetch_ancestor_chain(
        &self,
        target_vhandle: u32,
        device: &mut Device,
        auths: &[Auth],
    ) -> Result<Vec<(Handle, Auth)>, JobError> {
        let mut current_vhandle = target_vhandle;
        let mut vtp_chain: Vec<(Handle, Auth)> = Vec::new();
        let mut physical_primary: Option<Handle> = None;

        loop {
            let key = self.cache.find_by_vhandle(current_vhandle)?;

            if key.parent.inner.object_type == TpmAlgId::Null {
                break;
            }

            if let Some(parent_key) = self.cache.find_by_public(&key.parent.inner) {
                let parent_vhandle = parent_key.handle();
                let auth_index = vtp_chain.len();
                let auth = auths.get(auth_index).cloned().unwrap_or_default();
                vtp_chain.push((Handle((HandleClass::Vtpm, current_vhandle)), auth));
                current_vhandle = parent_vhandle;
            } else {
                match device.find_persistent(&key.parent.inner)? {
                    Some((phandle, _)) => {
                        physical_primary = Some(Handle((HandleClass::Tpm, phandle.0)));
                        break;
                    }
                    None => {
                        return Err(JobError::ParentNotFound);
                    }
                }
            }
        }

        let final_auth_index = vtp_chain.len();
        let final_auth = auths.get(final_auth_index).cloned().unwrap_or_default();
        vtp_chain.push((Handle((HandleClass::Vtpm, current_vhandle)), final_auth));

        if auths.len() > vtp_chain.len() {
            return Err(JobError::TrailingAuthorizations);
        }

        vtp_chain.reverse();

        if let Some(root_handle) = physical_primary {
            let mut final_chain = vec![(root_handle, Auth::default())];
            final_chain.extend(vtp_chain);
            Ok(final_chain)
        } else {
            Ok(vtp_chain)
        }
    }

    /// Loads a TPM context from a handle, recursively loading its ancestors
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when the
    /// target handle or any parent handle cannot be found, or if the chain is empty.
    /// Returns [`ParentNotFound`](crate::job::JobError::ParentNotFound) when a
    /// necessary parent handle isn't found in cache or persistent storage.
    /// Returns [`TrailingAuthorizations`](crate::job::JobError::TrailingAuthorizations)
    /// when more auth values are provided than necessary for the hierarchy.
    /// Returns [`Device`](crate::job::JobError::Device) or
    /// [`TpmProtocol`](crate::job::JobError::Device) when TPM commands fail.
    /// Returns [`ResponseMismatch`](crate::job::JobError::ResponseMismatch) when
    /// a TPM command returns an unexpected response type.
    /// Returns [`Vtpm`](crate::job::JobError::Vtpm) when tracking the loaded
    /// handle fails.
    /// Returns [`MalformedData`](crate::job::JobError::MalformedData) when an
    /// internal logic error occurs (e.g., trying to load under a None parent handle).
    pub fn load_context(
        &mut self,
        device: &mut Device,
        target: &Handle,
        auths: &[Auth],
    ) -> Result<TpmHandle, JobError> {
        if target.class() == HandleClass::Tpm {
            return Ok(TpmHandle(target.value()));
        }

        let target_vhandle = target.value();
        let chain = self.fetch_ancestor_chain(target_vhandle, device, auths)?;

        if chain.is_empty() {
            return Err(JobError::HandleNotFound("vtpm:", target_vhandle));
        }

        let mut phandle: Option<TpmHandle> = None;
        let mut chain_iter = chain.into_iter();

        if let Some((first_handle, _first_auth)) = chain_iter.next() {
            match first_handle.class() {
                HandleClass::Tpm => {
                    phandle = Some(TpmHandle(first_handle.value()));
                }
                HandleClass::Vtpm => {
                    let key = self.cache.find_by_vhandle(first_handle.value())?;
                    let loaded_phandle = device.load_context(key.context.clone())?;
                    self.cache.track(loaded_phandle)?;
                    phandle = Some(loaded_phandle);
                }
            }
        }

        for (handle, auth) in chain_iter {
            let vhandle = handle.value();
            let key = self.cache.find_by_vhandle(vhandle)?;

            let parent_phandle = phandle.ok_or(JobError::MalformedData)?;

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

            let loaded_phandle = resp.object_handle;
            self.cache.track(loaded_phandle)?;
            phandle = Some(loaded_phandle);
        }

        phandle.ok_or(JobError::HandleNotFound("vtpm:", target_vhandle))
    }

    /// Builds the authorization area for a command.
    ///
    /// # Errors
    ///
    /// Returns [`TrailingAuthorizations`](crate::job::JobError::TrailingAuthorizations)
    /// when more auth values are provided than handles requiring authorization.
    /// Returns [`InvalidAuth`](crate::job::JobError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when a
    /// session handle in `auth_list` is not found.
    /// Returns [`MalformedData`](crate::job::JobError::MalformedData) when the
    /// session's hash algorithm is unsupported.
    /// Returns [`Device`](crate::job::JobError::Device) when building TPM data
    /// structures fails or crypto operations fail.
    /// Returns [`Auth`](crate::job::JobError::Auth) when extracting a session
    /// handle fails.
    /// Returns [`Vtpm`](crate::job::JobError::Vtpm) when building a password
    /// session fails.
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
    /// Returns [`JobError`] if any stage of the session management or
    /// command execution fails. This includes errors from `prepare_sessions`,
    /// `build_auth_area`, `device.execute`, or `teardown_sessions`.
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
    /// Returns [`Device`](crate::job::JobError::Device) when the underlying
    /// `with_device` fails.
    /// Returns [`ResponseMismatch`](crate::job::JobError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    /// Returns [`JobError`] from the underlying `execute` call on failure.
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
    /// Returns [`InvalidFormat`](crate::job::JobError::InvalidFormat) when the
    /// input bytes represent a TPM key, not an external key.
    /// Returns [`Key`](crate::job::JobError::Key) when converting the external
    /// key or building the TPM key fails.
    /// Returns [`JobError`] from the underlying `TpmKey::from_external_key` call
    /// on failure.
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
    /// Returns [`ResponseMismatch`](crate::job::JobError::ResponseMismatch) when
    /// TPM commands return unexpected response types.
    /// Returns [`IntDecode`](crate::job::JobError::IntDecode) when converting
    /// chunk size or offset fails.
    /// Returns [`JobError`] from the underlying `execute` calls on failure.
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
