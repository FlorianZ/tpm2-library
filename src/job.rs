// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::{Auth, AuthClass, AuthError},
    crypto::{crypto_hash_size, crypto_make_name, CryptoError},
    device::{Device, DeviceError, TpmCommandObject},
    handle::{Handle, HandleClass},
    key::KeyError,
    vtpm::{build_password_session, create_auth, VtpmCache, VtpmContext, VtpmError, VtpmSession},
    write_object,
};
use rand::{thread_rng, RngCore};
use std::{cell::RefCell, collections::HashSet, io, io::Write, num::TryFromIntError, rc::Rc};
use thiserror::Error;
use tpm2_protocol::{
    data::{
        Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmCc, TpmRcBase, TpmRh, TpmSe, TpmaSession,
        TpmsAuthCommand, TpmtSymDefObject,
    },
    message::{
        TpmAuthResponses, TpmEvictControlCommand, TpmResponseBody, TpmStartAuthSessionCommand,
        TpmStartAuthSessionResponse,
    },
    TpmError, TpmHandle,
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
    /// Returns [`Device`](crate::job::JobError::Device) when the transmission
    /// fails.
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when the
    /// `target_vhandle` doesn't exist in the cache.
    /// Returns [`ParentNotFound`](crate::job::JobError::ParentNotFound) when an
    /// intermediate parent cannot be found in the cache or as a persistent
    /// handle.
    fn fetch_ancestor_chain(
        &self,
        target_vhandle: u32,
        device: &mut Device,
    ) -> Result<Vec<Handle>, JobError> {
        let mut current_vhandle = target_vhandle;
        let mut vtp_chain: Vec<Handle> = Vec::new();
        let mut physical_primary: Option<Handle> = None;

        loop {
            let key = self.cache.find_by_vhandle(current_vhandle)?;

            if key.parent.inner.object_type == TpmAlgId::Null {
                break;
            }

            if let Some(parent_key) = self.cache.find_by_public(&key.parent.inner) {
                let parent_vhandle = parent_key.handle();
                vtp_chain.push(Handle((HandleClass::Vtpm, current_vhandle)));
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

        vtp_chain.push(Handle((HandleClass::Vtpm, current_vhandle)));
        vtp_chain.reverse();

        if let Some(root_handle) = physical_primary {
            let mut final_chain = vec![root_handle];
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
    /// Returns [`Device`](crate::job::JobError::Device) when the transmission
    /// fails.
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when the
    /// target handle or any parent handle cannot be found, or if the chain is empty.
    /// Returns [`ParentNotFound`](crate::job::JobError::ParentNotFound) when a
    /// necessary parent handle isn't found in cache or persistent storage.
    /// Returns [`Vtpm`](crate::job::JobError::Vtpm) when tracking the loaded
    /// handle fails.
    /// Returns [`InvalidParent`](crate::job::JobError::InvalidParent) when
    /// loaded key's parent does not match the expected parent in the chain.
    pub fn load_context(
        &mut self,
        device: &mut Device,
        target: &Handle,
    ) -> Result<TpmHandle, JobError> {
        if target.class() == HandleClass::Tpm {
            return Ok(TpmHandle(target.value()));
        }

        let target_vhandle = target.value();
        let chain = self.fetch_ancestor_chain(target_vhandle, device)?;

        if chain.is_empty() {
            return Err(JobError::HandleNotFound("vtpm:", target_vhandle));
        }

        let mut phandle: Option<TpmHandle> = None;
        let mut chain_iter = chain.into_iter();

        if let Some(first_handle) = chain_iter.next() {
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

        for handle in chain_iter {
            let vhandle = handle.value();
            let key = self.cache.find_by_vhandle(vhandle)?;

            let parent_phandle = phandle.ok_or(JobError::ParentNotFound)?;
            let loaded_phandle = device.load_context(key.context.clone())?;

            if device.read_public(parent_phandle)?.1 != crypto_make_name(&key.parent.inner)? {
                self.cache.untrack(loaded_phandle.0);
                device.flush_context(loaded_phandle)?;
                return Err(JobError::InvalidParent("vtpm:", vhandle));
            }

            self.cache.track(loaded_phandle)?;
            phandle = Some(loaded_phandle);
        }

        phandle.ok_or(JobError::HandleNotFound("vtpm:", target_vhandle))
    }

    /// Builds the authorization area for a command.
    ///
    /// # Errors
    ///
    /// Returns [`Auth`](crate::job::JobError::Auth) when extracting a session
    /// handle fails.
    /// Returns [`HandleNotFound`](crate::job::JobError::HandleNotFound) when a
    /// session handle in `auth_list` is not found.
    /// Returns [`InvalidAuth`](crate::job::JobError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`MalformedData`](crate::job::JobError::MalformedData) when the
    /// session's hash algorithm is unsupported.
    /// Returns [`TrailingAuthorizations`](crate::job::JobError::TrailingAuthorizations)
    /// when more auth values are provided than handles requiring authorization.
    fn build_auth_area<C: TpmCommandObject>(
        &self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<Vec<TpmsAuthCommand>, JobError> {
        let mut built_auths = Vec::new();
        let params = write_object(command).map_err(|_| JobError::MalformedData)?;

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
                    let nonce_size = crypto_hash_size(session.auth_hash)?;
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
    /// # Errors
    ///
    /// Returns [`Auth`](crate::job::JobError::Auth) when extracting a session
    /// handle fails.
    /// Returns [`Device`](crate::job::JobError::Device) when the transmission
    /// fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), JobError> {
        let mut effective_auth_list: Vec<Auth> = Vec::with_capacity(auth_list.len());
        let mut vhandles: Vec<u32> = Vec::new();
        let mut phandles: Vec<TpmHandle> = Vec::new();

        for auth in auth_list {
            if *auth == Auth::default() {
                let (resp, nonce_caller) = Job::start_session(
                    device,
                    TpmSe::Hmac,
                    TpmAlgId::Sha256,
                    (TpmRh::Null as u32).into(),
                )?;
                let session = VtpmSession::new(TpmAlgId::Sha256, nonce_caller, &resp, &[])?;
                let vhandle = self.cache.add_session(session);

                vhandles.push(vhandle);
                phandles.push(resp.session_handle);
                effective_auth_list.push(Auth::new_session(vhandle)?);
            } else {
                effective_auth_list.push(auth.clone());
            }
        }

        let mut activated_handles = self.cache.prepare_sessions(device, auth_list)?;
        activated_handles.extend(phandles);

        for &handle in &activated_handles {
            self.cache.track(handle)?;
        }

        let sessions = self.build_auth_area(device, command, handles, &effective_auth_list)?;

        let (resp, auth_responses) = match device.execute(command, &sessions) {
            Ok((resp, auth_responses)) => (resp, auth_responses),
            Err(DeviceError::TpmRc(rc)) => {
                if rc.base() == TpmRcBase::PolicyFail {
                    for auth in auth_list {
                        if auth.class() == AuthClass::Session {
                            let vhandle = auth.session()?;
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            self.cache.remove(device, vhandle)?;
                        }
                    }
                }
                return Err(JobError::Device(DeviceError::TpmRc(rc)));
            }
            Err(err) => return Err(JobError::Device(err)),
        };

        let mut used_auth_list = HashSet::new();
        for auth in &effective_auth_list {
            if auth.class() == AuthClass::Session {
                let handle = auth.session()?;
                used_auth_list.insert(handle);
            }
        }

        self.cache
            .teardown_sessions(device, &used_auth_list, &auth_responses)?;

        for handle in activated_handles {
            self.cache.untrack(handle.0);
        }

        for vhandle in vhandles {
            self.cache.remove(device, vhandle)?;
        }

        Ok((resp, auth_responses))
    }

    /// Evicts a persistent object or makes a transient object persistent using `Job::execute`.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::job::JobError::Device) when the transmission
    /// fails.
    /// Returns [`ResponseMismatch`](crate::job::JobError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    pub fn evict_control(
        &mut self,
        device: &mut Device,
        object_to_evict: TpmHandle,
        persistent_handle: TpmHandle,
    ) -> Result<(), JobError> {
        let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
            (TpmRh::Owner as u32).into()
        } else {
            (TpmRh::Platform as u32).into()
        };

        let cmd = TpmEvictControlCommand {
            auth: auth_handle,
            object_handle: object_to_evict.0.into(),
            persistent_handle,
        };
        let handles_for_session = [auth_handle.0];

        let (resp, _) = self.execute(device, &cmd, &handles_for_session, self.auth_list)?;

        resp.EvictControl()
            .map_err(|_| JobError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    /// Starts a new authorization session.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::job::JobError::Device) when the transmission
    /// fails.
    /// Returns [`ResponseMismatch`](crate::job::JobError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    pub fn start_session(
        device: &mut Device,
        session_type: TpmSe,
        auth_hash: TpmAlgId,
        bind: TpmHandle,
    ) -> Result<(TpmStartAuthSessionResponse, Tpm2bNonce), JobError> {
        let digest_len = crypto_hash_size(auth_hash)?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind,
            nonce_caller,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: TpmtSymDefObject::default(),
            auth_hash,
        };
        let sessions = vec![];

        let (response_body, _) = device.execute(&cmd, &sessions)?;

        let resp = response_body
            .StartAuthSession()
            .map_err(|_| JobError::ResponseMismatch(TpmCc::StartAuthSession))?;

        Ok((resp, nonce_caller))
    }
}

impl Drop for Job<'_> {
    fn drop(&mut self) {
        self.cache.teardown(self.device.clone());
    }
}
