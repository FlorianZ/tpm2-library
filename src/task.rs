//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    command::AuthArgs,
    device::{Device, DeviceError, TpmCommandObject},
    vtpm::{build_password_session, create_auth, VtpmCache, VtpmError, VtpmSession},
    write_object,
};
use hex;
use indicatif::ProgressBar;
use rand::{thread_rng, RngCore};
use std::{
    cell::RefCell, collections::HashSet, io, io::Write, num::TryFromIntError, rc::Rc,
    time::Duration,
};
use thiserror::Error;
use tpm2_crypto::{tpm_make_name, Error as CryptoError, Hash};
use tpm2_policy_language::{TpmHandleClass, TpmHandleRef};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmRcBase,
        TpmRh, TpmSe, TpmaSession, TpmsAuthCommand, TpmtSymDefObject,
    },
    frame::{
        TpmAuthCommands, TpmAuthResponses, TpmCommand, TpmEvictControlCommand, TpmFrame,
        TpmResponse, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
    },
    TpmHandle, TpmSized, TpmUnmarshal,
};
use tpm2_tpmkey::TpmPolicyCommand;

type TpmCommandList = Vec<(TpmCommand, TpmAuthCommands)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Session(u32),
    Policy(Vec<u8>),
}

impl Default for Auth {
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

#[derive(Debug, Error)]
pub enum TaskError {
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("handle not found: {0}{1:08x}")]
    HandleNotFound(&'static str, u32),
    #[error("handle name not found: {}", hex::encode(.0.as_ref()))]
    HandleNameNotFound(Tpm2bName),
    #[error("invalid auth: only password auths are supported in policies")]
    InvalidAuth,
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
    Key(#[from] AlgError),
    #[error("cache: {0}")]
    Vtpm(#[from] VtpmError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("auth error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
}

pub struct TaskState<'a> {
    pub device: Option<Rc<RefCell<Device>>>,
    pub cache: &'a mut VtpmCache<'a>,
    pub writer: &'a mut dyn Write,
    pub is_tty: bool,
}

impl<'a> TaskState<'a> {
    /// Creates a new `Session`.
    #[must_use]
    pub fn new(
        device: Option<Rc<RefCell<Device>>>,
        cache: &'a mut VtpmCache<'a>,
        writer: &'a mut dyn Write,
        is_tty: bool,
    ) -> Self {
        Self {
            device,
            cache,
            writer,
            is_tty,
        }
    }

    /// Resolves a `Tpm2bName` from a `PolicySecret` to a live `TpmHandle`.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when a cache operation fails.
    /// Returns [`HandleNameNotFound`](crate::TaskError::HandleNameNotFound) when
    /// the name cannot be found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when the
    /// `TpmHandleRef` is invalid.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a VTPM
    /// handle is not in the cache.
    /// Returns [`ParentNotFound`](crate::TaskError::ParentNotFound) when a
    /// parent handle is not found.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    pub fn fetch_handle_by_name(
        &mut self,
        device: &mut Device,
        name: &Tpm2bName,
    ) -> Result<TpmHandle, TaskError> {
        if let Some(handle) = device.find_persistent_by_name(name)? {
            return Ok(handle);
        }

        if let Some(key) = self.cache.find_by_name(name)? {
            let vhandle = key.handle.0;
            return self.load_context(device, &TpmHandleRef::new(TpmHandleClass::Vtpm, vhandle));
        }

        Err(TaskError::HandleNameNotFound(*name))
    }

    /// Converts the custom binary cache format into a "live" `TpmCommandList`.
    ///
    /// This performs "JIT resolution" for `PolicySecret`, converting the stored
    /// `Tpm2bName` into a live `TpmHandle`.
    ///
    /// # Errors
    ///
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when parsing the policy blob
    /// fails.
    /// Returns [`Key`](crate::TaskError::Key) when parsing a policy command
    /// fails.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when an
    /// auth list is too large.
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    /// Returns [`HandleNameNotFound`](crate::TaskError::HandleNameNotFound) when
    /// a policy secret handle cannot be found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a
    /// `TpmHandleRef` is invalid.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a VTPM
    /// handle is not in the cache.
    /// Returns [`ParentNotFound`](crate::TaskError::ParentNotFound) when a
    /// parent handle is not found.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    pub fn to_policy_command_list(
        &mut self,
        device: &mut Device,
        policy_blob: &[u8],
        policy_auths: &mut std::slice::Iter<'_, Vec<u8>>,
    ) -> Result<Option<TpmCommandList>, TaskError> {
        if policy_blob.is_empty() {
            return Ok(None);
        }
        let (count, mut remainder) =
            u32::unmarshal(policy_blob).map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
        let mut commands = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let (cc, rest) =
                TpmCc::unmarshal(remainder).map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
            remainder = rest;

            let (cmd, auth) = if cc == TpmCc::PolicySecret {
                let (handle_hint, rest) = TpmHandle::unmarshal(remainder)
                    .map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
                let (object_name, rest) = Tpm2bName::unmarshal(rest)
                    .map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
                let (policy_ref, rest) = tpm2_protocol::data::Tpm2bDigest::unmarshal(rest)
                    .map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
                remainder = rest;

                let live_handle = if object_name.is_empty() {
                    log::warn!(
                        "PolicySecret uses handle hint {:08x} but has no object name. Policy may fail.",
                        handle_hint.0
                    );
                    handle_hint
                } else {
                    self.fetch_handle_by_name(device, &object_name)?
                };

                let tpm_cmd =
                    TpmCommand::PolicySecret(tpm2_protocol::frame::TpmPolicySecretCommand {
                        auth_handle: live_handle,
                        policy_session: TpmHandle(0),
                        nonce_tpm: Tpm2bNonce::default(),
                        cp_hash_a: Tpm2bDigest::default(),
                        policy_ref,
                        expiration: 0,
                    });

                let auth = policy_auths.next().cloned().unwrap_or_default();
                let auth_cmd = build_password_session(&auth)?;

                let mut auths = TpmAuthCommands::new();
                auths
                    .push(auth_cmd)
                    .map_err(|_| TaskError::CapacityExceeded)?;
                (tpm_cmd, auths)
            } else {
                let (body_blob, rest) =
                    TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)
                        .map_err(|e| TaskError::Vtpm(VtpmError::Protocol(e)))?;
                remainder = rest;

                let policy_cmd = TpmPolicyCommand::from_raw(cc, body_blob.to_vec())
                    .map_err(|e| TaskError::Key(AlgError::TpmKey(e)))?;
                policy_cmd
                    .to_command()
                    .map_err(|e| TaskError::Key(AlgError::TpmKey(e)))?
            };
            commands.push((cmd, auth));
        }
        Ok(Some(commands))
    }

    /// Creates and executes a policy session from a key's embedded policy blobs.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a
    /// non-password auth is provided.
    /// Returns [`MalformedData`](crate::TaskError::MalformedData) when an
    /// unsupported policy command is found.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when the
    /// temporary session handle is lost.
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when session creation, saving, or
    /// parsing fails.
    /// Returns [`Key`](crate::TaskError::Key) when parsing a policy command
    /// fails.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when an
    /// auth list is too large.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    /// Returns [`HandleNameNotFound`](crate::TaskError::HandleNameNotFound) when
    /// a policy secret handle cannot be found.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    /// Returns [`ParentNotFound`](crate::TaskError::ParentNotFound) when a
    /// parent handle is not found.
    pub fn build_policy_session(
        &mut self,
        device: &mut Device,
        policy_blob: &[u8],
        key_name_alg: TpmAlgId,
        policy_auths: &[Auth],
    ) -> Result<Option<Auth>, TaskError> {
        let mut raw_auths = Vec::new();
        for auth in policy_auths {
            if let Auth::Password(p) = auth {
                raw_auths.push(p.clone());
            } else {
                return Err(TaskError::InvalidAuth);
            }
        }
        let mut auth_iter = raw_auths.iter();

        let Some(commands) = self.to_policy_command_list(device, policy_blob, &mut auth_iter)?
        else {
            return Ok(None);
        };

        if commands.is_empty() {
            return Ok(None);
        }

        let (resp, nonce_caller) = TaskState::start_session(
            device,
            TpmSe::Policy,
            key_name_alg,
            (TpmRh::Null as u32).into(),
        )?;

        let temp_session = VtpmSession::new(key_name_alg, nonce_caller, &resp, &[])?;
        let vhandle = self.cache.add_session(temp_session);
        let policy_phandle = resp.session_handle;

        let execution_result: Result<(), TaskError> = (|| {
            for (command_body, auth_sessions) in commands {
                let mut command_body = command_body.clone();

                match &mut command_body {
                    TpmCommand::PolicyPcr(cmd) => cmd.policy_session = policy_phandle.0.into(),
                    TpmCommand::PolicyOr(cmd) => cmd.policy_session = policy_phandle.0.into(),
                    TpmCommand::PolicyRestart(cmd) => {
                        cmd.session_handle = policy_phandle.0.into();
                    }
                    TpmCommand::PolicySecret(cmd) => {
                        cmd.policy_session = policy_phandle.0.into();
                    }
                    _ => {
                        return Err(TaskError::MalformedData);
                    }
                }
                device.transmit(&command_body, auth_sessions.as_ref())?;
            }
            Ok(())
        })();

        match execution_result {
            Ok(()) => {
                let new_context = device.save_context(policy_phandle)?;
                let session = self
                    .cache
                    .get_mut_session(vhandle)
                    .ok_or(TaskError::HandleNotFound("vtpm:", vhandle))?;
                session.context = new_context;
                self.cache.save()?;
                Ok(Some(Auth::Session(vhandle)))
            }
            Err(e) => {
                let _ = self.cache.remove(device, vhandle);
                Err(e)
            }
        }
    }

    /// Prepares the final authorization vector for a command.
    ///
    /// This function contains the common logic to split user authentication,
    /// build policy sessions if needed, and return the final `auths` vector
    /// and the temporary `policy_session_auth` for cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a
    /// non-password auth is provided.
    /// Returns [`MalformedData`](crate::TaskError::MalformedData) when an
    /// unsupported policy command is found.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a
    /// temporary session handle is lost.
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when session creation, saving, or
    /// parsing fails.
    /// Returns [`Key`](crate::TaskError::Key) when parsing a policy command
    /// fails.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when an
    /// auth list is too large.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    /// Returns [`HandleNameNotFound`](crate::TaskError::HandleNameNotFound) when
    /// a policy secret handle cannot be found.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    /// Returns [`ParentNotFound`](crate::TaskError::ParentNotFound) when a
    /// parent handle is not found.
    pub fn build_auth(
        &mut self,
        device: &mut Device,
        policy_blob: &[u8],
        name_alg: TpmAlgId,
        empty_auth: bool,
        auth_args: &AuthArgs,
    ) -> Result<(Vec<Auth>, Option<Auth>), TaskError> {
        let mut policy_session_auth: Option<Auth> = None;
        let all_auths = auth_args.auths(empty_auth);
        let (cmd_auths, policy_auths) = if empty_auth {
            (Vec::new(), all_auths.as_ref())
        } else {
            (
                vec![all_auths.first().cloned().unwrap_or_default()],
                all_auths.get(1..).unwrap_or_default(),
            )
        };

        let mut auths = cmd_auths;

        if !policy_blob.is_empty() {
            if let Some(session_auth) =
                self.build_policy_session(device, policy_blob, name_alg, policy_auths)?
            {
                auths = vec![session_auth.clone()];
                policy_session_auth = Some(session_auth);
            }
        }

        Ok((auths, policy_session_auth))
    }

    /// Loads a TPM context from a handle, recursively loading its ancestors
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when the
    /// target handle or a parent handle cannot be found.
    /// Returns [`ParentNotFound`](crate::TaskError::ParentNotFound) when a
    /// necessary parent handle isn't found in cache or persistent storage.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when tracking the loaded
    /// handle fails.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when a
    /// loaded key's parent does not match the expected parent in the chain.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when the target
    /// `TpmHandleRef` is invalid.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    pub fn load_context(
        &mut self,
        device: &mut Device,
        target: &TpmHandleRef,
    ) -> Result<TpmHandle, TaskError> {
        let target_vhandle = target.value().ok_or(TaskError::InvalidAuth)?;

        if target.class() == TpmHandleClass::Tpm {
            return Ok(TpmHandle(target_vhandle));
        }

        let chain = self.cache.fetch_ancestor_chain(target_vhandle, device)?;

        if chain.is_empty() {
            return Err(TaskError::HandleNotFound("vtpm:", target_vhandle));
        }

        let mut phandle: Option<TpmHandle> = None;
        let mut chain_iter = chain.into_iter();

        if let Some(first_handle) = chain_iter.next() {
            let first_handle_val = first_handle
                .value()
                .ok_or(TaskError::InvalidParent("vtpm:", 0))?;
            match first_handle.class() {
                TpmHandleClass::Tpm => {
                    phandle = Some(TpmHandle(first_handle_val));
                }
                TpmHandleClass::Vtpm => {
                    let key = self.cache.find_by_vhandle(first_handle_val)?;
                    let loaded_phandle = device.load_context(key.context.clone())?;
                    self.cache.track(loaded_phandle)?;
                    phandle = Some(loaded_phandle);
                }
            }
        }

        for handle in chain_iter {
            let vhandle = handle.value().ok_or(TaskError::InvalidParent("vtpm:", 0))?;
            let key = self.cache.find_by_vhandle(vhandle)?;

            let parent_phandle = phandle.ok_or(TaskError::ParentNotFound)?;
            let loaded_phandle = device.load_context(key.context.clone())?;

            if device.read_public(parent_phandle)?.1 != tpm_make_name(&key.parent.inner)? {
                self.cache.untrack(loaded_phandle.0);
                device.flush_context(loaded_phandle)?;
                return Err(TaskError::InvalidParent("vtpm:", vhandle));
            }

            self.cache.track(loaded_phandle)?;
            phandle = Some(loaded_phandle);
        }

        phandle.ok_or(TaskError::HandleNotFound("vtpm:", target_vhandle))
    }

    /// Builds the authorization area for a command.
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a
    /// session handle in `auth_list` is not found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`MalformedData`](crate::TaskError::MalformedData) when
    /// serializing the command fails.
    /// Returns [`TrailingAuthorizations`](crate::TaskError::TrailingAuthorizations)
    /// when more auth values are provided than handles requiring authorization.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when
    /// an auth struct is too large.
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when an auth calculation
    /// fails.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when a cache operation fails.
    fn build_auth_area<C: TpmFrame>(
        &self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<Vec<TpmsAuthCommand>, TaskError> {
        let mut built_auths = Vec::new();
        let params = write_object(command).map_err(|_| TaskError::MalformedData)?;

        let mut nonce_decrypt: Option<Tpm2bNonce> = None;
        let mut nonce_encrypt: Option<Tpm2bNonce> = None;

        for auth in auth_list {
            if let Auth::Session(vhandle) = auth {
                if let Some(session) = self.cache.get_session(*vhandle) {
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
            let handle_param = handles.get(i).ok_or(TaskError::TrailingAuthorizations)?;

            match auth {
                Auth::Password(value) => {
                    built_auths.push(build_password_session(value)?);
                }
                Auth::Session(vhandle) => {
                    let session = self
                        .cache
                        .get_session(*vhandle)
                        .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?;
                    let nonce_size = Hash::from(session.auth_hash).size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| TaskError::CapacityExceeded)?;
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
                        command.cc(),
                        &[*handle_param],
                        &params,
                        current_nonce_decrypt,
                        current_nonce_encrypt,
                    )?;
                    built_auths.push(result);
                }
                Auth::Policy(_) => return Err(TaskError::InvalidAuth),
            }
        }
        Ok(built_auths)
    }

    /// Executes a TPM command with full authorization session handling.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when the transmission
    /// fails or the TPM returns an error.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when a session operation fails.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a
    /// session handle is not found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`MalformedData`](crate::TaskError::MalformedData) when
    /// serializing the command fails.
    /// Returns [`TrailingAuthorizations`](crate::TaskError::TrailingAuthorizations)
    /// when more auth values are provided than handles.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when
    /// an auth struct is too large.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when an auth calculation
    /// fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<(TpmResponse, TpmAuthResponses), TaskError> {
        let mut effective_auth_list: Vec<Auth> = Vec::with_capacity(auth_list.len());
        let mut vhandles: Vec<u32> = Vec::new();
        let mut phandles: Vec<TpmHandle> = Vec::new();

        for auth in auth_list {
            if *auth == Auth::default() {
                let (resp, nonce_caller) = TaskState::start_session(
                    device,
                    TpmSe::Hmac,
                    TpmAlgId::Sha256,
                    (TpmRh::Null as u32).into(),
                )?;
                let session = VtpmSession::new(TpmAlgId::Sha256, nonce_caller, &resp, &[])?;
                let vhandle = self.cache.add_session(session);

                vhandles.push(vhandle);
                phandles.push(resp.session_handle);
                effective_auth_list.push(Auth::Session(vhandle));
            } else {
                effective_auth_list.push(auth.clone());
            }
        }

        let mut activated_handles = self.cache.prepare_sessions(device, auth_list)?;
        activated_handles.extend(phandles);

        for &handle in &activated_handles {
            self.cache.track(handle)?;
        }

        let spinner = ProgressBar::new_spinner();
        spinner.set_message("Waiting for TPM...");
        spinner.enable_steady_tick(Duration::from_millis(100));

        let sessions = self.build_auth_area(device, command, handles, &effective_auth_list)?;

        let (resp, auth_responses) = match device.transmit(command, &sessions) {
            Ok((resp, auth_responses)) => {
                spinner.finish_and_clear();
                (resp, auth_responses)
            }
            Err(DeviceError::TpmRc(rc)) => {
                spinner.finish_and_clear();
                if rc.base() == TpmRcBase::PolicyFail {
                    for auth in auth_list {
                        if let Auth::Session(vhandle) = auth {
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            self.cache.remove(device, *vhandle)?;
                        }
                    }
                }
                return Err(TaskError::Device(DeviceError::TpmRc(rc)));
            }
            Err(err) => {
                spinner.finish_and_clear();
                return Err(TaskError::Device(err));
            }
        };

        let mut used_auth_list = HashSet::new();
        for auth in &effective_auth_list {
            if let Auth::Session(handle) = auth {
                used_auth_list.insert(*handle);
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

    /// Evicts a persistent object or makes a transient object persistent using `Session::execute`.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when the transmission
    /// fails.
    /// Returns [`ResponseMismatch`](crate::TaskError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when a session operation fails.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a
    /// session handle is not found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`MalformedData`](crate::TaskError::MalformedData) when
    /// serializing the command fails.
    /// Returns [`TrailingAuthorizations`](crate::TaskError::TrailingAuthorizations)
    /// when more auth values are provided than handles.
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when
    /// an auth struct is too large.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when an auth calculation
    /// fails.
    pub fn evict_control(
        &mut self,
        device: &mut Device,
        object_to_evict: TpmHandle,
        persistent_handle: TpmHandle,
        auth_list: &[Auth],
    ) -> Result<(), TaskError> {
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

        let (resp, _) = self.execute(device, &cmd, &handles_for_session, auth_list)?;

        resp.EvictControl()
            .map_err(|_| TaskError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    /// Starts a new authorization session.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when the transmission
    /// fails.
    /// Returns [`ResponseMismatch`](crate::TaskError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when `Tpm2bNonce` conversion
    /// fails.
    pub fn start_session(
        device: &mut Device,
        session_type: TpmSe,
        auth_hash: TpmAlgId,
        bind: TpmHandle,
    ) -> Result<(TpmStartAuthSessionResponse, Tpm2bNonce), TaskError> {
        let digest_len = Hash::from(auth_hash).size();
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| VtpmError::CapacityExceeded)?;

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

        let (response_body, _) = device.transmit(&cmd, &sessions)?;

        let resp = response_body
            .StartAuthSession()
            .map_err(|_| TaskError::ResponseMismatch(TpmCc::StartAuthSession))?;

        Ok((resp, nonce_caller))
    }
}

impl Drop for TaskState<'_> {
    fn drop(&mut self) {
        self.cache.teardown(self.device.clone());
    }
}
