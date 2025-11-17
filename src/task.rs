//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    command::AuthArgs,
    device::{Device, DeviceError, RefreshAction, TpmCommandObject},
    write_object,
};
use hex;
use indicatif::ProgressBar;
use rand::{thread_rng, RngCore};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
    num::TryFromIntError,
    rc::Rc,
    time::Duration,
};
use thiserror::Error;
use tpm2_crypto::{tpm_make_name, Error as CryptoError, Hash};
use tpm2_policy_language::{TpmHandleClass, TpmHandleRef};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc,
        TpmHt, TpmRcBase, TpmRh, TpmSe, TpmaObject, TpmaSession, TpmsAuthCommand, TpmsContext,
        TpmtPublic, TpmtSymDefObject,
    },
    frame::{
        TpmAuthCommands, TpmAuthResponses, TpmCommand, TpmEvictControlCommand, TpmFrame,
        TpmResponse, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
    },
    TpmHandle, TpmSized, TpmUnmarshal,
};
use tpm2_tpmkey::TpmPolicyCommand;
use tpm2_vtpm::{VtpmCache, VtpmError};

type TpmCommandList = Vec<(TpmCommand, TpmAuthCommands)>;

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct TaskSession {
    pub context: TpmsContext,
    pub nonce_tpm: Tpm2bNonce,
    pub attributes: TpmaSession,
    pub hmac_key: Tpm2bAuth,
    pub auth_hash: TpmAlgId,
}

impl TaskSession {
    /// Creates a new session from a `StartAuthSession` response.
    ///
    /// # Errors
    ///
    /// Returns a [`TaskError`] if the hash algorithm is unsupported or if `KDFa` fails.
    pub fn new(auth_hash: TpmAlgId, resp: &TpmStartAuthSessionResponse) -> Result<Self, TaskError> {
        Ok(Self {
            context: TpmsContext {
                sequence: 0,
                saved_handle: resp.session_handle.0.into(),
                hierarchy: TpmRh::Null,
                context_blob: TpmBuffer::default(),
            },
            nonce_tpm: resp.nonce_tpm,
            attributes: TpmaSession::CONTINUE_SESSION,
            hmac_key: Tpm2bAuth::default(),
            auth_hash,
        })
    }

    /// Returns the VTPM handle.
    #[must_use]
    pub fn handle(&self) -> u32 {
        self.context.saved_handle.0
    }

    /// Deletes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when the TPM
    /// transmission fails.
    pub fn delete(&self, device: &mut Device) -> Result<(), TaskError> {
        let vhandle = self.handle();
        match device.flush_session(self.context.clone()) {
            Ok(()) => {}
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                log::debug!("vtpm session:{vhandle:08x} stale");
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Refreshes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when the TPM
    /// transmission fails.
    pub fn refresh(&mut self, device: &mut Device) -> Result<RefreshAction, TaskError> {
        let vhandle = self.handle();
        match device.load_context(self.context.clone()) {
            Ok(phandle) => match device.save_context(phandle) {
                Ok(context) => {
                    self.context = context;
                    match device.flush_context(phandle) {
                        Ok(()) => Ok(RefreshAction::Keep),
                        Err(e) => {
                            log::warn!("vtpm:{vhandle:08x}: {e}");
                            Ok(RefreshAction::Stale)
                        }
                    }
                }
                Err(e) => {
                    log::warn!("vtpm:{vhandle:08x}: {e}");
                    if let Err(e) = device.flush_context(phandle) {
                        log::warn!("vtpm:{vhandle:08x}: {e}");
                    }
                    if matches!(&e, DeviceError::TpmRc(rc) if rc.base() == TpmRcBase::ReferenceH0) {
                        Ok(RefreshAction::Stale)
                    } else {
                        Err(e.into())
                    }
                }
            },
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                Ok(RefreshAction::Stale)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Returns true if the object's attributes indicate policy-only authorization.
#[must_use]
pub fn is_empty_auth(public: &TpmtPublic) -> bool {
    public
        .object_attributes
        .contains(TpmaObject::ADMIN_WITH_POLICY)
        && !public
            .object_attributes
            .contains(TpmaObject::USER_WITH_AUTH)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAuth {
    Password(Vec<u8>),
    Session(u32),
    Policy(Vec<u8>),
}

impl Default for TaskAuth {
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

#[derive(Debug, Error)]
pub enum TaskError {
    #[error("handle already tracked: {0}")]
    HandleAlreadyTracked(TpmHandle),
    #[error("handle not found: {0}{1:08x}")]
    HandleNotFound(&'static str, u32),
    #[error("handle name not found: {}", hex::encode(.0.as_ref()))]
    HandleNameNotFound(Tpm2bName),
    #[error("invalid auth")]
    InvalidAuth,
    #[error("invalid key bits: {0}")]
    InvalidKeyBits(String),
    #[error("invalid parent: {0}{1:08x}")]
    InvalidParent(&'static str, u32),
    #[error("malformed data")]
    MalformedData,
    #[error("out of memory")]
    OutOfMemory,
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
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
}

pub struct TaskState<'a> {
    pub device: Option<Rc<RefCell<Device>>>,
    pub cache: VtpmCache<'a>,
    pub is_tty: bool,
    /// Holds all temporary sessions, indexed by their vhandle.
    pub sessions: HashMap<u32, TaskSession>,
    /// Holds all temporary physical handles (loaded keys + sessions) to be
    /// flushed on drop.
    pub physical_handles_to_flush: HashMap<u32, TpmHandle>,
}

impl<'a> TaskState<'a> {
    /// Creates a new `Session`.
    #[must_use]
    pub fn new(device: Option<Rc<RefCell<Device>>>, cache: VtpmCache<'a>, is_tty: bool) -> Self {
        Self {
            device,
            cache,
            is_tty,
            sessions: HashMap::new(),
            physical_handles_to_flush: HashMap::new(),
        }
    }

    /// Adds a session to the task's temporary state.
    pub fn add_session(&mut self, session: TaskSession) -> u32 {
        let vhandle = session.handle();
        self.sessions.insert(vhandle, session);
        vhandle
    }

    /// Gets an immutable reference to a session.
    #[must_use]
    pub fn get_session(&self, vhandle: u32) -> Option<&TaskSession> {
        self.sessions.get(&vhandle)
    }

    /// Gets a mutable reference to a session.
    pub fn get_mut_session(&mut self, vhandle: u32) -> Option<&mut TaskSession> {
        self.sessions.get_mut(&vhandle)
    }

    /// Removes a session from the task's state and flushes it from the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when the TPM
    /// transmission fails.
    /// Returns [`HandleNotFound`](crate::task::TaskError::HandleNotFound) if
    /// the session does not exist.
    pub fn remove_session(&mut self, device: &mut Device, vhandle: u32) -> Result<(), TaskError> {
        let session = self
            .sessions
            .remove(&vhandle)
            .ok_or(TaskError::HandleNotFound("vtpm:", vhandle))?;
        session.delete(device)
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`HandleAlreadyTracked`](crate::task::TaskError::HandleAlreadyTracked)
    /// if the handle is already being tracked.
    pub fn track_handle(&mut self, handle: TpmHandle) -> Result<(), TaskError> {
        if self.physical_handles_to_flush.contains_key(&handle.0) {
            return Err(TaskError::HandleAlreadyTracked(handle));
        }
        self.physical_handles_to_flush.insert(handle.0, handle);
        Ok(())
    }

    /// Removes a handle from the tracking list.
    pub fn untrack_handle(&mut self, handle: u32) {
        self.physical_handles_to_flush.remove(&handle);
    }

    /// Flushes all tracked transient handles from the TPM.
    fn flush_handles(&mut self, device: &mut Device) {
        let handles_to_flush: Vec<TpmHandle> = self
            .physical_handles_to_flush
            .drain()
            .map(|(_, v)| v)
            .collect();
        for handle in handles_to_flush {
            if let Err(err) = device.flush_context(handle) {
                log::error!("{handle}: {err}");
            }
        }
    }

    /// Prepares sessions by loading them into the TPM.
    ///
    /// # Errors
    ///
    /// Returns a [`TaskError`] if a session is not found or if loading its
    /// context fails.
    pub fn prepare_sessions(
        &mut self,
        device: &mut Device,
        auth_list: &[TaskAuth],
    ) -> Result<Vec<TpmHandle>, TaskError> {
        let mut activated_handles = Vec::new();
        for auth in auth_list {
            if let TaskAuth::Session(vhandle) = auth {
                let session = self
                    .get_session(*vhandle)
                    .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?;
                activated_handles.push(device.load_context(session.context.clone())?);
            }
        }
        Ok(activated_handles)
    }

    /// Tears down sessions by saving their updated contexts.
    ///
    /// # Errors
    ///
    /// Returns a [`TaskError`] if a session is not found or if saving/flushing
    /// the context fails.
    pub fn teardown_sessions(
        &mut self,
        device: &mut Device,
        session_vhandles: &HashSet<u32>,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), TaskError> {
        for (i, vhandle) in session_vhandles.iter().enumerate() {
            let session_handle = self
                .get_session(*vhandle)
                .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?
                .context
                .saved_handle;

            match device.save_context(session_handle) {
                Ok(new_context) => {
                    let session = self
                        .get_mut_session(*vhandle)
                        .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?;
                    session.context = new_context;
                    let auth = auth_responses[i];
                    session.nonce_tpm = auth.nonce;
                    session.attributes = auth.session_attributes;
                }
                Err(e) => {
                    if let Err(e) = device.flush_context(session_handle) {
                        log::warn!("{session_handle}: {e}");
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(())
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
        policy_auths: &mut std::slice::Iter<'_, TaskAuth>,
    ) -> Result<Option<TpmCommandList>, TaskError> {
        if policy_blob.is_empty() {
            return Ok(None);
        }
        let (count, mut remainder) = u32::unmarshal(policy_blob).map_err(TaskError::Unmarshal)?;
        let mut commands = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let (cc, rest) = TpmCc::unmarshal(remainder).map_err(TaskError::Unmarshal)?;
            remainder = rest;

            let (cmd, auth) = if cc == TpmCc::PolicySecret {
                let (handle_hint, rest) =
                    TpmHandle::unmarshal(remainder).map_err(TaskError::Unmarshal)?;
                let (object_name, rest) =
                    Tpm2bName::unmarshal(rest).map_err(TaskError::Unmarshal)?;
                let (policy_ref, rest) = tpm2_protocol::data::Tpm2bDigest::unmarshal(rest)
                    .map_err(TaskError::Unmarshal)?;
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

                let auth = match policy_auths.next().cloned().unwrap_or_default() {
                    TaskAuth::Password(val) => build_password_session(&val)?,
                    _ => return Err(TaskError::InvalidAuth),
                };

                let mut auths = TpmAuthCommands::new();
                auths.push(auth).map_err(|_| TaskError::OutOfMemory)?;
                (tpm_cmd, auths)
            } else {
                let (body_blob, rest) =
                    TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)
                        .map_err(TaskError::Unmarshal)?;
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
        policy_auths: &[TaskAuth],
    ) -> Result<Option<TaskAuth>, TaskError> {
        let mut auth_iter = policy_auths.iter();

        let Some(commands) = self.to_policy_command_list(device, policy_blob, &mut auth_iter)?
        else {
            return Ok(None);
        };

        if commands.is_empty() {
            return Ok(None);
        }

        let (resp, _) = TaskState::start_session(
            device,
            TpmSe::Policy,
            key_name_alg,
            (TpmRh::Null as u32).into(),
        )?;

        let temp_session = TaskSession::new(key_name_alg, &resp)?;
        let vhandle = self.add_session(temp_session);
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
                    .get_mut_session(vhandle)
                    .ok_or(TaskError::HandleNotFound("vtpm:", vhandle))?;
                session.context = new_context;
                Ok(Some(TaskAuth::Session(vhandle)))
            }
            Err(e) => {
                let _ = self.remove_session(device, vhandle);
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
    ) -> Result<(Vec<TaskAuth>, Option<TaskAuth>), TaskError> {
        let mut policy_session_auth: Option<TaskAuth> = None;
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

        let handles = device.fetch_handles((TpmHt::Persistent as u32) << 24)?;
        let mut persistent_keys = HashMap::new();
        for handle_ref in handles {
            if let Some(handle_val) = handle_ref.value() {
                let phandle = TpmHandle(handle_val);
                if let Ok((public, _)) = device.read_public(phandle) {
                    let key_bytes = write_object(&public).map_err(TaskError::Marshal)?;
                    persistent_keys.insert(key_bytes, phandle);
                }
            }
        }

        let chain = self
            .cache
            .fetch_ancestor_chain(target_vhandle, &persistent_keys)?;

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
                    self.track_handle(loaded_phandle)?;
                    phandle = Some(loaded_phandle);
                }
            }
        }

        for handle in chain_iter {
            let vhandle = handle.value().ok_or(TaskError::InvalidParent("vtpm:", 0))?;
            let key = self.cache.find_by_vhandle(vhandle)?;

            let parent_phandle = phandle.ok_or(TaskError::ParentNotFound)?;
            let loaded_phandle = device.load_context(key.context.clone())?;

            if device.read_public(parent_phandle)?.1 != tpm_make_name(&key.parent)? {
                self.untrack_handle(loaded_phandle.0);
                device.flush_context(loaded_phandle)?;
                return Err(TaskError::InvalidParent("vtpm:", vhandle));
            }

            self.track_handle(loaded_phandle)?;
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
        auth_list: &[TaskAuth],
    ) -> Result<Vec<TpmsAuthCommand>, TaskError> {
        let mut built_auths = Vec::new();
        let params = write_object(command).map_err(|_| TaskError::MalformedData)?;

        let mut nonce_decrypt: Option<Tpm2bNonce> = None;
        let mut nonce_encrypt: Option<Tpm2bNonce> = None;

        for auth in auth_list {
            if let TaskAuth::Session(vhandle) = auth {
                if let Some(session) = self.get_session(*vhandle) {
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

            let auth_cmd = match auth {
                TaskAuth::Session(vhandle) => {
                    let session = self
                        .get_session(*vhandle)
                        .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?;
                    let nonce_size = Hash::from(session.auth_hash).size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| TaskError::OutOfMemory)?;
                    let (current_nonce_decrypt, current_nonce_encrypt) = if i == 0 {
                        (nonce_decrypt.as_ref(), nonce_encrypt.as_ref())
                    } else {
                        (None, None)
                    };

                    create_auth(
                        device,
                        session,
                        &nonce_caller,
                        &[],
                        command.cc(),
                        &[*handle_param],
                        &params,
                        current_nonce_decrypt,
                        current_nonce_encrypt,
                    )?
                }
                TaskAuth::Password(password) => build_password_session(password)?,
                TaskAuth::Policy(_) => return Err(TaskError::InvalidAuth),
            };
            built_auths.push(auth_cmd);
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
        auth_list: &[TaskAuth],
    ) -> Result<(TpmResponse, TpmAuthResponses), TaskError> {
        let mut effective_auth_list: Vec<TaskAuth> = Vec::with_capacity(1);
        let virtual_handles: Vec<u32> = Vec::new();
        let physical_handles: Vec<TpmHandle> = Vec::new();

        if let Some(auth) = auth_list.first() {
            match auth {
                TaskAuth::Password(_) | TaskAuth::Session(_) => {
                    effective_auth_list.push(auth.clone());
                }
                TaskAuth::Policy(_) => {
                    return Err(TaskError::InvalidAuth);
                }
            }
        }

        let mut activated_handles = self.prepare_sessions(device, auth_list)?;
        activated_handles.extend(physical_handles);

        for &handle in &activated_handles {
            self.track_handle(handle)?;
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
                return Err(TaskError::Device(DeviceError::TpmRc(rc)));
            }
            Err(err) => {
                spinner.finish_and_clear();
                return Err(TaskError::Device(err));
            }
        };

        let mut used_auth_list = HashSet::new();
        for auth in &effective_auth_list {
            if let TaskAuth::Session(handle) = auth {
                used_auth_list.insert(*handle);
            }
        }

        self.teardown_sessions(device, &used_auth_list, &auth_responses)?;

        for handle in activated_handles {
            self.untrack_handle(handle.0);
        }

        for vhandle in virtual_handles {
            self.remove_session(device, vhandle)?;
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
        auth_list: &[TaskAuth],
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
        let nonce_caller =
            Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(|_| TaskError::OutOfMemory)?;

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

/// Creates an authorization command structure for an HMAC session.
///
/// # Errors
///
/// Returns a [`TaskError`] on cryptographic failures or if TPM data structures
/// cannot be serialized.
#[allow(clippy::too_many_arguments)]
fn create_auth(
    device: &mut Device,
    session: &TaskSession,
    nonce_caller: &Tpm2bNonce,
    auth_value: &[u8],
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
    nonce_decrypt: Option<&Tpm2bNonce>,
    nonce_encrypt: Option<&Tpm2bNonce>,
) -> Result<TpmsAuthCommand, TaskError> {
    let handle_names: Vec<Tpm2bName> = handles
        .iter()
        .map(|&handle| {
            let handle_type = (handle >> 24) as u8;
            if handle_type == TpmHt::Transient as u8 || handle_type == TpmHt::Persistent as u8 {
                device
                    .read_public(handle.into())
                    .map(|(_, name)| name)
                    .map_err(TaskError::Device)
            } else {
                let mut buf = [0u8; TpmHandle::SIZE];
                let mut pos = 0;
                handle.to_be_bytes().iter().for_each(|b| {
                    if pos < buf.len() {
                        buf[pos] = *b;
                        pos += 1;
                    }
                });
                let len = pos;

                if let Ok(name) = Tpm2bName::try_from(&buf[..len]) {
                    Ok(name)
                } else {
                    Err(TaskError::OutOfMemory)
                }
            }
        })
        .collect::<Result<_, TaskError>>()?;

    let command_code_bytes = (command_code as u32).to_be_bytes();

    let mut cp_hash_chunks: Vec<&[u8]> = Vec::with_capacity(2 + handle_names.len());
    cp_hash_chunks.push(&command_code_bytes);
    for name in &handle_names {
        cp_hash_chunks.push(name.as_ref());
    }
    cp_hash_chunks.push(parameters);

    let cp_hash = Hash::from(session.auth_hash).digest(&cp_hash_chunks)?;

    let hmac_bytes = if (session.context.saved_handle.0 >> 24) as u8 == TpmHt::HmacSession as u8 {
        let hmac_key = [session.hmac_key.as_ref(), auth_value].concat();
        if hmac_key.is_empty() {
            return Ok(TpmsAuthCommand {
                session_handle: session.context.saved_handle,
                nonce: *nonce_caller,
                session_attributes: session.attributes,
                hmac: Tpm2bAuth::default(),
            });
        }

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

        Hash::from(session.auth_hash).hmac(&hmac_key, &hmac_payload)?
    } else {
        Vec::new()
    };

    Ok(TpmsAuthCommand {
        session_handle: session.context.saved_handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::try_from(hmac_bytes.as_slice()).map_err(|_| TaskError::OutOfMemory)?,
    })
}

impl Drop for TaskState<'_> {
    fn drop(&mut self) {
        if let Some(device_rc) = self.device.clone() {
            if let Ok(mut dev) = device_rc.try_borrow_mut() {
                self.flush_handles(&mut dev);
                for session in self.sessions.values() {
                    if let Err(e) = session.delete(&mut dev) {
                        log::error!("vtpm:{:08x}: {e}", session.handle());
                    }
                }
            }
        }
        self.cache.teardown();
    }
}

fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, TaskError> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(|_| TaskError::OutOfMemory)?,
    })
}
