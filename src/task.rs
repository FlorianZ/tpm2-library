// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::command::AuthArgs;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
    num::TryFromIntError,
    rc::Rc,
};

use hex;
use rand::{thread_rng, RngCore};
use thiserror::Error;
use tpm2_crypto::{tpm_make_name, TpmCryptoError, TpmHash};
use tpm2_device::{TpmDevice, TpmDeviceError};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc,
        TpmRh, TpmSe, TpmaObject, TpmaSession, TpmsAuthCommand, TpmtPublic, TpmtSymDefObject,
    },
    frame::{
        TpmAuthCommands, TpmAuthResponses, TpmCommand, TpmEvictControlCommand, TpmFrame,
        TpmResponse, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
    },
    TpmHandle, TpmUnmarshal,
};
use tpm2_vtpm::{
    VtpmCache, VtpmError, VtpmHandle, VtpmHandleClass, VtpmPolicyCommand, VtpmPolicySecretCommand,
};

type TpmCommandList = Vec<(TpmCommand, TpmAuthCommands)>;

/// Interface for reporting progress of long-running TPM operations.
pub trait TaskStateProgress {
    fn start(&self);
    fn stop(&self);
}

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct TaskSession {
    pub handle: TpmHandle,
    pub attributes: TpmaSession,
    pub hash_alg: TpmAlgId,
}

impl TaskSession {
    /// Creates a new session from a `StartAuthSession` response.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] if the hash algorithm is unsupported or if `KDFa` fails.
    pub fn new(hash_alg: TpmAlgId, handle: TpmHandle) -> Result<Self, TaskError> {
        Ok(Self {
            handle,
            attributes: TpmaSession::CONTINUE_SESSION,
            hash_alg,
        })
    }

    /// Returns the VTPM handle.
    #[must_use]
    pub fn handle(&self) -> TpmHandle {
        self.handle
    }

    /// Deletes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when the TPM
    /// transmission fails.
    pub fn delete(&self, device: &mut TpmDevice) -> Result<(), TaskError> {
        device.flush_context(self.handle).map_err(TaskError::Device)
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
    #[error("invalid parent: {0}{1:08x}")]
    InvalidParent(&'static str, u32),
    #[error("malformed data")]
    MalformedData,
    #[error("out of memory")]
    OutOfMemory,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("cache: {0}")]
    Vtpm(#[from] VtpmError),
    #[error("device: {0}")]
    Device(#[from] TpmDeviceError),
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
}

pub struct TaskState<'a> {
    pub device: Option<Rc<RefCell<TpmDevice>>>,
    pub cache: VtpmCache<'a>,
    pub progress: Option<Box<dyn TaskStateProgress>>,
    /// Holds all temporary sessions, indexed by their vhandle.
    pub sessions: HashMap<TpmHandle, TaskSession>,
    /// Live handles (virtual handle -> physical handle).
    pub live_handles: HashMap<u32, TpmHandle>,
    /// All tracked handles (physical) for cleanup.
    pub tracked_handles: HashSet<TpmHandle>,
}

impl<'a> TaskState<'a> {
    /// Creates a new `Session`.
    #[must_use]
    pub fn new(
        device: Option<Rc<RefCell<TpmDevice>>>,
        cache: VtpmCache<'a>,
        progress: Option<Box<dyn TaskStateProgress>>,
    ) -> Self {
        Self {
            device,
            cache,
            progress,
            sessions: HashMap::new(),
            live_handles: HashMap::new(),
            tracked_handles: HashSet::new(),
        }
    }

    /// Removes a session from the task's state and flushes it from the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when the TPM
    /// transmission fails.
    /// Returns [`HandleNotFound`](crate::task::TaskError::HandleNotFound) if
    /// the session does not exist.
    pub fn remove_session(
        &mut self,
        device: &mut TpmDevice,
        vhandle: TpmHandle,
    ) -> Result<(), TaskError> {
        let session = self
            .sessions
            .remove(&vhandle)
            .ok_or(TaskError::HandleNotFound("tpm:", vhandle.0))?;
        session.delete(device)
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`HandleAlreadyTracked`](crate::task::TaskError::HandleAlreadyTracked)
    /// if the handle is already being tracked.
    pub fn track(&mut self, handle: TpmHandle) -> Result<(), TaskError> {
        if self.tracked_handles.contains(&handle) {
            return Err(TaskError::HandleAlreadyTracked(handle));
        }
        self.tracked_handles.insert(handle);
        Ok(())
    }

    /// Removes a handle from the live handle tracking list.
    pub fn untrack(&mut self, handle: TpmHandle) {
        self.tracked_handles.remove(&handle);
        self.live_handles.retain(|_, v| *v != handle);
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
    #[allow(clippy::type_complexity)]
    pub fn build_auth(
        &mut self,
        device: &mut TpmDevice,
        handle: &VtpmHandle,
        auth_args: &AuthArgs,
    ) -> Result<(TpmHandle, TpmAlgId, Vec<TaskAuth>, Option<TaskAuth>), TaskError> {
        let (phys_handle, policy, name_alg, empty_auth) = self.fetch_policy(device, handle)?;

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

        if !policy.is_empty() {
            if let Some(session_auth) =
                self.start_policy_session(device, &policy, name_alg, policy_auths)?
            {
                auths = vec![session_auth.clone()];
                policy_session_auth = Some(session_auth);
            }
        }

        Ok((phys_handle, name_alg, auths, policy_session_auth))
    }

    /// Loads a TPM context from a handle, recursively loading its ancestors
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::task::TaskError::Device) when a TPM command
    /// fails.
    /// Returns [`HandleNotFound`](crate::task::TaskError::HandleNotFound) when
    /// the target handle or a parent handle cannot be found.
    /// Returns [`Vtpm`](crate::task::TaskError::Vtpm) when tracking the loaded
    /// handle fails.
    /// Returns [`InvalidParent`](crate::task::TaskError::InvalidParent) when a
    /// loaded key's parent does not match the expected parent in the chain.
    /// Returns [`InvalidAuth`](crate::task::TaskError::InvalidAuth) when the
    /// target `VtpmHandle` is invalid.
    /// Returns [`Crypto`](crate::task::TaskError::Crypto) when name calculation
    /// fails.
    /// Returns [`Marshal`](crate::task::TaskError::Marshal) when marshaling
    /// fails during persistent key lookup.
    /// Returns
    /// [`HandleAlreadyTracked`](crate::task::TaskError::HandleAlreadyTracked)
    /// if a loaded handle
    /// is already being tracked.
    pub fn load_key(
        &mut self,
        device: &mut TpmDevice,
        target: &VtpmHandle,
    ) -> Result<TpmHandle, TaskError> {
        let target_vhandle = target.value().ok_or(TaskError::InvalidAuth)?;

        if target.class() == VtpmHandleClass::Tpm {
            return Ok(TpmHandle(target_vhandle));
        }

        if let Some(&phandle) = self.live_handles.get(&target_vhandle) {
            return Ok(phandle);
        }

        let chain = self.cache.fetch_ancestor_chain(TpmHandle(target_vhandle))?;

        if chain.is_empty() {
            return Err(TaskError::HandleNotFound("vtpm:", target_vhandle));
        }

        let mut chain_iter = chain.into_iter();

        let first_handle = chain_iter
            .next()
            .ok_or(TaskError::HandleNotFound("vtpm:", target_vhandle))?;
        let mut phandle = self.load_chain_root(device, &first_handle)?;

        for handle in chain_iter {
            let vhandle = handle.value().ok_or(TaskError::InvalidParent("vtpm:", 0))?;

            if let Some(&live_h) = self.live_handles.get(&vhandle) {
                phandle = live_h;
                continue;
            }

            let key = self.cache.find_by_virtual_handle(TpmHandle(vhandle))?;

            let loaded_phandle = device.load_context(key.context.clone())?;

            if device.read_public(phandle)?.1 != tpm_make_name(&key.parent)? {
                self.untrack(loaded_phandle);
                device.flush_context(loaded_phandle)?;
                return Err(TaskError::InvalidParent("vtpm:", vhandle));
            }

            self.track(loaded_phandle)?;
            self.live_handles.insert(vhandle, loaded_phandle);
            phandle = loaded_phandle;
        }

        Ok(phandle)
    }

    /// Loads a TPM context from a `Tpm2bName`, recursively loading its ancestors first
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::TaskError::Device) when a TPM command fails.
    /// Returns [`Crypto`](crate::TaskError::Crypto) when name calculation fails.
    /// Returns [`Vtpm`](crate::TaskError::Vtpm) when a cache operation fails.
    /// Returns [`HandleNameNotFound`](crate::TaskError::HandleNameNotFound) when
    /// the name cannot be found.
    /// Returns [`InvalidAuth`](crate::TaskError::InvalidAuth) when the
    /// `VtpmHandle` is invalid.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a VTPM
    /// handle is not in the cache.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    pub fn load_key_by_name(
        &mut self,
        device: &mut TpmDevice,
        name: &Tpm2bName,
    ) -> Result<TpmHandle, TaskError> {
        if let Some(handle) = device.find_persistent(name)? {
            return Ok(handle);
        }

        if let Some(key) = self.cache.find_by_name(name)? {
            let vhandle = key.handle.0;
            return self.load_key(device, &VtpmHandle::new(VtpmHandleClass::Vtpm, vhandle));
        }

        Err(TaskError::HandleNameNotFound(*name))
    }

    /// Fetches policy details (policy blob, name algorithm, and empty auth
    /// status) for a handle.
    ///
    /// This loads the context associated with the handle first.
    ///
    /// If the handle is a vTPM handle, details are fetched from the cache.
    /// If it is a physical TPM handle, details are read from the device.
    ///
    /// # Errors
    ///
    /// Returns [`Vtpm`](crate::task::TaskError::Vtpm) when a vTPM cache lookup
    /// fails.
    /// Returns [`Device`](crate::task::TaskError::Device) when reading the
    /// public area fails.
    /// Returns [`InvalidAuth`](crate::task::TaskError::InvalidAuth) when the
    /// handle is invalid.
    /// Returns [`HandleNotFound`](crate::task::TaskError::HandleNotFound) when
    /// the handle cannot be loaded.
    #[allow(clippy::type_complexity)]
    fn fetch_policy(
        &mut self,
        device: &mut TpmDevice,
        handle: &VtpmHandle,
    ) -> Result<(TpmHandle, Vec<Box<dyn VtpmPolicyCommand>>, TpmAlgId, bool), TaskError> {
        let phys_handle = self.load_key(device, handle)?;

        if handle.class() == VtpmHandleClass::Vtpm {
            let vhandle = handle.value().ok_or(TaskError::InvalidAuth)?;
            let key = self
                .cache
                .find_by_virtual_handle(TpmHandle(vhandle))
                .map_err(TaskError::Vtpm)?;
            Ok((
                phys_handle,
                key.policy.clone(),
                key.public.name_alg,
                key.empty_auth != 0,
            ))
        } else {
            let (public, _) = device.read_public(phys_handle)?;
            let empty = is_empty_auth(&public);
            Ok((phys_handle, Vec::new(), public.name_alg, empty))
        }
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
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when
    /// an auth struct is too large.
    pub fn execute<C: TpmFrame>(
        &mut self,
        device: &mut TpmDevice,
        command: &C,
        auth_list: &[TaskAuth],
    ) -> Result<(TpmResponse, TpmAuthResponses), TaskError> {
        if let Some(p) = &self.progress {
            p.start();
        }

        let mut sessions = Vec::new();

        for auth in auth_list {
            let auth_cmd = match auth {
                TaskAuth::Session(vhandle) => {
                    let session = self
                        .sessions
                        .get(&TpmHandle(*vhandle))
                        .ok_or(TaskError::HandleNotFound("vtpm:", *vhandle))?;
                    let nonce_size = TpmHash::from(session.hash_alg).size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| TaskError::OutOfMemory)?;

                    TpmsAuthCommand {
                        session_handle: session.handle(),
                        nonce,
                        session_attributes: session.attributes,
                        hmac: Tpm2bAuth::default(),
                    }
                }
                TaskAuth::Password(password) => build_password_session(password)?,
            };
            sessions.push(auth_cmd);
        }

        let result = device.transmit(command, &sessions);

        if let Some(p) = &self.progress {
            p.stop();
        }

        Ok(result?)
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
    /// Returns [`CapacityExceeded`](crate::TaskError::CapacityExceeded) when
    /// an auth struct is too large.
    pub fn evict_control(
        &mut self,
        device: &mut TpmDevice,
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
            persistent_handle,
            handles: [auth_handle, object_to_evict],
        };

        let (resp, _) = self.execute(device, &cmd, auth_list)?;

        resp.EvictControl()
            .map_err(|_| TaskError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    fn start_policy_session(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
        key_name_alg: TpmAlgId,
        policy_auths: &[TaskAuth],
    ) -> Result<Option<TaskAuth>, TaskError> {
        let mut auth_iter = policy_auths.iter();

        let Some(commands) = self.load_policy_command_list(device, policy, &mut auth_iter)? else {
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

        let temp_session = TaskSession::new(key_name_alg, resp.handles[0])?;
        let vhandle = temp_session.handle();
        self.sessions.insert(vhandle, temp_session);
        let policy_phandle = resp.handles[0];

        let execution_result: Result<(), TaskError> = (|| {
            for (mut command_body, auth_sessions) in commands {
                match &mut command_body {
                    TpmCommand::PolicyPcr(cmd) => cmd.handles[0] = policy_phandle.0.into(),
                    TpmCommand::PolicyOr(cmd) => cmd.handles[0] = policy_phandle.0.into(),
                    TpmCommand::PolicyRestart(cmd) => {
                        cmd.handles[0] = policy_phandle.0.into();
                    }
                    TpmCommand::PolicySecret(cmd) => {
                        cmd.handles[1] = policy_phandle.0.into();
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
            Ok(()) => Ok(Some(TaskAuth::Session(vhandle.0))),
            Err(e) => {
                let _ = self.remove_session(device, policy_phandle);
                Err(e)
            }
        }
    }

    fn start_session(
        device: &mut TpmDevice,
        session_type: TpmSe,
        auth_hash: TpmAlgId,
        bind: TpmHandle,
    ) -> Result<(TpmStartAuthSessionResponse, Tpm2bNonce), TaskError> {
        let digest_len = TpmHash::from(auth_hash).size();
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller =
            Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(|_| TaskError::OutOfMemory)?;

        let cmd = TpmStartAuthSessionCommand {
            nonce_caller,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: TpmtSymDefObject::default(),
            auth_hash,
            handles: [(TpmRh::Null as u32).into(), bind],
        };
        let sessions = vec![];

        let (response_body, _) = device.transmit(&cmd, &sessions)?;

        let resp = response_body
            .StartAuthSession()
            .map_err(|_| TaskError::ResponseMismatch(TpmCc::StartAuthSession))?;

        Ok((resp, nonce_caller))
    }

    fn load_chain_root(
        &mut self,
        device: &mut TpmDevice,
        handle: &VtpmHandle,
    ) -> Result<TpmHandle, TaskError> {
        let handle_val = handle.value().ok_or(TaskError::InvalidParent("vtpm:", 0))?;

        match handle.class() {
            VtpmHandleClass::Tpm => Ok(TpmHandle(handle_val)),
            VtpmHandleClass::Vtpm => {
                if let Some(&phandle) = self.live_handles.get(&handle_val) {
                    return Ok(phandle);
                }

                let key = self.cache.find_by_virtual_handle(TpmHandle(handle_val))?;
                let loaded_phandle = device.load_context(key.context.clone())?;
                self.track(loaded_phandle)?;
                self.live_handles.insert(handle_val, loaded_phandle);
                Ok(loaded_phandle)
            }
        }
    }

    fn load_policy_command_list(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
        policy_auths: &mut std::slice::Iter<'_, TaskAuth>,
    ) -> Result<Option<TpmCommandList>, TaskError> {
        if policy.is_empty() {
            return Ok(None);
        }

        let mut commands = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            let cc = vtpm_cmd.cc();
            let (cmd, auth) = if cc == TpmCc::PolicySecret {
                let body = vtpm_cmd.body();
                let (vtpm_secret_cmd, rest) =
                    VtpmPolicySecretCommand::unmarshal(&body).map_err(TaskError::Unmarshal)?;

                if !rest.is_empty() {
                    return Err(TaskError::MalformedData);
                }

                let live_handle = if vtpm_secret_cmd.object_name.is_empty() {
                    log::warn!(
                        "PolicySecret uses handle hint {:08x} but has no object name. Policy may fail.",
                        vtpm_secret_cmd.object_handle_hint.0
                    );
                    vtpm_secret_cmd.object_handle_hint
                } else {
                    self.load_key_by_name(device, &vtpm_secret_cmd.object_name)?
                };

                let tpm_cmd =
                    TpmCommand::PolicySecret(tpm2_protocol::frame::TpmPolicySecretCommand {
                        nonce_tpm: Tpm2bNonce::default(),
                        cp_hash_a: Tpm2bDigest::default(),
                        policy_ref: vtpm_secret_cmd.policy_ref,
                        expiration: 0,
                        handles: [live_handle, TpmHandle(0)],
                    });

                let auth = match policy_auths
                    .next()
                    .unwrap_or(&TaskAuth::Password(Vec::new()))
                {
                    TaskAuth::Password(val) => build_password_session(val)?,
                    TaskAuth::Session(_) => return Err(TaskError::InvalidAuth),
                };

                let mut auths = TpmAuthCommands::new();
                auths.try_push(auth).map_err(|_| TaskError::OutOfMemory)?;
                (tpm_cmd, auths)
            } else {
                let tpm_cmd = vtpm_cmd.to_command().map_err(TaskError::Vtpm)?;
                (tpm_cmd, TpmAuthCommands::new())
            };
            commands.push((cmd, auth));
        }
        Ok(Some(commands))
    }
}

impl Drop for TaskState<'_> {
    fn drop(&mut self) {
        if let Some(device_rc) = self.device.clone() {
            if let Ok(mut dev) = device_rc.try_borrow_mut() {
                let handles_to_flush: Vec<TpmHandle> = self.tracked_handles.drain().collect();
                for handle in handles_to_flush {
                    if let Err(err) = dev.flush_context(handle) {
                        log::error!("{handle}: {err}");
                    }
                }
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
