// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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
use tpm2_device::{TpmDevice, TpmDeviceError, TpmPolicySession};
use tpm2_protocol::{
    basic::{TpmHandle, TpmInt32, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc,
        TpmHt, TpmRh, TpmaSession, TpmsAuthCommand,
    },
    frame::{
        TpmAuthCommands, TpmAuthResponses, TpmCommand, TpmEvictControlCommand, TpmFrame,
        TpmResponse,
    },
    TpmUnmarshal,
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyPolicyCommand};
use tpm2_vtpm::{
    vtpm_policy_command_from, VtpmCache, VtpmError, VtpmPolicyCommand, VtpmPolicySecretCommand,
};

type TpmCommandList = Vec<(TpmCommand, TpmAuthCommands)>;

/// Interface for reporting progress of long-running TPM operations.
pub trait TaskStateProgress {
    fn start(&self);
    fn stop(&self);
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
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),
    #[error("device: {0}")]
    Device(#[from] TpmDeviceError),
    #[error("handle already tracked: {0}")]
    HandleAlreadyTracked(TpmHandle),
    #[error("handle not found: {0}")]
    HandleNotFound(TpmHandle),
    #[error("handle name not found: {}", hex::encode(.0.as_ref()))]
    HandleNameNotFound(Tpm2bName),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("invalid auth")]
    InvalidAuth,
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("malformed data")]
    MalformedData,
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),
    #[error("out of memory")]
    OutOfMemory,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("too many auths")]
    TooManyAuths,
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
    #[error("cache: {0}")]
    Vtpm(#[from] VtpmError),
}

pub struct TaskState<'a> {
    pub device: Option<Rc<RefCell<TpmDevice>>>,
    pub cache: VtpmCache<'a>,
    pub progress: Option<Box<dyn TaskStateProgress>>,
    /// Holds all temporary sessions, indexed by their vhandle.
    pub sessions: HashMap<TpmHandle, TpmPolicySession>,
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
            .ok_or(TaskError::HandleNotFound(vhandle))?;
        session.flush(device).map_err(TaskError::Device)
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

    /// Resolves authorization for a given object.
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
    pub fn resolve_auth(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
        auth_map: &HashMap<TpmHandle, TaskAuth>,
    ) -> Result<(TpmHandle, TpmAlgId, TaskAuth), TaskError> {
        let (phys_handle, policy, name_alg) = self.fetch_policy(device, handle)?;

        if let Some(auth) = auth_map.get(&handle).cloned() {
            return Ok((phys_handle, name_alg, auth));
        }

        if let Some(commands) = self.load_policy(device, &policy, auth_map)? {
            if !commands.is_empty() {
                let session = TpmPolicySession::builder()
                    .with_auth_hash(name_alg)
                    .open(device)?;
                if let Err(e) = session.run(device, commands) {
                    let _ = session.flush(device);
                    return Err(e.into());
                }
                let vhandle = session.handle();
                self.sessions.insert(vhandle, session);
                return Ok((phys_handle, name_alg, TaskAuth::Session(vhandle.0)));
            }
        }

        Ok((phys_handle, name_alg, TaskAuth::default()))
    }

    /// Constructs a `TpmKeyFile` from the given key components.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] if reading the parent public area or building the key policy fails.
    pub fn build_tpm_key_file(
        &self,
        device: &mut TpmDevice,
        public: Tpm2bPublic,
        private: Tpm2bPrivate,
        parent_handle: TpmHandle,
        empty_auth: bool,
        policy_commands: Option<Vec<(TpmCommand, TpmAuthCommands)>>,
    ) -> Result<TpmKeyFile, TaskError> {
        Ok(TpmKeyFile::builder()
            .with_policy(self.build_key_policy(device, policy_commands)?)
            .with_empty_auth(empty_auth)
            .build(public, private, parent_handle))
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
    /// target `TpmHandle` is invalid.
    /// Returns [`Crypto`](crate::task::TaskError::Crypto) when name calculation
    /// fails.
    /// Returns [`Marshal`](crate::task::TaskError::Marshal) when marshaling
    /// fails during persistent key lookup.
    /// Returns
    /// [`HandleAlreadyTracked`](crate::task::TaskError::HandleAlreadyTracked)
    /// if a loaded handle
    /// is already being tracked.
    pub fn load_key_by_handle(
        &mut self,
        device: &mut TpmDevice,
        target: TpmHandle,
    ) -> Result<TpmHandle, TaskError> {
        let target_vhandle = target.0;

        if let Some(&phandle) = self.live_handles.get(&target_vhandle) {
            return Ok(phandle);
        }

        let chain = self.cache.fetch_ancestors(TpmUint32(target_vhandle))?;

        if chain.is_empty() {
            return Err(TaskError::HandleNotFound(TpmUint32(target_vhandle)));
        }

        let mut last_phandle = TpmUint32(0);
        for handle in chain {
            last_phandle = self.load_key_context(device, handle)?;
        }

        Ok(last_phandle)
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
    /// `TpmHandle` is invalid.
    /// Returns [`HandleNotFound`](crate::TaskError::HandleNotFound) when a VTPM
    /// handle is not in the cache.
    /// Returns [`InvalidParent`](crate::TaskError::InvalidParent) when the
    /// loaded key's parent is incorrect.
    pub fn load_key_by_name(
        &mut self,
        device: &mut TpmDevice,
        name: &Tpm2bName,
    ) -> Result<TpmHandle, TaskError> {
        if let Some(key) = self.cache.find_by_name(name) {
            let vhandle = key.handle().0;
            return self.load_key_by_handle(device, TpmUint32(vhandle));
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
        handle: TpmHandle,
    ) -> Result<(TpmHandle, Vec<Box<dyn VtpmPolicyCommand>>, TpmAlgId), TaskError> {
        let phys_handle = self.load_key_by_handle(device, handle)?;
        let ht_byte = (handle.0 >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| TaskError::InvalidHandleType(ht_byte))?;

        if ht == TpmHt::Transient {
            let vhandle = handle.0;
            let key = self
                .cache
                .find_by_handle(TpmUint32(vhandle))
                .ok_or(TaskError::HandleNotFound(TpmUint32(vhandle)))?;
            Ok((phys_handle, key.policy().clone(), key.public().name_alg))
        } else {
            let (public, _) = device.read_public(phys_handle)?;
            Ok((phys_handle, Vec::new(), public.name_alg))
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
                        .get(&TpmUint32(*vhandle))
                        .ok_or(TaskError::HandleNotFound(TpmUint32(*vhandle)))?;
                    let nonce_size = TpmHash::from(session.hash_alg()).size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| TaskError::OutOfMemory)?;

                    TpmsAuthCommand {
                        session_handle: session.handle(),
                        nonce,
                        session_attributes: session.attributes(),
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
        auth_map: &HashMap<TpmHandle, TaskAuth>,
    ) -> Result<(), TaskError> {
        let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
            (TpmRh::Owner as u32).into()
        } else {
            (TpmRh::Platform as u32).into()
        };

        let auth = auth_map.get(&auth_handle).cloned().unwrap_or_default();

        let cmd = TpmEvictControlCommand {
            persistent_handle,
            handles: [auth_handle, object_to_evict],
        };

        let (resp, _) = self.execute(device, &cmd, &[auth])?;

        resp.EvictControl()
            .map_err(|_| TaskError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    fn build_key_policy(
        &self,
        device: &mut TpmDevice,
        commands: Option<Vec<(TpmCommand, TpmAuthCommands)>>,
    ) -> Result<Option<TpmKeyPolicy>, TaskError> {
        let Some(commands) = commands else {
            return Ok(None);
        };

        let mut vtpm_policy: Vec<Box<dyn VtpmPolicyCommand>> = Vec::new();
        for (cmd, _) in commands {
            let object_name = if let TpmCommand::PolicySecret(inner) = &cmd {
                if let Some(key) = self.cache.find_by_handle(inner.handles[0]) {
                    tpm_make_name(key.public())?
                } else {
                    let (_, name) = device.read_public(inner.handles[0])?;
                    name
                }
            } else {
                Tpm2bName::default()
            };
            vtpm_policy.push(vtpm_policy_command_from(&cmd, &object_name)?);
        }

        let mut policy = Vec::new();
        for cmd in vtpm_policy {
            policy.push(TpmKeyPolicyCommand {
                cc: cmd.cc(),
                body: cmd.body(),
            });
        }
        Ok(Some(TpmKeyPolicy { name: None, policy }))
    }

    fn load_policy(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
        auth_map: &HashMap<TpmHandle, TaskAuth>,
    ) -> Result<Option<TpmCommandList>, TaskError> {
        if policy.is_empty() {
            return Ok(None);
        }

        let mut commands = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            let (cmd, auth) = if vtpm_cmd.cc() == TpmCc::PolicySecret {
                self.load_policy_secret(device, vtpm_cmd.as_ref(), auth_map)?
            } else {
                let tpm_cmd = vtpm_cmd.to_command().map_err(TaskError::Vtpm)?;
                (tpm_cmd, TpmAuthCommands::new())
            };
            commands.push((cmd, auth));
        }

        Ok(Some(commands))
    }

    fn load_policy_secret(
        &mut self,
        device: &mut TpmDevice,
        vtpm_cmd: &dyn VtpmPolicyCommand,
        auth_map: &HashMap<TpmHandle, TaskAuth>,
    ) -> Result<(TpmCommand, TpmAuthCommands), TaskError> {
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

        let tpm_cmd = TpmCommand::PolicySecret(tpm2_protocol::frame::TpmPolicySecretCommand {
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: vtpm_secret_cmd.policy_ref,
            expiration: TpmInt32(0),
            handles: [live_handle, TpmUint32(0)],
        });

        let vhandle = if vtpm_secret_cmd.object_name.is_empty() {
            None
        } else {
            self.cache
                .find_by_name(&vtpm_secret_cmd.object_name)
                .map(|k| TpmUint32(k.handle().0))
        };

        let task_auth = vhandle
            .and_then(|vhandle| auth_map.get(&vhandle))
            .cloned()
            .unwrap_or_default();

        let auth_cmd = match task_auth {
            TaskAuth::Password(password) => build_password_session(&password)?,
            TaskAuth::Session(_) => return Err(TaskError::InvalidAuth),
        };

        let mut auths = TpmAuthCommands::new();
        auths
            .try_push(auth_cmd)
            .map_err(|_| TaskError::OutOfMemory)?;

        Ok((tpm_cmd, auths))
    }

    fn load_key_context(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> Result<TpmHandle, TaskError> {
        let handle_val = handle.0;
        let ht_byte = (handle_val >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| TaskError::InvalidHandleType(ht_byte))?;

        if ht == TpmHt::Persistent {
            return Ok(TpmUint32(handle_val));
        }

        if let Some(&phandle) = self.live_handles.get(&handle_val) {
            return Ok(phandle);
        }

        let key = self
            .cache
            .find_by_handle(TpmUint32(handle_val))
            .ok_or(TaskError::HandleNotFound(TpmUint32(handle_val)))?;
        let loaded_phandle = device.load_context(key.context().clone())?;
        self.track(loaded_phandle)?;
        self.live_handles.insert(handle_val, loaded_phandle);
        Ok(loaded_phandle)
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
                    if let Err(e) = session.flush(&mut dev) {
                        log::error!("{:08x}: {e}", session.handle());
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
