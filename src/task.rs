// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::{error::CommandError, response::parse_response, unmarshal::TpmUnmarshal};

use rand::{RngCore, thread_rng};
use tpm2_crypto::{TpmHash, tpm_make_name};
use tpm2_device::{TpmDevice, TpmDeviceError, TpmPolicySession};
use tpm2_protocol::{
    TpmWriter,
    basic::{TpmHandle, TpmInt32, TpmUint32},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
        Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmHt, TpmRcBase, TpmRh, TpmSt, TpmaSession,
        TpmsAuthCommand, TpmsContext, TpmtSymDefObject,
    },
    frame::{
        TpmAuthCommands, TpmCommand as TpmCommandFrame, TpmCommandValue as TpmCommand,
        TpmEvictControlCommand, TpmEvictControlResponse, TpmFrame, TpmImportCommand,
        TpmImportResponse, TpmResponse,
    },
};
use tpm2_tpmkey::TpmKeyPolicyCommand;
use tpm2_vtpm::{VtpmCache, VtpmPolicyCommand, VtpmPolicySecretCommand, vtpm_policy_command_from};

type TpmCommandList = Vec<(TpmCommand, TpmAuthCommands)>;

/// Interface for reporting progress of long-running TPM operations.
pub trait TaskStateProgress {
    fn start(&self);
    fn stop(&self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Session(u32),
}

impl Default for Auth {
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

pub struct TaskState<'a> {
    pub device: Option<Rc<RefCell<TpmDevice>>>,
    pub cache: VtpmCache<'a>,
    pub progress: Option<Box<dyn TaskStateProgress>>,
    /// Holds all temporary sessions, indexed by their virtual handle.
    pub sessions: HashMap<TpmHandle, TpmPolicySession>,
    /// Loaded virtual handles. Handles containted are s a subset of
    /// `phys_handles`.
    pub virt_handles: HashMap<u32, TpmHandle>,
    /// Tracked physical handles. Handles contained are a superset of
    /// `virt_handles`.
    pub phys_handles: HashSet<TpmHandle>,
    /// Authentication values indexed by handle.
    pub auth_map: HashMap<TpmHandle, Auth>,
}

impl<'a> TaskState<'a> {
    /// Creates a new `TaskState` and performs initial cache sanitization.
    ///
    /// If a TPM device is available, this scans persistent entries in the vTPM
    /// cache and drops those that no longer exist in the TPM or whose public
    /// area has changed.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Device`] if reading public areas from the TPM
    /// fails, or [`CommandError::Crypto`] if computing a name for a cached key
    /// fails. May also return [`CommandError::Vtpm`] if a cache operation fails.
    pub fn new(
        device: Option<Rc<RefCell<TpmDevice>>>,
        cache: VtpmCache<'a>,
        progress: Option<Box<dyn TaskStateProgress>>,
        auth_map: HashMap<TpmHandle, Auth>,
    ) -> Result<Self, CommandError> {
        let mut state = Self {
            device,
            cache,
            progress,
            sessions: HashMap::new(),
            virt_handles: HashMap::new(),
            phys_handles: HashSet::new(),
            auth_map,
        };

        let device_opt = state.device.clone();
        if let Some(device_rc) = device_opt {
            let mut dev = device_rc.borrow_mut();
            state.validate_persistent_handles(&mut dev)?;
        }

        Ok(state)
    }

    /// Removes a session from the task's state and flushes it from the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Device`] when the TPM transmission fails.
    /// Returns [`CommandError::HandleNotFound`] if the session does not exist.
    pub fn remove_session(
        &mut self,
        device: &mut TpmDevice,
        vhandle: TpmHandle,
    ) -> Result<(), CommandError> {
        let session = self
            .sessions
            .remove(&vhandle)
            .ok_or(CommandError::HandleNotFound(vhandle))?;
        session.flush(device)?;
        Ok(())
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// If the handle is already tracked, the new instance (which is presumed
    /// to be active on the TPM) is flushed immediately to prevent a resource leak.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::HandleAlreadyTracked`] if the handle is already
    /// being tracked.
    pub fn track(
        &mut self,
        device: &mut TpmDevice,
        phys_handle: TpmHandle,
    ) -> Result<(), CommandError> {
        if self.phys_handles.contains(&phys_handle) {
            let _ = device.flush_context(phys_handle);
            return Err(CommandError::HandleAlreadyTracked(phys_handle));
        }
        self.phys_handles.insert(phys_handle);
        Ok(())
    }

    /// Removes a handle from the live handle tracking list.
    pub fn untrack(&mut self, handle: TpmHandle) {
        self.phys_handles.remove(&handle);
        self.virt_handles.retain(|_, v| *v != handle);
    }

    /// Refreshes the cache by checking validity of the keys.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::CommandError::Device) when the TPM context
    /// load or flush fails.
    /// Returns [`Vtpm`](crate::CommandError::Vtpm) when removing a stale entry
    /// from the cache fails.
    pub fn refresh_cache(&mut self, device: &mut TpmDevice) -> Result<(), CommandError> {
        let vhandles: Vec<u32> = self.cache.key_iter().map(|(h, _)| *h).collect();
        let mut first_error: Option<CommandError> = None;
        let mut handles_to_remove = Vec::new();

        for &vhandle in &vhandles {
            if (vhandle >> 24) as u8 == TpmHt::Persistent as u8 {
                continue;
            }

            if let Some(key) = self.cache.find_by_handle(TpmUint32::new(vhandle)) {
                match Self::refresh_key(device, vhandle, key.context().clone()) {
                    Ok(true) => {
                        self.cache.mark_dirty(vhandle);
                    }
                    Ok(false) => handles_to_remove.push(vhandle),
                    Err(e) => {
                        log::warn!("{vhandle:08x}: {e}");
                        first_error.get_or_insert_with(|| e.into());
                        handles_to_remove.push(vhandle);
                    }
                }
            }
        }

        for vhandle in handles_to_remove {
            if let Err(e) = self.cache.remove(vhandle) {
                log::error!("{vhandle:08x}: {e}");
                first_error.get_or_insert_with(|| e.into());
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Resolves authorization for a given object.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when a
    /// non-password auth is provided.
    /// Returns [`MalformedData`](CommandError::MalformedData) when an
    /// unsupported policy command is found.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when a
    /// temporary session handle is lost.
    /// Returns [`Device`](CommandError::Device) when a TPM command fails.
    /// Returns [`Vtpm`](CommandError::Vtpm) when session creation, saving, or
    /// parsing fails.
    /// Returns [`Key`](CommandError::Key) when parsing a policy command
    /// fails.
    /// Returns [`CapacityExceeded`](CommandError::CapacityExceeded) when an
    /// auth list is too large.
    /// Returns [`Crypto`](CommandError::Crypto) when name calculation fails.
    /// Returns [`HandleNameNotFound`](CommandError::HandleNameNotFound) when
    /// a policy secret handle cannot be found.
    #[allow(clippy::type_complexity)]
    pub fn resolve_auth(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> Result<(TpmHandle, TpmAlgId, Auth), CommandError> {
        let (phys_handle, policy, name_alg) = self.fetch_policy(device, handle)?;

        if let Some(auth) = self.auth_map.get(&handle).cloned() {
            return Ok((phys_handle, name_alg, auth));
        }

        if let Some(commands) = self.load_policy(device, &policy)? {
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
                return Ok((phys_handle, name_alg, Auth::Session(vhandle.value())));
            }
        }

        Ok((phys_handle, name_alg, Auth::default()))
    }

    /// Constructs a [`TpmKeyPolicy`](tpm2_tpmkey::TpmKeyPolicy) instance from
    /// the given sequence of policy commands.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::CommandError::Device) when the TPM
    /// transmission has failed.
    /// Returns [`ResponseMismatch`](crate::CommandError::ResponseMismatch) if
    /// the TPM response tag is not valid.
    pub fn save_key_policy(
        &self,
        device: &mut TpmDevice,
        commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<Vec<TpmKeyPolicyCommand>, CommandError> {
        let vtpm_policy = self.save_vtpm_policy(device, commands)?;
        let mut key_policy = Vec::with_capacity(vtpm_policy.len());
        for cmd in vtpm_policy {
            key_policy.push(TpmKeyPolicyCommand::new(cmd.cc(), cmd.body()));
        }
        Ok(key_policy)
    }

    /// Runs the `TPM2_Import` command to load a duplicate blob into the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Device`] if the TPM transaction fails.
    /// Returns [`CommandError::ResponseMismatch`] if the TPM response tag is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn import_key(
        &mut self,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        public: &Tpm2bPublic,
        duplicate: &Tpm2bPrivate,
        in_sym_seed: &Tpm2bEncryptedSecret,
        encryption_key: &Tpm2bData,
        symmetric_alg: &TpmtSymDefObject,
        auth_list: &[Auth],
    ) -> Result<Tpm2bPrivate, CommandError> {
        let import_cmd = TpmImportCommand {
            encryption_key: *encryption_key,
            object_public: public.clone(),
            duplicate: *duplicate,
            in_sym_seed: *in_sym_seed,
            symmetric_alg: *symmetric_alg,
            handles: [parent_handle.value().into()],
        };

        let resp = self.execute(device, &import_cmd, auth_list)?;
        let import_resp = parse_response::<TpmImportResponse>(resp)?;

        Ok(import_resp.out_private)
    }

    /// Loads a TPM context from a handle.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](CommandError::Device) when a TPM command
    /// fails.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when
    /// the target handle cannot be found.
    /// Returns [`Vtpm`](CommandError::Vtpm) when tracking the loaded
    /// handle fails.
    /// Returns
    /// [`HandleAlreadyTracked`](CommandError::HandleAlreadyTracked)
    /// if a loaded handle
    /// is already being tracked.
    pub fn load_key_by_handle(
        &mut self,
        device: &mut TpmDevice,
        target: TpmHandle,
    ) -> Result<TpmHandle, CommandError> {
        let target_vhandle = target.value();

        if let Some(&phandle) = self.virt_handles.get(&target_vhandle) {
            return Ok(phandle);
        }

        if (target_vhandle >> 24) as u8 == TpmHt::Persistent as u8 {
            return Ok(TpmUint32::new(target_vhandle));
        }

        let key = self
            .cache
            .find_by_handle(TpmUint32::new(target_vhandle))
            .ok_or(CommandError::HandleNotFound(TpmUint32::new(target_vhandle)))?;
        let loaded_phandle = device.load_context(key.context().clone())?;
        self.track(device, loaded_phandle)?;
        self.virt_handles.insert(target_vhandle, loaded_phandle);
        Ok(loaded_phandle)
    }

    /// Loads a TPM context from a `Tpm2bName`, recursively loading its ancestors first
    ///
    /// # Errors
    ///
    /// Returns [`Device`](CommandError::Device) when a TPM command fails.
    /// Returns [`Crypto`](CommandError::Crypto) when name calculation fails.
    /// Returns [`Vtpm`](CommandError::Vtpm) when a cache operation fails.
    /// Returns [`HandleNameNotFound`](CommandError::HandleNameNotFound) when
    /// the name cannot be found.
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when the
    /// `TpmHandle` is invalid.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when a VTPM
    /// handle is not in the cache.
    pub fn load_key_by_name(
        &mut self,
        device: &mut TpmDevice,
        name: &Tpm2bName,
    ) -> Result<TpmHandle, CommandError> {
        if let Some(key) = self.cache.find_by_name(name) {
            let vhandle = key.handle().value();
            return self.load_key_by_handle(device, TpmUint32::new(vhandle));
        }

        Err(CommandError::HandleNameNotFound(*name))
    }

    /// Executes a TPM command with full authorization session handling.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](CommandError::Device) when the transmission
    /// fails or the TPM returns an error.
    /// Returns [`Vtpm`](CommandError::Vtpm) when a session operation fails.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when a
    /// session handle is not found.
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`CapacityExceeded`](CommandError::CapacityExceeded) when
    /// an auth struct is too large.
    pub fn execute<'device, C: TpmFrame>(
        &mut self,
        device: &'device mut TpmDevice,
        command: &C,
        auth_list: &[Auth],
    ) -> Result<&'device TpmResponse, CommandError> {
        if let Some(p) = &self.progress {
            p.start();
        }

        let mut sessions = Vec::new();

        for auth in auth_list {
            let auth_cmd = match auth {
                Auth::Session(vhandle) => {
                    let session = self
                        .sessions
                        .get(&TpmUint32::new(*vhandle))
                        .ok_or(CommandError::HandleNotFound(TpmUint32::new(*vhandle)))?;
                    let nonce_size = TpmHash::try_from(session.hash_alg())?.size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| CommandError::OutOfMemory)?;

                    TpmsAuthCommand {
                        session_handle: session.handle(),
                        nonce,
                        session_attributes: session.attributes(),
                        hmac: Tpm2bAuth::default(),
                    }
                }
                Auth::Password(password) => build_password_session(password)?,
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
    /// Returns [`Device`](CommandError::Device) when the transmission
    /// fails.
    /// Returns [`ResponseMismatch`](CommandError::ResponseMismatch) when
    /// the TPM command returns an unexpected response type.
    /// Returns [`Vtpm`](CommandError::Vtpm) when a session operation fails.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when a
    /// session handle is not found.
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`CapacityExceeded`](CommandError::CapacityExceeded) when
    /// an auth struct is too large.
    pub fn evict_control(
        &mut self,
        device: &mut TpmDevice,
        object_to_evict: TpmHandle,
        persistent_handle: TpmHandle,
    ) -> Result<(), CommandError> {
        let auth_handle: TpmHandle = if (persistent_handle.value() & 0x00FF_FFFF) <= 0x007F_FFFF {
            (TpmRh::Owner as u32).into()
        } else {
            (TpmRh::Platform as u32).into()
        };

        let auth = self.auth_map.get(&auth_handle).cloned().unwrap_or_default();

        let cmd = TpmEvictControlCommand {
            persistent_handle,
            handles: [auth_handle, object_to_evict],
        };

        let resp = self.execute(device, &cmd, &[auth])?;
        parse_response::<TpmEvictControlResponse>(resp)?;
        Ok(())
    }

    /// Converts an ephemeral list of TPM policy commands into a storable vTPM policy.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] if reading a public area, computing a name, or
    /// creating a vTPM policy command fails.
    pub(crate) fn save_vtpm_policy(
        &self,
        device: &mut TpmDevice,
        commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<Vec<Box<dyn VtpmPolicyCommand>>, CommandError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }

        let mut vtpm_policy = Vec::with_capacity(commands.len());
        for (cmd, auths) in commands {
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

            let frame = marshal_command_frame(&cmd, &auths)?;
            let command_frame = TpmCommandFrame::cast(&frame).map_err(CommandError::Unmarshal)?;
            vtpm_policy.push(vtpm_policy_command_from(command_frame, &object_name)?);
        }

        Ok(vtpm_policy)
    }

    /// Best-effort validation of persistent handles in the vTPM cache.
    ///
    /// For each cached entry whose vhandle is in the persistent handle range,
    /// this:
    ///    * checks whether the TPM still has an object at that handle
    ///    * compares the cached public area against the TPM's view by name
    ///      (`Tpm2bName`)
    ///    * removes the cache entry when the handle is gone or the name changes.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Device`] if `read_public` fails in a way that
    /// cannot be handled gracefully, or [`CommandError::Crypto`] if computing the
    /// cached name fails. May also return [`CommandError::Vtpm`] if removing an
    /// entry from the cache fails.
    fn validate_persistent_handles(&mut self, device: &mut TpmDevice) -> Result<(), CommandError> {
        let mut persistent_vhandles = Vec::new();
        for (vhandle, _) in self.cache.key_iter() {
            if (*vhandle >> 24) as u8 == TpmHt::Persistent as u8 {
                persistent_vhandles.push(*vhandle);
            }
        }

        for vhandle in persistent_vhandles {
            let tpm_handle = TpmUint32::new(vhandle);

            let Some(key) = self.cache.find_by_handle(tpm_handle) else {
                continue;
            };

            match device.read_public(tpm_handle) {
                Ok((_public, name_on_tpm)) => {
                    let cached_name = tpm_make_name(key.public())?;

                    if cached_name != name_on_tpm {
                        log::debug!("dropping stale persistent entry {vhandle:08x}: name mismatch");
                        self.cache.remove(vhandle)?;
                    }
                }
                Err(e) => {
                    log::debug!(
                        "dropping stale persistent entry {vhandle:08x}: read_public failed: {e}"
                    );
                    self.cache.remove(vhandle)?;
                }
            }
        }

        Ok(())
    }

    fn refresh_key(
        device: &mut TpmDevice,
        vhandle: u32,
        context: TpmsContext,
    ) -> Result<bool, TpmDeviceError> {
        match device.load_context(context) {
            Ok(handle) => match device.flush_context(handle) {
                Ok(()) => Ok(true),
                Err(e) => Err(e),
            },
            Err(TpmDeviceError::TpmRc(rc)) => match rc.base() {
                TpmRcBase::ReferenceH0
                | TpmRcBase::Integrity
                | TpmRcBase::Hierarchy
                | TpmRcBase::Value
                | TpmRcBase::Handle => {
                    log::debug!("{vhandle:08x}: {rc}");
                    Ok(false)
                }
                _ => Err(TpmDeviceError::TpmRc(rc)),
            },
            Err(e) => Err(e),
        }
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
    /// Returns [`Vtpm`](CommandError::Vtpm) when a vTPM cache lookup
    /// fails.
    /// Returns [`Device`](CommandError::Device) when reading the
    /// public area fails.
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when the
    /// handle is invalid.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when
    /// the handle cannot be loaded.
    #[allow(clippy::type_complexity)]
    fn fetch_policy(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> Result<(TpmHandle, Vec<Box<dyn VtpmPolicyCommand>>, TpmAlgId), CommandError> {
        let phys_handle = self.load_key_by_handle(device, handle)?;
        if (handle.value() >> 24) as u8 == TpmHt::Transient as u8 {
            let vhandle = handle.value();
            let key = self
                .cache
                .find_by_handle(TpmUint32::new(vhandle))
                .ok_or(CommandError::HandleNotFound(TpmUint32::new(vhandle)))?;
            Ok((phys_handle, key.policy().clone(), key.public().name_alg))
        } else {
            let (public, _) = device.read_public(phys_handle)?;
            Ok((phys_handle, Vec::new(), public.name_alg))
        }
    }

    fn load_policy(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
    ) -> Result<Option<TpmCommandList>, CommandError> {
        if policy.is_empty() {
            return Ok(None);
        }

        let mut commands = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            let (cmd, auth) = if vtpm_cmd.cc() == TpmCc::PolicySecret {
                self.load_policy_secret(device, vtpm_cmd.as_ref())?
            } else {
                let tpm_cmd = vtpm_cmd.to_command().map_err(CommandError::Vtpm)?;
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
    ) -> Result<(TpmCommand, TpmAuthCommands), CommandError> {
        let body = vtpm_cmd.body();
        let (vtpm_secret_cmd, rest) =
            VtpmPolicySecretCommand::unmarshal(&body).map_err(CommandError::Unmarshal)?;

        if !rest.is_empty() {
            return Err(CommandError::MalformedData);
        }

        let live_handle = if vtpm_secret_cmd.object_name.is_empty() {
            log::warn!(
                "PolicySecret uses handle hint {:08x} but has no object name. Policy may fail.",
                vtpm_secret_cmd.object_handle_hint.value()
            );
            vtpm_secret_cmd.object_handle_hint
        } else {
            self.load_key_by_name(device, &vtpm_secret_cmd.object_name)?
        };

        let tpm_cmd = TpmCommand::PolicySecret(tpm2_protocol::frame::TpmPolicySecretCommand {
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: vtpm_secret_cmd.policy_ref,
            expiration: TpmInt32::new(0),
            handles: [live_handle, TpmUint32::new(0)],
        });

        let vhandle = if vtpm_secret_cmd.object_name.is_empty() {
            None
        } else {
            self.cache
                .find_by_name(&vtpm_secret_cmd.object_name)
                .map(|k| TpmUint32::new(k.handle().value()))
        };

        let task_auth = vhandle
            .and_then(|vhandle| self.auth_map.get(&vhandle))
            .cloned()
            .unwrap_or_default();

        let auth_cmd = match task_auth {
            Auth::Password(password) => build_password_session(&password)?,
            Auth::Session(_) => return Err(CommandError::InvalidAuth),
        };

        let mut auths = TpmAuthCommands::new();
        auths
            .try_push(auth_cmd)
            .map_err(|_| CommandError::OutOfMemory)?;

        Ok((tpm_cmd, auths))
    }
}

impl Drop for TaskState<'_> {
    fn drop(&mut self) {
        if let Some(device_rc) = self.device.clone() {
            if let Ok(mut dev) = device_rc.try_borrow_mut() {
                let handles_to_flush: Vec<TpmHandle> = self.phys_handles.drain().collect();
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

fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, CommandError> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(|_| CommandError::OutOfMemory)?,
    })
}

fn marshal_command_frame(
    command: &TpmCommand,
    auths: &TpmAuthCommands,
) -> Result<Vec<u8>, CommandError> {
    let mut buf = vec![0_u8; TPM_MAX_COMMAND_SIZE];
    let tag = if auths.is_empty() {
        TpmSt::NoSessions
    } else {
        TpmSt::Sessions
    };

    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        command
            .marshal_frame(tag, auths, &mut writer)
            .map_err(CommandError::Marshal)?;
        writer.len()
    };

    buf.truncate(len);
    Ok(buf)
}
