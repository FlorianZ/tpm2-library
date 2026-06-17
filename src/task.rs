// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::{
    error::device_err, handle::handle_type, response::parse_response, unmarshal::TpmUnmarshal,
};

use anyhow::{Result, anyhow};
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
    /// Returns an error if reading public areas from the TPM fails, computing a
    /// name for a cached key fails, or a cache operation fails.
    pub fn new(
        device: Option<Rc<RefCell<TpmDevice>>>,
        cache: VtpmCache<'a>,
        progress: Option<Box<dyn TaskStateProgress>>,
        auth_map: HashMap<TpmHandle, Auth>,
    ) -> Result<Self> {
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
    /// Returns an error if the session does not exist or the flush fails.
    pub fn remove_session(&mut self, device: &mut TpmDevice, vhandle: TpmHandle) -> Result<()> {
        let session = self
            .sessions
            .remove(&vhandle)
            .ok_or_else(|| anyhow!("handle not found: {vhandle:08x}"))?;
        session.flush(device).map_err(device_err)?;
        Ok(())
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// If the handle is already tracked, the new instance (which is presumed
    /// to be active on the TPM) is flushed immediately to prevent a resource leak.
    ///
    /// # Errors
    ///
    /// Returns an error if the handle is already being tracked.
    pub fn track(&mut self, device: &mut TpmDevice, phys_handle: TpmHandle) -> Result<()> {
        if self.phys_handles.contains(&phys_handle) {
            let _ = device.flush_context(phys_handle);
            return Err(anyhow!("handle already tracked: {phys_handle}"));
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
    /// Returns an error if a TPM context load or flush fails, or if removing a
    /// stale entry from the cache fails.
    pub fn refresh_cache(&mut self, device: &mut TpmDevice) -> Result<()> {
        let vhandles: Vec<u32> = self.cache.key_iter().map(|(h, _)| *h).collect();
        let mut first_error: Option<anyhow::Error> = None;
        let mut handles_to_remove = Vec::new();

        for &vhandle in &vhandles {
            if handle_type(vhandle) == Some(TpmHt::Persistent) {
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
                        first_error.get_or_insert_with(|| device_err(e));
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
    /// Returns an error if reading the policy fails, a TPM command fails, or a
    /// policy session cannot be created or run.
    pub fn resolve_auth(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> Result<(TpmHandle, TpmAlgId, Auth)> {
        let (phys_handle, policy, name_alg) = self.fetch_policy(device, handle)?;

        if let Some(auth) = self.auth_map.get(&handle).cloned() {
            return Ok((phys_handle, name_alg, auth));
        }

        if let Some(commands) = self.load_policy(device, &policy)? {
            if !commands.is_empty() {
                let session = TpmPolicySession::builder()
                    .with_auth_hash(name_alg)
                    .open(device)
                    .map_err(device_err)?;
                if let Err(e) = session.run(device, commands) {
                    let _ = session.flush(device);
                    return Err(device_err(e));
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
    /// Returns an error if the TPM transmission fails or a response is invalid.
    pub fn save_key_policy(
        &self,
        device: &mut TpmDevice,
        commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<Vec<TpmKeyPolicyCommand>> {
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
    /// Returns an error if the TPM transaction fails or the response is invalid.
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
    ) -> Result<Tpm2bPrivate> {
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
    /// Returns an error if the target handle cannot be found, the context load
    /// fails, or the loaded handle is already tracked.
    pub fn load_key_by_handle(
        &mut self,
        device: &mut TpmDevice,
        target: TpmHandle,
    ) -> Result<TpmHandle> {
        let target_vhandle = target.value();

        if let Some(&phandle) = self.virt_handles.get(&target_vhandle) {
            return Ok(phandle);
        }

        if handle_type(target_vhandle) == Some(TpmHt::Persistent) {
            return Ok(TpmUint32::new(target_vhandle));
        }

        let key = self
            .cache
            .find_by_handle(TpmUint32::new(target_vhandle))
            .ok_or_else(|| anyhow!("handle not found: {target_vhandle:08x}"))?;
        let loaded_phandle = device
            .load_context(key.context().clone())
            .map_err(device_err)?;
        self.track(device, loaded_phandle)?;
        self.virt_handles.insert(target_vhandle, loaded_phandle);
        Ok(loaded_phandle)
    }

    /// Loads a TPM context from a `Tpm2bName`, recursively loading its ancestors first
    ///
    /// # Errors
    ///
    /// Returns an error if the name cannot be found in the cache or the context
    /// load fails.
    pub fn load_key_by_name(
        &mut self,
        device: &mut TpmDevice,
        name: &Tpm2bName,
    ) -> Result<TpmHandle> {
        if let Some(key) = self.cache.find_by_name(name) {
            let vhandle = key.handle().value();
            return self.load_key_by_handle(device, TpmUint32::new(vhandle));
        }

        Err(anyhow!(
            "handle name not found: {}",
            hex::encode(name.as_ref())
        ))
    }

    /// Executes a TPM command with full authorization session handling.
    ///
    /// # Errors
    ///
    /// Returns an error if a referenced session handle is missing, building an
    /// auth session fails, or the TPM transmission fails.
    pub fn execute<'device, C: TpmFrame>(
        &mut self,
        device: &'device mut TpmDevice,
        command: &C,
        auth_list: &[Auth],
    ) -> Result<&'device TpmResponse> {
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
                        .ok_or_else(|| anyhow!("handle not found: {vhandle:08x}"))?;
                    let nonce_size = TpmHash::try_from(session.hash_alg())?.size();
                    let mut nonce_bytes = vec![0; nonce_size];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Tpm2bNonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| anyhow!("out of memory"))?;

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

        result.map_err(device_err)
    }

    /// Evicts a persistent object or makes a transient object persistent using `Session::execute`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transmission fails or the TPM returns an
    /// unexpected response.
    pub fn evict_control(
        &mut self,
        device: &mut TpmDevice,
        object_to_evict: TpmHandle,
        persistent_handle: TpmHandle,
    ) -> Result<()> {
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
    /// Returns an error if reading a public area, computing a name, or creating
    /// a vTPM policy command fails.
    pub(crate) fn save_vtpm_policy(
        &self,
        device: &mut TpmDevice,
        commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<Vec<Box<dyn VtpmPolicyCommand>>> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }

        let mut vtpm_policy = Vec::with_capacity(commands.len());
        for (cmd, auths) in commands {
            let object_name = if let TpmCommand::PolicySecret(inner) = &cmd {
                if let Some(key) = self.cache.find_by_handle(inner.handles[0]) {
                    tpm_make_name(key.public())?
                } else {
                    let (_, name) = device.read_public(inner.handles[0]).map_err(device_err)?;
                    name
                }
            } else {
                Tpm2bName::default()
            };

            let frame = marshal_command_frame(&cmd, &auths)?;
            let command_frame = TpmCommandFrame::cast(&frame)?;
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
    /// Returns an error if computing the cached name fails or removing an entry
    /// from the cache fails.
    fn validate_persistent_handles(&mut self, device: &mut TpmDevice) -> Result<()> {
        let mut persistent_vhandles = Vec::new();
        for (vhandle, _) in self.cache.key_iter() {
            if handle_type(*vhandle) == Some(TpmHt::Persistent) {
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
    /// Returns an error if loading the context fails, the handle cannot be
    /// found, or reading the public area fails.
    #[allow(clippy::type_complexity)]
    fn fetch_policy(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> Result<(TpmHandle, Vec<Box<dyn VtpmPolicyCommand>>, TpmAlgId)> {
        let phys_handle = self.load_key_by_handle(device, handle)?;
        if handle_type(handle.value()) == Some(TpmHt::Transient) {
            let vhandle = handle.value();
            let key = self
                .cache
                .find_by_handle(TpmUint32::new(vhandle))
                .ok_or_else(|| anyhow!("handle not found: {vhandle:08x}"))?;
            Ok((phys_handle, key.policy().clone(), key.public().name_alg))
        } else {
            let (public, _) = device.read_public(phys_handle).map_err(device_err)?;
            Ok((phys_handle, Vec::new(), public.name_alg))
        }
    }

    fn load_policy(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
    ) -> Result<Option<TpmCommandList>> {
        if policy.is_empty() {
            return Ok(None);
        }

        let mut commands = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            let (cmd, auth) = if vtpm_cmd.cc() == TpmCc::PolicySecret {
                self.load_policy_secret(device, vtpm_cmd.as_ref())?
            } else {
                let tpm_cmd = vtpm_cmd.to_command()?;
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
    ) -> Result<(TpmCommand, TpmAuthCommands)> {
        let body = vtpm_cmd.body();
        let (vtpm_secret_cmd, rest) = VtpmPolicySecretCommand::unmarshal(&body)?;

        if !rest.is_empty() {
            return Err(anyhow!("malformed data"));
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
            Auth::Session(_) => return Err(anyhow!("invalid auth")),
        };

        let mut auths = TpmAuthCommands::new();
        auths
            .try_push(auth_cmd)
            .map_err(|_| anyhow!("out of memory"))?;

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

fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(|_| anyhow!("out of memory"))?,
    })
}

fn marshal_command_frame(command: &TpmCommand, auths: &TpmAuthCommands) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; TPM_MAX_COMMAND_SIZE];
    let tag = if auths.is_empty() {
        TpmSt::NoSessions
    } else {
        TpmSt::Sessions
    };

    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        command.marshal_frame(tag, auths, &mut writer)?;
        writer.len()
    };

    buf.truncate(len);
    Ok(buf)
}
