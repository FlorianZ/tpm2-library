// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::error::CommandError;

use rand::{thread_rng, RngCore};
use tpm2_crypto::{tpm_make_name, TpmHash};
use tpm2_device::{TpmDevice, TpmPolicySession};
use tpm2_protocol::TpmUnmarshal;
use tpm2_protocol::{
    basic::{TpmHandle, TpmInt32, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
        Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmHt, TpmRh, TpmaSession, TpmsAuthCommand,
        TpmtSymDefObject,
    },
    frame::{
        TpmAuthCommands, TpmAuthResponses, TpmCommand, TpmEvictControlCommand, TpmFrame,
        TpmImportCommand, TpmResponse,
    },
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyPolicyCommand, TpmKeyType};
use tpm2_vtpm::{vtpm_policy_command_from, VtpmCache, VtpmPolicyCommand, VtpmPolicySecretCommand};

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
    /// Holds all temporary sessions, indexed by their vhandle.
    pub sessions: HashMap<TpmHandle, TpmPolicySession>,
    /// Live handles (virtual handle -> physical handle).
    pub live_handles: HashMap<u32, TpmHandle>,
    /// All tracked handles (physical) for cleanup.
    pub tracked_handles: HashSet<TpmHandle>,
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
    ) -> Result<Self, CommandError> {
        let mut state = Self {
            device,
            cache,
            progress,
            sessions: HashMap::new(),
            live_handles: HashMap::new(),
            tracked_handles: HashSet::new(),
        };

        let device_opt = state.device.clone();
        if let Some(device_rc) = device_opt {
            let mut dev = device_rc.borrow_mut();
            state.validate_persistent_handles(&mut dev)?;
        }

        Ok(state)
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
            let handle_val = *vhandle;
            let ht_byte = (handle_val >> 24) as u8;
            if let Ok(TpmHt::Persistent) = TpmHt::try_from(ht_byte) {
                persistent_vhandles.push(handle_val);
            }
        }

        for vhandle in persistent_vhandles {
            let tpm_handle = TpmUint32(vhandle);

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
    pub fn track(&mut self, device: &mut TpmDevice, handle: TpmHandle) -> Result<(), CommandError> {
        if self.tracked_handles.contains(&handle) {
            let _ = device.flush_context(handle);
            return Err(CommandError::HandleAlreadyTracked(handle));
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
        auth_map: &HashMap<TpmHandle, Auth>,
    ) -> Result<(TpmHandle, TpmAlgId, Auth), CommandError> {
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
                return Ok((phys_handle, name_alg, Auth::Session(vhandle.0)));
            }
        }

        Ok((phys_handle, name_alg, Auth::default()))
    }

    /// Constructs a `TpmKeyFile` from the given key components.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] if reading the parent public area or building the key policy fails.
    pub fn save_key(
        &self,
        device: &mut TpmDevice,
        public: Tpm2bPublic,
        private: Tpm2bPrivate,
        parent_handle: TpmHandle,
        empty_auth: bool,
        commands: Option<Vec<(TpmCommand, TpmAuthCommands)>>,
    ) -> Result<TpmKeyFile, CommandError> {
        let kind = if public.inner.object_type == TpmAlgId::KeyedHash {
            TpmKeyType::SealedData
        } else {
            TpmKeyType::Loadable
        };

        let mut file = TpmKeyFile::new()
            .with_kind(kind)
            .with_empty_auth(empty_auth)
            .with_public(public)
            .with_private(private)
            .with_parent(parent_handle);

        if let Some(vtpm_policy) = self.save_policy(device, commands)? {
            let mut policy = Vec::with_capacity(vtpm_policy.len());
            for cmd in vtpm_policy {
                policy.push(TpmKeyPolicyCommand::new(cmd.cc(), cmd.body()));
            }
            file = file.with_policy(TpmKeyPolicy::new(None, policy));
        }

        Ok(file)
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
            handles: [parent_handle.0.into()],
        };

        let (resp, _) = self.execute(device, &import_cmd, auth_list)?;
        let import_resp = resp
            .Import()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Import))?;

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
        let target_vhandle = target.0;

        if let Some(&phandle) = self.live_handles.get(&target_vhandle) {
            return Ok(phandle);
        }

        let handle_val = target.0;
        let ht_byte = (handle_val >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| CommandError::InvalidHandleType(ht_byte))?;

        if ht == TpmHt::Persistent {
            return Ok(TpmUint32(handle_val));
        }

        if let Some(&phandle) = self.live_handles.get(&handle_val) {
            return Ok(phandle);
        }

        let key = self
            .cache
            .find_by_handle(TpmUint32(handle_val))
            .ok_or(CommandError::HandleNotFound(TpmUint32(handle_val)))?;
        let loaded_phandle = device.load_context(key.context().clone())?;
        self.track(device, loaded_phandle)?;
        self.live_handles.insert(handle_val, loaded_phandle);
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
            let vhandle = key.handle().0;
            return self.load_key_by_handle(device, TpmUint32(vhandle));
        }

        Err(CommandError::HandleNameNotFound(*name))
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
        let ht_byte = (handle.0 >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| CommandError::InvalidHandleType(ht_byte))?;

        if ht == TpmHt::Transient {
            let vhandle = handle.0;
            let key = self
                .cache
                .find_by_handle(TpmUint32(vhandle))
                .ok_or(CommandError::HandleNotFound(TpmUint32(vhandle)))?;
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
    /// Returns [`Device`](CommandError::Device) when the transmission
    /// fails or the TPM returns an error.
    /// Returns [`Vtpm`](CommandError::Vtpm) when a session operation fails.
    /// Returns [`HandleNotFound`](CommandError::HandleNotFound) when a
    /// session handle is not found.
    /// Returns [`InvalidAuth`](CommandError::InvalidAuth) when a `Policy`
    /// auth class is encountered.
    /// Returns [`CapacityExceeded`](CommandError::CapacityExceeded) when
    /// an auth struct is too large.
    pub fn execute<C: TpmFrame>(
        &mut self,
        device: &mut TpmDevice,
        command: &C,
        auth_list: &[Auth],
    ) -> Result<(TpmResponse, TpmAuthResponses), CommandError> {
        if let Some(p) = &self.progress {
            p.start();
        }

        let mut sessions = Vec::new();

        for auth in auth_list {
            let auth_cmd = match auth {
                Auth::Session(vhandle) => {
                    let session = self
                        .sessions
                        .get(&TpmUint32(*vhandle))
                        .ok_or(CommandError::HandleNotFound(TpmUint32(*vhandle)))?;
                    let nonce_size = TpmHash::from(session.hash_alg()).size();
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
        auth_map: &HashMap<TpmHandle, Auth>,
    ) -> Result<(), CommandError> {
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
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    /// Converts an ephemeral list of TPM policy commands into a storable vTPM policy.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] if reading a public area, computing a name, or
    /// creating a vTPM policy command fails.
    pub(crate) fn save_policy(
        &self,
        device: &mut TpmDevice,
        commands: Option<Vec<(TpmCommand, TpmAuthCommands)>>,
    ) -> Result<Option<Vec<Box<dyn VtpmPolicyCommand>>>, CommandError> {
        let Some(commands) = commands else {
            return Ok(None);
        };

        let mut vtpm_policy = Vec::with_capacity(commands.len());
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

        Ok(Some(vtpm_policy))
    }

    fn load_policy(
        &mut self,
        device: &mut TpmDevice,
        policy: &[Box<dyn VtpmPolicyCommand>],
        auth_map: &HashMap<TpmHandle, Auth>,
    ) -> Result<Option<TpmCommandList>, CommandError> {
        if policy.is_empty() {
            return Ok(None);
        }

        let mut commands = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            let (cmd, auth) = if vtpm_cmd.cc() == TpmCc::PolicySecret {
                self.load_policy_secret(device, vtpm_cmd.as_ref(), auth_map)?
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
        auth_map: &HashMap<TpmHandle, Auth>,
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

fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, CommandError> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(|_| CommandError::OutOfMemory)?,
    })
}
