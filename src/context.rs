// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages the execution context, including sessions and transient object handles.
//!
//! ## Design Invariants
//!
//! To ensure predictable failure modes (i.e., failing on capacity limits rather
//! than opaque I/O errors from the TPM), this module upholds the invariant that
//! all created transient object handles must be tracked by a `Context` object.
//!
//! This makes the `Context` the sole owner of all temporary resources, which are
//! guaranteed to be flushed at the end of the context's lifecycle.

use crate::{
    convert::from_tpm_object_to_vec,
    crypto::crypto_digest,
    device::{Auth, Device, DeviceError, TpmCommandObject},
    key::{AnyKey, KeyError, TpmKey},
    session::SessionCache,
    uri::{Uri, UriError},
};

use std::{
    cell::RefCell,
    cmp,
    collections::{HashMap, HashSet},
    fmt, fs,
    io::Write,
    num::TryFromIntError,
    path::{Path, PathBuf},
    rc::Rc,
};

use thiserror::Error;
use tpm2_protocol::{
    data::{Tpm2bName, TpmAlgId, TpmCc, TpmHt, TpmRcBase, TpmRh, TpmaNv, TpmsContext, TpmtPublic},
    message::{
        TpmAuthResponses, TpmEvictControlCommand, TpmFlushContextCommand, TpmNvReadCommand,
        TpmNvReadPublicCommand, TpmResponseBody,
    },
    TpmErrorKind, TpmHandle, TpmParse,
};

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("already tracked: {0}")]
    AlreadyTracked(TpmHandle),
    #[error("context not found: {0}")]
    ContextNotFound(String),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("invalid handle: {0:08x}")]
    InvalidHandle(u32),
    #[error("invalid parent URI: must be a tpm: or key: URI")]
    InvalidParentUri,
    #[error("invalid URI: {0}")]
    InvalidUri(UriError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(#[from] KeyError),
    #[error("not tracked: {0}")]
    NotTracked(TpmHandle),
    #[error("parent not loaded")]
    ParentNotLoaded,
    #[error("session: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("unknown handle: {0:08x}")]
    UnknownHandle(u32),
    #[error("uri: {0}")]
    Uri(#[from] UriError),
}

impl From<TpmErrorKind> for ContextError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Device(DeviceError::from(err))
    }
}

impl From<TryFromIntError> for ContextError {
    fn from(err: TryFromIntError) -> Self {
        Self::Device(err.into())
    }
}

pub struct ContextCache<'a> {
    pub handles: HashMap<u32, TpmHandle>,
    pub writer: &'a mut dyn Write,
    pub contexts: HashMap<String, Vec<u8>>,
    dirty_contexts: HashSet<String>,
    contexts_dir: PathBuf,
    pub session_map: SessionCache,
}

impl std::fmt::Debug for ContextCache<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let handles: Vec<String> = self
            .handles
            .values()
            .map(|t| Uri::Tpm(t.0).to_string())
            .collect();
        f.debug_struct("Context")
            .field("handles", &handles)
            .field("contexts", &self.contexts.keys())
            .field("writer", &"<dyn Write>")
            .finish()
    }
}

/// A RAII guard for a loaded TPM context handle, ensuring it's flushed on drop.
pub struct Context {
    pub device: Rc<RefCell<Device>>,
    pub handle: TpmHandle,
    pub grip: String,
    pub public: TpmtPublic,
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Ok(mut device) = self.device.try_borrow_mut() {
            if let Err(e) = device.flush_context(self.handle.0) {
                log::warn!(
                    "Failed to flush context for handle {:08x}: {e}",
                    self.handle
                );
            }
        } else {
            log::error!(
                "Could not borrow device to flush context handle {}",
                self.handle
            );
        }
    }
}

/// An iterator over the live, loaded contexts from the context store.
pub struct ContextIterator<'a> {
    device: Rc<RefCell<Device>>,
    context_keys: Vec<String>,
    contexts_map: &'a HashMap<String, Vec<u8>>,
}

/// The item yielded by the `ContextIterator`.
pub enum ContextItem {
    /// A successfully loaded context, guarded by a RAII struct.
    Loaded(Box<Context>),
    /// The grip of a context that was found to be stale and should be removed.
    Stale(String),
}

impl Iterator for ContextIterator<'_> {
    type Item = Result<ContextItem, DeviceError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(grip) = self.context_keys.pop() {
            let Some(context_blob) = self.contexts_map.get(&grip) else {
                continue;
            };

            let context_struct = match TpmsContext::parse(context_blob) {
                Ok((cs, _)) => cs,
                Err(e) => {
                    log::warn!("Failed to parse context for grip {grip}: {e}");
                    continue;
                }
            };

            let mut device = self.device.borrow_mut();
            let live_handle = match device.load_context(context_struct) {
                Ok(h) => h,
                Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                    return Some(Ok(ContextItem::Stale(grip)));
                }
                Err(e) => {
                    log::warn!("Skipping unloadable context {grip}: {e}");
                    continue;
                }
            };

            let public = match device.read_public(live_handle.into()) {
                Ok((p, _)) => p,
                Err(e) => {
                    log::warn!("Failed to read public area for context {grip}: {e}");
                    if let Err(flush_err) = device.flush_context(live_handle) {
                        log::error!(
                            "Failed to flush context after read_public failed: {flush_err}"
                        );
                    }
                    continue;
                }
            };

            return Some(Ok(ContextItem::Loaded(Box::new(Context {
                device: self.device.clone(),
                handle: live_handle.into(),
                grip,
                public,
            }))));
        }
        None
    }
}

impl<'a> ContextCache<'a> {
    /// Flushes transient handles and saves dirty contexts, printing errors to stderr.
    pub fn teardown(&mut self, device: Option<Rc<RefCell<Device>>>) {
        if let Err(e) = self.save_contexts() {
            eprintln!("teardown: {e:#}");
        }
        if let Err(e) = self.session_map.save() {
            eprintln!("teardown: {e:#}");
        }
        if let Some(device_rc) = device {
            match device_rc.try_borrow_mut() {
                Ok(mut device_guard) => {
                    if let Err(e) = self.flush(&mut device_guard) {
                        eprintln!("teardown: {e:#}");
                    }
                }
                Err(e) => {
                    eprintln!("teardown: {e:#}");
                }
            }
        }
    }

    /// Executes a TPM command with full authorization session handling.
    ///
    /// This function encapsulates the prepare, build, execute, and teardown
    /// sequence for authorized commands.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if any stage of the session management or
    /// command execution fails.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        device: &mut Device,
        command: &C,
        handles: &[u32],
        auths: &[Auth],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), ContextError> {
        let activated_handles = self.session_map.prepare_sessions(device, auths)?;

        for &handle in &activated_handles {
            self.track(TpmHandle(handle))?;
        }

        let (sessions, session_handles) = self
            .session_map
            .build_auth_area(device, command, handles, auths)?;

        let (resp, auth_responses) = device.execute(command, &sessions)?;

        self.session_map
            .teardown_sessions(device, &session_handles, &auth_responses)?;

        for handle in activated_handles {
            self.untrack(handle);
        }

        Ok((resp, auth_responses))
    }

    /// Creates a new `Context`, loads and refreshes saved contexts from disk.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if loading or refreshing contexts fails.
    pub fn new(
        device: Option<&mut Device>,
        cache_dir: &Path,
        writer: &'a mut dyn Write,
        session_map: SessionCache,
    ) -> Result<ContextCache<'a>, ContextError> {
        let contexts_dir = cache_dir.join("contexts");
        let mut new_context = Self {
            handles: HashMap::new(),
            writer,
            contexts: HashMap::new(),
            dirty_contexts: HashSet::new(),
            contexts_dir,
            session_map,
        };

        new_context.load_contexts()?;

        if let Some(dev) = device {
            new_context.refresh_contexts(dev)?;
        }

        Ok(new_context)
    }

    /// Creates an iterator that loads each saved context and yields a `Context` guard.
    pub fn loaded_contexts(&self, device: Rc<RefCell<Device>>) -> ContextIterator<'_> {
        let keys = self.contexts.keys().cloned().collect();
        ContextIterator {
            device,
            context_keys: keys,
            contexts_map: &self.contexts,
        }
    }

    /// Loads all saved contexts from the cache directory, pruning invalid ones.
    fn load_contexts(&mut self) -> Result<(), ContextError> {
        fs::create_dir_all(&self.contexts_dir)?;
        let entries = match fs::read_dir(&self.contexts_dir) {
            Ok(entries) => entries.filter_map(Result::ok),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        for entry in entries {
            let path = entry.path();
            if path.is_file() {
                if let Some(grip) = path.file_stem().and_then(|s| s.to_str()) {
                    if grip.len() == 16 && grip.chars().all(|c| c.is_ascii_hexdigit()) {
                        let content = fs::read(&path)?;
                        self.contexts.insert(grip.to_string(), content);
                    } else {
                        log::trace!(
                            "Pruning invalid or outdated context file: {}",
                            path.display()
                        );
                        fs::remove_file(path)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Saves all dirty contexts back to the cache directory.
    fn save_contexts(&mut self) -> Result<(), ContextError> {
        if self.dirty_contexts.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(&self.contexts_dir)?;
        for grip in self.dirty_contexts.drain() {
            if let Some(data) = self.contexts.get(&grip) {
                let path = self.contexts_dir.join(&grip);
                fs::write(path, data)?;
            }
        }
        Ok(())
    }

    /// Removes a context from the cache.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the context file cannot be removed from disk.
    pub fn remove_context(&mut self, grip: &str) -> Result<(), ContextError> {
        if self.contexts.remove(grip).is_some() {
            let path = self.contexts_dir.join(grip);
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    /// Deletes all cached contexts from disk and memory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if any context file cannot be removed.
    pub fn reset(&mut self) -> Result<(), ContextError> {
        let paths_to_delete: Vec<_> = self
            .contexts
            .keys()
            .map(|grip| self.contexts_dir.join(grip))
            .collect();
        for path in paths_to_delete {
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
        }
        self.contexts.clear();
        self.dirty_contexts.clear();
        Ok(())
    }

    /// Refreshes all contexts, pruning stale ones.
    fn refresh_contexts(&mut self, device: &mut Device) -> Result<(), ContextError> {
        let grips_to_refresh: Vec<String> = self.contexts.keys().cloned().collect();
        for grip in grips_to_refresh {
            let context_blob = match self.contexts.get(&grip) {
                Some(blob) => blob.clone(),
                None => continue,
            };

            let (context_struct, _) = TpmsContext::parse(&context_blob)?;

            match device.load_context(context_struct) {
                Ok(live_handle) => {
                    let new_context_struct = device.save_context(live_handle)?;
                    device.flush_context(live_handle)?;

                    let new_context_blob = from_tpm_object_to_vec(&new_context_struct)?;

                    self.contexts.insert(grip.clone(), new_context_blob);
                    self.dirty_contexts.insert(grip);
                }
                Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                    self.remove_context(&grip)?;
                }
                Err(e) => {
                    log::warn!("key:{grip}: {e}");
                    self.remove_context(&grip)?;
                }
            }
        }
        Ok(())
    }

    /// Creates and saves a new managed transient context.
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM context cannot be saved or if the new context
    /// cannot be written to the writer.
    pub fn new_context(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        name: &Tpm2bName,
    ) -> Result<(), ContextError> {
        let context_struct = device.save_context(handle.0)?;
        let context_bytes = from_tpm_object_to_vec(&context_struct)?;
        let digest = crypto_digest(TpmAlgId::Sha256, &[name.as_ref()])?;
        let grip = hex::encode(&digest[..8]);

        self.contexts.insert(grip.clone(), context_bytes);
        self.dirty_contexts.insert(grip.clone());

        writeln!(self.writer, "key:{grip}")?;
        Ok(())
    }

    /// Marks a saved context as needing to be written to disk.
    pub fn mark_dirty(&mut self, grip: String) {
        self.dirty_contexts.insert(grip);
    }

    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.contexts_dir
    }

    /// Imports an external key under a TPM parent, creating a new `TpmKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM import operation fails.
    pub fn import_key(
        &mut self,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
    ) -> Result<TpmKey, ContextError> {
        let external_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(_) => return Err(ContextError::Key(KeyError::InvalidFormat)),
            AnyKey::External(key) => key,
        };

        let mut rng = rand::thread_rng();
        let handles = [parent_handle.0];

        self.session_map.prepare_sessions(device, auths)?;
        Ok(TpmKey::from_external_key(
            device,
            parent_handle,
            &external_key,
            &mut rng,
            &handles,
            auths,
            self,
        )?)
    }

    /// Loads a TPM context from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` on parsing or TPM command failure.
    pub fn load_context_from_bytes(
        &mut self,
        device: &mut Device,
        blob: &[u8],
    ) -> Result<(TpmHandle, Tpm2bName), ContextError> {
        let (context, _) = TpmsContext::parse(blob)?;
        match device.load_context(context) {
            Ok(handle) => {
                let handle = TpmHandle(handle);
                let (_, name) = device.read_public(handle)?;
                device.add_name_to_cache(handle.0, name);
                self.track(handle)?;
                Ok((handle, name))
            }
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::Handle => {
                Err(ContextError::ParentNotLoaded)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Validates a URI for a parent object and loads its context.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is not a valid parent type (`tpm:` or `key:`)
    /// or if context loading fails.
    pub fn load_parent(
        &mut self,
        device: &mut Device,
        uri: &Uri,
    ) -> Result<TpmHandle, ContextError> {
        if matches!(uri, Uri::Path(_) | Uri::Password(_)) {
            return Err(ContextError::InvalidParentUri);
        }
        self.load_context(device, uri)
    }

    /// Loads a TPM context from a URI.
    ///
    /// If the URI points to a transient context, the context is loaded into the
    /// TPM and its handle is tracked for automatic cleanup. Persistent handles
    /// from `tpm:` URIs are returned directly and are not tracked.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` on parsing or TPM command failure.
    pub fn load_context(
        &mut self,
        device: &mut Device,
        uri: &Uri,
    ) -> Result<TpmHandle, ContextError> {
        match uri {
            Uri::Tpm(handle) => Ok(TpmHandle(*handle)),
            Uri::Context(grip) => {
                let context_blob = self
                    .contexts
                    .get(grip)
                    .ok_or_else(|| ContextError::ContextNotFound(grip.clone()))?
                    .clone();
                self.load_context_from_bytes(device, &context_blob)
                    .map(|(handle, _)| handle)
            }
            Uri::Path(_) => {
                let context_blob = uri.to_bytes()?;
                self.load_context_from_bytes(device, &context_blob)
                    .map(|(handle, _)| handle)
            }
            Uri::Password(_) | Uri::Session(_) => {
                Err(ContextError::InvalidUri(UriError::InvalidUriType))
            }
        }
    }

    /// Deletes a persistent or transient object by URI.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is invalid or the delete operation fails.
    pub fn delete(
        &mut self,
        device: &mut Device,
        uri: &Uri,
        auths: &[Auth],
    ) -> Result<u32, ContextError> {
        let handle = self.load_context(device, uri)?.0;

        let mso = (handle >> 24) as u8;
        let result = match TpmHt::try_from(mso) {
            Ok(TpmHt::Persistent) => self.delete_persistent(device, TpmHandle(handle), auths),
            Ok(TpmHt::Transient) => self.delete_transient(device, TpmHandle(handle)),
            Ok(TpmHt::HmacSession | TpmHt::PolicySession) => {
                let cmd = TpmFlushContextCommand {
                    flush_handle: handle.into(),
                };
                let sessions = vec![];
                device.execute(&cmd, &sessions)?;
                self.handles.remove(&handle);
                Ok(())
            }
            _ => return Err(ContextError::InvalidHandle(handle)),
        };

        match result {
            Ok(()) => Ok(handle),
            Err(ContextError::Device(DeviceError::TpmRc(rc))) if rc.base() == TpmRcBase::Handle => {
                Err(ContextError::UnknownHandle(handle))
            }
            Err(e) => Err(e),
        }
    }

    /// Tracks a transient handle for automatic cleanup at the end of execution.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is invalid or does not exist.
    pub fn track(&mut self, handle: TpmHandle) -> Result<(), ContextError> {
        self.non_existence_invariant(handle)?;

        let mso = (handle.0 >> 24) as u8;
        match TpmHt::try_from(mso) {
            Ok(TpmHt::Transient | TpmHt::HmacSession | TpmHt::PolicySession) => {
                self.handles.insert(handle.0, handle);
                Ok(())
            }
            _ => Err(ContextError::InvalidHandle(handle.0)),
        }
    }

    /// Removes a handle from the automatic cleanup list.
    pub fn untrack(&mut self, handle: u32) {
        self.handles.remove(&handle);
    }

    /// Flushes all tracked transient handles out of the TPM device.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the device mutex is poisoned or if flushing a
    /// handle fails. It returns the first error encountered.
    pub fn flush(&mut self, device: &mut Device) -> Result<(), ContextError> {
        let handles_to_flush: Vec<TpmHandle> = self.handles.drain().map(|(_, v)| v).collect();

        for handle in handles_to_flush {
            let cmd = TpmFlushContextCommand {
                flush_handle: handle,
            };
            let sessions = vec![];
            if let Err(err) = device.execute(&cmd, &sessions) {
                let uri = Uri::Tpm(handle.0);
                log::error!("{uri}: {err}");
            }
        }

        Ok(())
    }

    /// Handles the output of a `TpmKey`, choosing PEM or DER format based on the URI.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` on failure.
    pub fn write_key_data(
        &mut self,
        output_uri: Option<&Uri>,
        key: &TpmKey,
    ) -> Result<(), ContextError> {
        let output_is_der = if let Some(Uri::Path(path_str)) = output_uri {
            Path::new(path_str)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                == Some("der")
        } else {
            false
        };

        let output_bytes = if output_is_der {
            key.to_der()?
        } else {
            key.to_pem()?.into_bytes()
        };

        self.write_data(output_uri, &output_bytes)
    }

    /// Writes data to a file path or stdout.
    ///
    /// # Errors
    ///
    /// This function will return an error if writing to a file fails.
    pub fn write_data(
        &mut self,
        output_uri: Option<&Uri>,
        data: &[u8],
    ) -> Result<(), ContextError> {
        if let Some(uri) = output_uri {
            match uri {
                Uri::Path(path) => {
                    std::fs::write(path, data)?;
                    writeln!(self.writer, "{uri}")?;
                }
                _ => return Err(ContextError::InvalidUri(UriError::InvalidUriType)),
            }
        } else {
            self.writer.write_all(data)?;
        }
        Ok(())
    }

    /// Reads a certificate from a given NV index.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the TPM commands fail or if the response is invalid.
    pub fn read_certificate(
        &mut self,
        device: &mut Device,
        auths: &[Auth],
        handle: u32,
        max_read_size: usize,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let nv_read_public_cmd = TpmNvReadPublicCommand {
            nv_index: handle.into(),
        };
        let (resp, _) = device.execute(&nv_read_public_cmd, &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size as usize;

        if data_size == 0 {
            return Ok(None);
        }

        let auth_handle = if nv_public.attributes.contains(TpmaNv::AUTHREAD) {
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
            let chunk_size = cmp::min(max_read_size, data_size - offset);

            let nv_read_cmd = TpmNvReadCommand {
                auth_handle: auth_handle.into(),
                nv_index: handle.into(),
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
            };

            let (resp, _) = self.execute(device, &nv_read_cmd, &[auth_handle], auths)?;

            let read_resp = resp
                .NvRead()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::NvRead))?;
            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += chunk_size;
        }

        Ok(Some(cert_bytes))
    }

    fn delete_persistent(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        auths: &[Auth],
    ) -> Result<(), ContextError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };
        let handles = [auth_handle as u32, handle.0];

        let (resp, _) = self.execute(device, &cmd, &handles, auths)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    fn delete_transient(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
    ) -> Result<(), ContextError> {
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
        };
        let sessions = vec![];
        let (_, _) = device.execute(&cmd, &sessions)?;
        self.handles.remove(&handle.0);
        Ok(())
    }

    /// Makes a transient key persistent.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the transient handle is not being tracked by
    /// the context, or if the underlying `TPM2_EvictControl` command fails.
    pub fn evict_key(
        &mut self,
        device: &mut Device,
        transient_handle: TpmHandle,
        persistent_handle: TpmHandle,
        auths: &[Auth],
    ) -> Result<(), ContextError> {
        self.existence_invariant(transient_handle)?;
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: transient_handle.0.into(),
            persistent_handle,
        };
        let handles = [auth_handle as u32, transient_handle.0];

        let (resp, _) = self.execute(device, &cmd, &handles, auths)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        self.handles.remove(&transient_handle.0);
        Ok(())
    }

    fn existence_invariant(&self, handle: TpmHandle) -> Result<(), ContextError> {
        if self.handles.contains_key(&handle.0) {
            Ok(())
        } else {
            Err(ContextError::NotTracked(handle))
        }
    }

    fn non_existence_invariant(&self, handle: TpmHandle) -> Result<(), ContextError> {
        if self.handles.contains_key(&handle.0) {
            Err(ContextError::AlreadyTracked(handle))
        } else {
            Ok(())
        }
    }
}
