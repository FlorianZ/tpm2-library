// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{CommandError, OutputEncoding},
    convert::from_tpm_object_to_vec,
    crypto::crypto_digest,
    device::{Device, DeviceError},
    key::{KeyError, TpmKey},
    uri::{Uri, UriError},
};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    io::Write,
    num::TryFromIntError,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bName, Tpm2bPublic, TpmAlgId, TpmHt, TpmRcBase, TpmsContext},
    message::TpmFlushContextCommand,
    TpmBuffer, TpmBuild, TpmErrorKind, TpmHandle, TpmParse, TpmSized, TpmWriter,
};

#[derive(Debug, Clone)]
pub struct CacheKey {
    pub public: Vec<u8>,
    pub context: TpmsContext,
}

impl TpmSized for CacheKey {
    const SIZE: usize = 0;
    fn len(&self) -> usize {
        2 + self.public.len() + self.context.len()
    }
}

impl TpmBuild for CacheKey {
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmErrorKind> {
        let public_buf = TpmBuffer::<TPM_MAX_COMMAND_SIZE>::try_from(self.public.as_slice())?;
        public_buf.build(writer)?;
        self.context.build(writer)
    }
}

impl TpmParse for CacheKey {
    fn parse(buffer: &[u8]) -> Result<(Self, &[u8]), TpmErrorKind> {
        let (public_buf, remainder) = TpmBuffer::<TPM_MAX_COMMAND_SIZE>::parse(buffer)?;
        let (context, remainder) = TpmsContext::parse(remainder)?;
        let new_self = Self {
            public: public_buf.to_vec(),
            context,
        };
        Ok((new_self, remainder))
    }
}

#[derive(Debug, Error)]
pub enum KeyCacheError {
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
    #[error("invalid parent: {0}")]
    InvalidParent(String),
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

impl From<TpmErrorKind> for KeyCacheError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Device(DeviceError::from(err))
    }
}

impl From<TryFromIntError> for KeyCacheError {
    fn from(err: TryFromIntError) -> Self {
        Self::Device(err.into())
    }
}

impl From<CommandError> for KeyCacheError {
    fn from(err: CommandError) -> Self {
        match err {
            CommandError::KeyCacheError(e) => e,
            CommandError::Crypto(e) => Self::Crypto(e),
            CommandError::Device(e) => Self::Device(e),
            CommandError::Io(e) => Self::Io(e),
            CommandError::Key(e) => Self::Key(e),
            CommandError::Session(e) => Self::Session(e),
            CommandError::Uri(e) => Self::Uri(e),
            _ => Self::Key(KeyError::ValueConversionFailed(err.to_string())),
        }
    }
}

pub struct KeyCache<'a> {
    pub handles: HashMap<u32, TpmHandle>,
    pub writer: &'a mut dyn Write,
    pub contexts: HashMap<String, CacheKey>,
    dirty_contexts: HashSet<String>,
    contexts_dir: PathBuf,
}

impl std::fmt::Debug for KeyCache<'_> {
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

impl<'a> KeyCache<'a> {
    /// Flushes transient handles and saves dirty contexts, logging errors.
    pub fn teardown(&mut self, device: Option<std::rc::Rc<std::cell::RefCell<Device>>>) {
        if !self.dirty_contexts.is_empty() {
            if let Err(e) = fs::create_dir_all(&self.contexts_dir) {
                log::error!("teardown: {e:#}");
            }
            for grip in self.dirty_contexts.drain() {
                if let Some(data) = self.contexts.get(&grip) {
                    let path = self.contexts_dir.join(&grip);
                    match from_tpm_object_to_vec(data) {
                        Ok(bytes) => {
                            if let Err(e) = fs::write(path, bytes) {
                                log::error!("teardown: {grip}: {e:#}");
                            }
                        }
                        Err(e) => {
                            log::error!("teardown: {grip}: {e:#}");
                        }
                    }
                }
            }
        }

        if let Some(device_rc) = device {
            match device_rc.try_borrow_mut() {
                Ok(mut device_guard) => {
                    if let Err(e) = self.flush(&mut device_guard) {
                        log::error!("teardown: {e:#}");
                    }
                }
                Err(e) => {
                    log::error!("teardown: {e:#}");
                }
            }
        }
    }

    /// Creates a new `Context`, loads and refreshes saved contexts from disk.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` if loading or refreshing contexts fails.
    pub fn new(
        device: Option<&mut Device>,
        cache_dir: &Path,
        writer: &'a mut dyn Write,
    ) -> Result<KeyCache<'a>, KeyCacheError> {
        let contexts_dir = cache_dir.join("contexts");
        let mut new_context = Self {
            handles: HashMap::new(),
            writer,
            contexts: HashMap::new(),
            dirty_contexts: HashSet::new(),
            contexts_dir,
        };

        new_context.load_contexts()?;

        if let Some(dev) = device {
            new_context.refresh_contexts(dev)?;
        }

        Ok(new_context)
    }

    /// Loads all saved contexts from the cache directory, pruning invalid ones.
    fn load_contexts(&mut self) -> Result<(), KeyCacheError> {
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
                        let (key, remainder) = CacheKey::parse(&content)?;
                        if !remainder.is_empty() {
                            log::trace!(
                                "Pruning invalid or outdated context file: {}",
                                path.display()
                            );
                            fs::remove_file(path)?;
                            continue;
                        }

                        self.contexts.insert(grip.to_string(), key);
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

    /// Removes a context from the cache.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the context file cannot be removed from disk.
    pub fn remove_context(&mut self, grip: &str) -> Result<(), KeyCacheError> {
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
    pub fn reset(&mut self) -> Result<(), KeyCacheError> {
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
    fn refresh_contexts(&mut self, device: &mut Device) -> Result<(), KeyCacheError> {
        let grips_to_refresh: Vec<String> = self.contexts.keys().cloned().collect();
        for grip in grips_to_refresh {
            let key = match self.contexts.get(&grip) {
                Some(cc) => cc.clone(),
                None => continue,
            };

            match device.load_context(key.context) {
                Ok(live_handle) => {
                    let new_context_struct = device.save_context(live_handle)?;
                    device.flush_context(live_handle)?;
                    if let Some(entry) = self.contexts.get_mut(&grip) {
                        entry.context = new_context_struct;
                        self.dirty_contexts.insert(grip);
                    }
                }
                Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                    log::debug!("key:{grip}: is stale");
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
    pub fn save_context(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        public: &Tpm2bPublic,
        name: &Tpm2bName,
    ) -> Result<(), KeyCacheError> {
        let context_struct = device.save_context(handle.0)?;
        let public_bytes = from_tpm_object_to_vec(public)?;
        let key = CacheKey {
            public: public_bytes,
            context: context_struct,
        };
        let digest = crypto_digest(TpmAlgId::Sha256, &[name.as_ref()])?;
        let grip = hex::encode(&digest[..8]);

        self.contexts.insert(grip.clone(), key);
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

    /// Loads a TPM context from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` on parsing or TPM command failure.
    pub fn load_context_from_bytes(
        &mut self,
        device: &mut Device,
        blob: &[u8],
    ) -> Result<(TpmHandle, Tpm2bName), KeyCacheError> {
        let (key, _) = CacheKey::parse(blob)?;
        match device.load_context(key.context) {
            Ok(handle) => {
                let handle = TpmHandle(handle);
                let (_, name) = device.read_public(handle)?;
                self.track(handle)?;
                Ok((handle, name))
            }
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::Handle => {
                Err(KeyCacheError::ParentNotLoaded)
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
    ) -> Result<TpmHandle, KeyCacheError> {
        if matches!(uri, Uri::Key(_)) {
            self.load_context(device, uri)
        } else {
            Err(KeyCacheError::InvalidParent(uri.to_string()))
        }
    }

    /// Loads a TPM context from a URI.
    ///
    /// If the URI points to a transient context, the context is loaded into the
    /// TPM and its handle is tracked for automatic cleanup. Persistent handles
    /// from `tpm:` URIs are returned directly and are not tracked.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` on parsing or TPM command failure.
    pub fn load_context(
        &mut self,
        device: &mut Device,
        uri: &Uri,
    ) -> Result<TpmHandle, KeyCacheError> {
        match uri {
            Uri::Tpm(handle) => Ok(TpmHandle(*handle)),
            Uri::Key(grip) => {
                let key = self
                    .contexts
                    .get(grip)
                    .ok_or_else(|| KeyCacheError::ContextNotFound(grip.clone()))?
                    .clone();
                match device.load_context(key.context) {
                    Ok(handle) => {
                        let handle = TpmHandle(handle);
                        let (_, _) = device.read_public(handle)?;
                        self.track(handle)?;
                        Ok(handle)
                    }
                    Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::Handle => {
                        Err(KeyCacheError::ParentNotLoaded)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Uri::Path(_) => {
                let context_blob = uri.to_bytes()?;
                self.load_context_from_bytes(device, &context_blob)
                    .map(|(handle, _)| handle)
            }
            Uri::Session(_) => Err(KeyCacheError::InvalidUri(UriError::InvalidUriType)),
        }
    }

    /// Tracks a transient handle for automatic cleanup at the end of execution.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` if the handle is invalid or does not exist.
    pub fn track(&mut self, handle: TpmHandle) -> Result<(), KeyCacheError> {
        self.non_existence_invariant(handle)?;

        let mso = (handle.0 >> 24) as u8;
        match TpmHt::try_from(mso) {
            Ok(TpmHt::Transient | TpmHt::HmacSession | TpmHt::PolicySession) => {
                self.handles.insert(handle.0, handle);
                Ok(())
            }
            _ => Err(KeyCacheError::InvalidHandle(handle.0)),
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
    /// Returns `KeyCacheError` if the device mutex is poisoned or if flushing a
    /// handle fails. It returns the first error encountered.
    pub fn flush(&mut self, device: &mut Device) -> Result<(), KeyCacheError> {
        let handles_to_flush: Vec<TpmHandle> = self.handles.drain().map(|(_, v)| v).collect();

        for handle in handles_to_flush {
            let cmd = TpmFlushContextCommand {
                flush_handle: handle,
            };
            let sessions = vec![];
            if let Err(err) = device.execute(&cmd, &sessions) {
                let uri = Uri::Tpm(handle.0);
                log::error!("Failed to flush handle {uri}: {err}");
            }
        }

        Ok(())
    }

    /// Handles the output of a `TpmKey`, choosing PEM or DER format based on the URI.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` on failure.
    pub fn write_key_data(
        &mut self,
        output_uri: Option<&Uri>,
        key: &TpmKey,
        encoding: OutputEncoding,
    ) -> Result<(), KeyCacheError> {
        let output_bytes = match encoding {
            OutputEncoding::Der => key.to_der()?,
            OutputEncoding::Pem => key.to_pem()?.into_bytes(),
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
    ) -> Result<(), KeyCacheError> {
        if let Some(uri) = output_uri {
            match uri {
                Uri::Path(path) => {
                    if path.to_str() == Some("-") {
                        self.writer.write_all(data)?;
                    } else {
                        std::fs::write(path, data)?;
                        writeln!(self.writer, "{uri}")?;
                    }
                }
                _ => return Err(KeyCacheError::InvalidUri(UriError::InvalidUriType)),
            }
        } else {
            self.writer.write_all(data)?;
        }
        Ok(())
    }

    fn non_existence_invariant(&self, handle: TpmHandle) -> Result<(), KeyCacheError> {
        if self.handles.contains_key(&handle.0) {
            Err(KeyCacheError::AlreadyTracked(handle))
        } else {
            Ok(())
        }
    }
}
