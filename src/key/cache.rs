// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{CommandError, OutputEncoding},
    convert::from_tpm_object_to_vec,
    device::{Device, DeviceError},
    key::{KeyError, TpmKey},
    scheme::{Scheme, SchemeError},
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
    data::{Tpm2bPublic, TpmHt, TpmRcBase, TpmsContext},
    message::TpmFlushContextCommand,
    TpmBuild, TpmErrorKind, TpmHandle, TpmParse, TpmSized, TpmWriter,
};

#[derive(Debug, Clone)]
pub struct CacheKey {
    pub public: Tpm2bPublic,
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
        self.public.build(writer)?;
        self.context.build(writer)
    }
}

impl TpmParse for CacheKey {
    fn parse(buffer: &[u8]) -> Result<(Self, &[u8]), TpmErrorKind> {
        let (public, remainder) = Tpm2bPublic::parse(buffer)?;
        let (context, remainder) = TpmsContext::parse(remainder)?;
        let new_self = Self { public, context };
        Ok((new_self, remainder))
    }
}

#[derive(Debug, Error)]
pub enum KeyCacheError {
    #[error("already tracked: {0}")]
    AlreadyTracked(TpmHandle),
    #[error("context not found: {0:08x}")]
    ContextNotFound(u32),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("invalid handle: {0:08x}")]
    InvalidHandle(u32),
    #[error("invalid parent: {0}")]
    InvalidParent(String),
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] SchemeError),
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
            CommandError::Uri(e) => Self::InvalidUri(e),
            _ => Self::Key(KeyError::ValueConversionFailed(err.to_string())),
        }
    }
}

pub struct KeyCache<'a> {
    pub handles: HashMap<u32, TpmHandle>,
    pub contexts: HashMap<u32, CacheKey>,
    pub writer: &'a mut dyn Write,
    dirty_contexts: HashSet<u32>,
    contexts_dir: PathBuf,
}

impl std::fmt::Debug for KeyCache<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let handles: Vec<String> = self
            .handles
            .values()
            .map(|t| Scheme::Tpm(t.0).to_string())
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
            for vhandle in self.dirty_contexts.drain() {
                if let Some(data) = self.contexts.get(&vhandle) {
                    let path = self.contexts_dir.join(format!("{vhandle:08x}.bin"));
                    match from_tpm_object_to_vec(data) {
                        Ok(bytes) => {
                            if let Err(e) = fs::write(path, bytes) {
                                log::error!("teardown: {vhandle}: {e:#}");
                            }
                        }
                        Err(e) => {
                            log::error!("teardown: {vhandle}: {e:#}");
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
    pub fn new(cache_dir: &Path, writer: &'a mut dyn Write) -> Result<KeyCache<'a>, KeyCacheError> {
        let contexts_dir = cache_dir.join("contexts");
        let mut new_context = Self {
            handles: HashMap::new(),
            writer,
            contexts: HashMap::new(),
            dirty_contexts: HashSet::new(),
            contexts_dir,
        };

        new_context.load_contexts()?;

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

            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                let _ = std::fs::remove_file(path);
                continue;
            }

            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                let _ = std::fs::remove_file(path);
                continue;
            };

            let Ok(vhandle) = u32::from_str_radix(stem, 16) else {
                let _ = std::fs::remove_file(path);
                continue;
            };

            let content = fs::read(&path)?;
            let (key, remainder) = CacheKey::parse(&content)?;

            if !remainder.is_empty() {
                let _ = std::fs::remove_file(path);
                continue;
            }

            self.contexts.insert(vhandle, key);
        }
        Ok(())
    }

    /// Removes a context from the cache.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the context file cannot be removed from disk.
    pub fn remove_context(&mut self, vhandle: u32) -> Result<(), KeyCacheError> {
        if self.contexts.remove(&vhandle).is_some() {
            let path = self.contexts_dir.join(format!("{vhandle:08x}.bin"));
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
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
    ) -> Result<(), KeyCacheError> {
        let public = public.clone();
        let context = device.save_context(handle.0)?;
        for vhandle in 0x8000_0000u32..=0x80FF_FFFF {
            if let std::collections::hash_map::Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let key = CacheKey {
                    public: public.clone(),
                    context: context.clone(),
                };
                e.insert(key.clone());
                self.dirty_contexts.insert(vhandle);
                writeln!(self.writer, "vtpm:{vhandle:08x}")?;
                break;
            }
        }
        Ok(())
    }

    /// Marks a saved context as needing to be written to disk.
    pub fn mark_dirty(&mut self, vhandle: u32) {
        self.dirty_contexts.insert(vhandle);
    }

    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.contexts_dir
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
        uri: &Scheme,
    ) -> Result<TpmHandle, KeyCacheError> {
        match uri {
            Scheme::Transient(_) => self.load_context(device, uri),
            Scheme::Tpm(handle) => {
                if (*handle >> 24) as u8 == TpmHt::Persistent as u8 {
                    Ok(TpmHandle(*handle))
                } else {
                    Err(KeyCacheError::InvalidParent(
                        "Parent 'tpm:' handle must be persistent (0x81xxxxxx)".to_string(),
                    ))
                }
            }
            _ => Err(KeyCacheError::InvalidParent(uri.to_string())),
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
        uri: &Scheme,
    ) -> Result<TpmHandle, KeyCacheError> {
        match uri {
            Scheme::Tpm(handle) => Ok(TpmHandle(*handle)),
            Scheme::Transient(vhandle) => {
                let key = self
                    .contexts
                    .get(vhandle)
                    .ok_or(KeyCacheError::ContextNotFound(*vhandle))?
                    .clone();
                match device.load_context(key.context) {
                    Ok(handle) => {
                        let handle = TpmHandle(handle);
                        let (_, _) = device.read_public(handle)?;
                        self.track(handle)?;
                        Ok(handle)
                    }
                    Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                        log::debug!("vtpm:{vhandle} is stale");
                        self.remove_context(*vhandle)?;
                        Err(KeyCacheError::ContextNotFound(*vhandle))
                    }
                    Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::Handle => {
                        Err(KeyCacheError::ParentNotLoaded)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Scheme::Session(_) | Scheme::Password(_) | Scheme::Path(_) | Scheme::Policy(_) => Err(
                KeyCacheError::InvalidUri(SchemeError::UnsupportedScheme(uri.to_string())),
            ),
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
                let uri = Scheme::Tpm(handle.0);
                log::error!("{uri}: {err}");
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
        output_uri: Option<&Scheme>,
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
        output_uri: Option<&Scheme>,
        data: &[u8],
    ) -> Result<(), KeyCacheError> {
        if let Some(uri) = output_uri {
            match uri {
                Scheme::Path(path) => {
                    if path.to_str() == Some("-") {
                        self.writer.write_all(data)?;
                    } else {
                        std::fs::write(path, data)?;
                        writeln!(self.writer, "{uri}")?;
                    }
                    Ok(())
                }
                _ => Err(KeyCacheError::InvalidUri(SchemeError::UnsupportedScheme(
                    uri.to_string(),
                ))),
            }
        } else {
            self.writer.write_all(data)?;
            Ok(())
        }
    }

    fn non_existence_invariant(&self, handle: TpmHandle) -> Result<(), KeyCacheError> {
        if self.handles.contains_key(&handle.0) {
            Err(KeyCacheError::AlreadyTracked(handle))
        } else {
            Ok(())
        }
    }
}
