// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::OutputEncoding,
    convert::from_tpm_object_to_vec,
    device::{Device, DeviceError},
    handle::{Handle, HandleClass},
    key::{KeyError, TpmKey},
    session_cache::SessionError,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    num::TryFromIntError,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tpm2_protocol::{
    data::{Tpm2bPublic, TpmHt, TpmRc, TpmRcBase, TpmsContext},
    TpmBuild, TpmError, TpmHandle, TpmParse, TpmSized, TpmWriter,
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
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmError> {
        self.public.build(writer)?;
        self.context.build(writer)
    }
}

impl TpmParse for CacheKey {
    fn parse(buffer: &[u8]) -> Result<(Self, &[u8]), TpmError> {
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
    #[error("invalid parent: {0}")]
    InvalidParent(String),
    #[error("parent not loaded")]
    ParentNotLoaded,
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(#[from] KeyError),
    #[error("session: {0}")]
    Session(#[from] SessionError),
}

impl From<TpmError> for KeyCacheError {
    fn from(err: TpmError) -> Self {
        Self::Device(DeviceError::from(err))
    }
}

pub struct KeyCache<'a> {
    pub handles: HashMap<u32, TpmHandle>,
    pub contexts: HashMap<u32, CacheKey>,
    pub writer: &'a mut dyn Write,
    dirty_contexts: HashSet<u32>,
    cache_dir: &'a PathBuf,
}

impl std::fmt::Debug for KeyCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handles: Vec<String> = self
            .handles
            .values()
            .map(|t| Handle((HandleClass::Tpm, t.0)).to_string())
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
            for vhandle in self.dirty_contexts.drain() {
                if let Some(data) = self.contexts.get(&vhandle) {
                    let path = self.cache_dir.join(format!("{vhandle:08x}.bin"));
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
    pub fn new(
        cache_dir: &'a PathBuf,
        writer: &'a mut dyn Write,
    ) -> Result<KeyCache<'a>, KeyCacheError> {
        let mut new_context = Self {
            handles: HashMap::new(),
            writer,
            contexts: HashMap::new(),
            dirty_contexts: HashSet::new(),
            cache_dir,
        };

        new_context.load_contexts()?;

        Ok(new_context)
    }

    /// Loads all saved contexts from the cache directory, pruning invalid ones.
    fn load_contexts(&mut self) -> Result<(), KeyCacheError> {
        let entries = match fs::read_dir(self.cache_dir) {
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

            let vhandle_mso = (vhandle >> 24) as u8;
            if vhandle_mso == TpmHt::Transient as u8 {
                let content = fs::read(&path)?;
                let (key, remainder) = CacheKey::parse(&content)?;
                if !remainder.is_empty() {
                    log::warn!("trailing data");
                }
                self.contexts.insert(vhandle, key);
            } else {
                log::debug!("skip: {vhandle}");
            }
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
            let path = self.cache_dir.join(format!("{vhandle:08x}.bin"));
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
        self.cache_dir
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
        handle: &Handle,
    ) -> Result<TpmHandle, KeyCacheError> {
        self.load_context(device, handle)
    }

    /// Loads a TPM context from a handle.
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
        handle: &Handle,
    ) -> Result<TpmHandle, KeyCacheError> {
        match handle.class() {
            HandleClass::Tpm => Ok(TpmHandle(handle.value())),
            HandleClass::Vtpm => {
                let vhandle = handle.value();
                let key = self
                    .contexts
                    .get(&vhandle)
                    .ok_or(KeyCacheError::ContextNotFound(vhandle))?
                    .clone();
                match device.load_context(key.context) {
                    Ok(loaded_handle_val) => {
                        let loaded_handle = TpmHandle(loaded_handle_val);
                        let (_, _) = device.read_public(loaded_handle)?;
                        self.track(loaded_handle)?;
                        Ok(loaded_handle)
                    }
                    Err(DeviceError::TpmRc(rc)) => {
                        let base = match rc {
                            TpmRc::Fmt0(base) | TpmRc::Warn(base) => base,
                            TpmRc::Fmt1(fmt1) => fmt1.base,
                        };
                        if base == TpmRcBase::ReferenceH0 {
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            self.remove_context(vhandle)?;
                            Err(KeyCacheError::ContextNotFound(vhandle))
                        } else if base == TpmRcBase::Handle {
                            Err(KeyCacheError::ParentNotLoaded)
                        } else {
                            Err(DeviceError::TpmRc(rc).into())
                        }
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    /// Tracks a transient handle for automatic cleanup at the end of execution.
    ///
    /// # Errors
    ///
    /// Returns a `KeyCacheError` if the handle is invalid or does not exist.
    pub fn track(&mut self, handle: TpmHandle) -> Result<(), KeyCacheError> {
        if self.handles.contains_key(&handle.0) {
            return Err(KeyCacheError::AlreadyTracked(handle));
        }
        self.handles.insert(handle.0, handle);
        Ok(())
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
            if let Err(err) = device.flush_context(handle) {
                log::error!("{handle}: {err}");
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
        output_path: Option<&Path>,
        key: &TpmKey,
        encoding: OutputEncoding,
    ) -> Result<(), KeyCacheError> {
        let output_bytes = match encoding {
            OutputEncoding::Der => key.to_der()?,
            OutputEncoding::Pem => key.to_pem()?.into_bytes(),
        };

        self.write_data(output_path, &output_bytes)
    }

    /// Writes data to a file path or stdout.
    ///
    /// # Errors
    ///
    /// This function will return an error if writing to a file fails.
    pub fn write_data(
        &mut self,
        output_path: Option<&Path>,
        data: &[u8],
    ) -> Result<(), KeyCacheError> {
        if let Some(path) = output_path {
            if path.to_str() == Some("-") {
                self.writer.write_all(data)?;
            } else {
                std::fs::write(path, data)?;
                writeln!(self.writer, "file:{}", path.to_string_lossy())?;
            }
        } else {
            self.writer.write_all(data)?;
        }
        Ok(())
    }
}
