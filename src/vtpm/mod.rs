// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys and sessions.

use crate::{
    auth::{Auth, AuthClass, AuthError},
    crypto::CryptoError,
    device::{Device, DeviceError},
    handle::HandleError,
    key::Tpm2shAlgId,
};
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap, HashSet},
    fs, io,
    num::TryFromIntError,
    path::Path,
    rc::Rc,
};
use thiserror::Error;
use tpm2_protocol::{
    data::{Tpm2bPublic, TpmHt, TpmRc, TpmtPublic},
    message::TpmAuthResponses,
    TpmError, TpmHandle,
};

mod key;
mod session;

pub use key::*;
pub use session::*;

#[derive(Debug, Error)]
pub enum VtpmError {
    #[error("already tracked: {0}")]
    AlreadyTracked(TpmHandle),
    #[error("handle not found: {0}{1:08x}")]
    HandleNotFound(&'static str, u32),
    #[error("invalid auth")]
    InvalidAuth,
    #[error("invalid key bits: {0}")]
    InvalidKeyBits(String),
    #[error("invalid parent: {0:08x}")]
    InvalidParent(u32),
    #[error("no handles")]
    NoHandles,
    #[error("parent not loaded")]
    ParentNotLoaded,
    #[error("trailing authorizations")]
    TrailingAuthorizations,
    #[error("unsupported name algorithm: {0}")]
    UnsupportedNameAlgorithm(Tpm2shAlgId),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("handle: {0}")]
    Handle(#[from] HandleError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("TPM: {0}")]
    Tpm(TpmError),
}

impl From<TpmError> for VtpmError {
    fn from(err: TpmError) -> Self {
        Self::Device(DeviceError::from(err))
    }
}

impl From<TpmRc> for VtpmError {
    fn from(rc: TpmRc) -> Self {
        Self::Device(DeviceError::TpmRc(rc))
    }
}

/// A VTPM object.
pub trait VtpmContext: 'static {
    /// Immutable cast.
    fn as_any(&self) -> &dyn Any;

    /// Mutable cast.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns the virtual handle of the context.
    fn handle(&self) -> u32;

    /// Returns class string.
    fn class(&self) -> &'static str;

    /// Returns details string.
    fn details(&self) -> String;

    /// Saves the context to a file.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if the context cannot be serialized or written to disk.
    fn save(&self, path: &Path) -> Result<(), VtpmError>;

    /// Deletes the context.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if disk or TPM device operations fail.
    fn delete(&self, device: &mut Device, cache_dir: &Path, vhandle: u32) -> Result<(), VtpmError>;
}

pub struct VtpmCache<'a> {
    pub contexts: HashMap<u32, Box<dyn VtpmContext>>,
    pub handles: HashMap<u32, TpmHandle>,
    dirty: HashSet<u32>,
    cache_dir: &'a Path,
}

impl<'a> VtpmCache<'a> {
    /// Creates a new cache and loads existing contexts from disk.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if loading contexts from the cache directory fails.
    pub fn new(cache_dir: &'a Path) -> Result<Self, VtpmError> {
        let mut cache = Self {
            contexts: HashMap::new(),
            handles: HashMap::new(),
            dirty: HashSet::new(),
            cache_dir,
        };
        cache.load()?;
        Ok(cache)
    }

    fn cache_dir(&self) -> &Path {
        self.cache_dir
    }

    /// Finds a VTPM key corresponding to a `TpmtPublic`,
    #[must_use]
    pub fn find_by_public(&self, public: &TpmtPublic) -> Option<&VtpmKey> {
        self.key_iter()
            .find(|(_, key)| key.public.inner == *public)
            .map(|(_, key)| key)
    }

    /// Finds a VTPM key corresponding to a physical handle.
    ///
    /// Reads the public area of a physical TPM handle and searches the cache
    /// for a loaded key with a matching public area. If found, it returns the
    /// corresponding virtual handle.
    ///
    /// # Errors
    ///
    /// Returns [`ContextNotFound`](crate::vtpm::VtpmError::ContextNotFound)
    /// when context is not found.
    /// Returns [`Device`](crate::vtpm::VtpmError::Device) when
    /// `TPM2_ReadPublic` fails.
    pub fn find_by_phandle(
        &self,
        device: &mut Device,
        phandle: u32,
    ) -> Result<&VtpmKey, VtpmError> {
        let (public, _) = device.read_public(phandle.into())?;
        self.find_by_public(&public)
            .ok_or(VtpmError::HandleNotFound("tpm:", phandle))
    }

    /// Finds a VTPM key corresponding to a virtual handle.
    ///
    /// Reads the public area of a physical TPM handle and searches the cache
    /// for a loaded key with a matching public area. If found, it returns the
    /// corresponding virtual handle.
    ///
    /// # Errors
    ///
    /// Returns [`ContextNotFound`](crate::vtpm::VtpmError::ContextNotFound)
    /// when context is not found.
    pub fn find_by_vhandle(&self, vhandle: u32) -> Result<&VtpmKey, VtpmError> {
        self.key_iter()
            .find(|(h, _)| **h == vhandle)
            .map(|(_, key)| key)
            .ok_or(VtpmError::HandleNotFound("vtpm:", vhandle))
    }

    /// Loads all contexts from the cache directory.
    fn load(&mut self) -> Result<(), VtpmError> {
        let entries = match fs::read_dir(self.cache_dir()) {
            Ok(entries) => entries.filter_map(Result::ok),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(vhandle) = u32::from_str_radix(stem, 16) else {
                continue;
            };

            let ht = (vhandle >> 24) as u8;
            let context: Box<dyn VtpmContext> = if ht == TpmHt::Transient as u8 {
                Box::new(VtpmKey::load_from_path(&path)?)
            } else if ht == TpmHt::HmacSession as u8 || ht == TpmHt::PolicySession as u8 {
                Box::new(VtpmSession::load_from_path(&path)?)
            } else {
                continue;
            };
            self.contexts.insert(vhandle, context);
        }
        Ok(())
    }

    /// Saves all dirty contexts to disk.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if saving any of the dirty contexts fails.
    pub fn save(&mut self) -> Result<(), VtpmError> {
        let vhandles_to_save: Vec<u32> = self.dirty.drain().collect();
        for vhandle in vhandles_to_save {
            if let Some(context) = self.contexts.get(&vhandle) {
                let path = self.cache_dir().join(format!("{vhandle:08x}.bin"));
                context.save(&path)?;
            }
        }
        Ok(())
    }

    /// Removes a context from the cache and performs necessary cleanup.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if deleting the context fails.
    pub fn remove(&mut self, device: &mut Device, vhandle: u32) -> Result<(), VtpmError> {
        if let Some(context) = self.contexts.remove(&vhandle) {
            context.delete(device, self.cache_dir(), vhandle)?;
        }
        self.dirty.remove(&vhandle);
        Ok(())
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError::AlreadyTracked`] if the handle is already being tracked.
    pub fn track(&mut self, handle: TpmHandle) -> Result<(), VtpmError> {
        if self.handles.contains_key(&handle.0) {
            return Err(VtpmError::AlreadyTracked(handle));
        }
        self.handles.insert(handle.0, handle);
        Ok(())
    }

    /// Removes a handle from the tracking list.
    pub fn untrack(&mut self, handle: u32) {
        self.handles.remove(&handle);
    }

    /// Flushes all tracked transient handles from the TPM.
    fn flush(&mut self, device: &mut Device) {
        let handles_to_flush: Vec<TpmHandle> = self.handles.drain().map(|(_, v)| v).collect();
        for handle in handles_to_flush {
            if let Err(err) = device.flush_context(handle) {
                log::error!("{handle}: {err}");
            }
        }
    }

    /// Finalizes the cache, saving dirty contexts and flushing handles.
    pub fn teardown(&mut self, device: Option<Rc<std::cell::RefCell<Device>>>) {
        if let Err(e) = self.save() {
            log::error!("teardown: {e:#}");
        }
        if let Some(device_rc) = device {
            if let Ok(mut dev) = device_rc.try_borrow_mut() {
                self.flush(&mut dev);
            }
        }
    }

    /// Saves a new key context.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if saving the context to the TPM or writing the
    /// cache file fails.
    pub fn save_context(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        public: &Tpm2bPublic,
        parent_public: &Tpm2bPublic,
    ) -> Result<u32, VtpmError> {
        let context = device.save_context(handle.0)?;
        for vhandle in 0x8000_0000u32..=0x80FF_FFFF {
            if let Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let key = VtpmKey {
                    context,
                    handle: TpmHandle(vhandle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                };
                e.insert(Box::new(key));
                self.dirty.insert(vhandle);
                return Ok(vhandle);
            }
        }
        Err(VtpmError::NoHandles)
    }

    /// Adds a session to the cache.
    pub fn add_session(&mut self, session: VtpmSession) -> u32 {
        let vhandle = session.handle();
        self.contexts.insert(vhandle, Box::new(session));
        self.dirty.insert(vhandle);
        vhandle
    }

    /// Marks a context as dirty.
    pub fn mark_dirty(&mut self, vhandle: u32) {
        self.dirty.insert(vhandle);
    }

    /// Gets an immutable reference to a session.
    #[must_use]
    pub fn get_session(&self, vhandle: u32) -> Option<&VtpmSession> {
        self.contexts
            .get(&vhandle)
            .and_then(|ctx| ctx.as_any().downcast_ref::<VtpmSession>())
    }

    /// Gets a mutable reference to a session.
    pub fn get_mut_session(&mut self, vhandle: u32) -> Option<&mut VtpmSession> {
        self.dirty.insert(vhandle);
        self.contexts
            .get_mut(&vhandle)
            .and_then(|ctx| ctx.as_any_mut().downcast_mut::<VtpmSession>())
    }

    /// Returns an iterator over the key contexts.
    pub fn key_iter(&self) -> impl Iterator<Item = (&u32, &VtpmKey)> {
        self.contexts
            .iter()
            .filter_map(|(h, ctx)| ctx.as_any().downcast_ref::<VtpmKey>().map(|key| (h, key)))
    }

    /// Prepares sessions by loading them into the TPM.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if a session is not found or loading its context fails.
    pub fn prepare_sessions(
        &mut self,
        device: &mut Device,
        auth_list: &[Auth],
    ) -> Result<Vec<TpmHandle>, VtpmError> {
        let mut activated_handles = Vec::new();
        for auth in auth_list {
            if auth.class() == AuthClass::Session {
                let vhandle = auth.session()?;
                let session = self
                    .get_session(vhandle)
                    .ok_or(VtpmError::HandleNotFound("vtpm:", vhandle))?;
                let new_handle = device.load_context(session.context.clone())?;
                activated_handles.push(TpmHandle(new_handle));
            }
        }
        Ok(activated_handles)
    }

    /// Tears down sessions by saving their updated contexts.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if a session is not found or if saving/flushing
    /// the context fails.
    pub fn teardown_sessions(
        &mut self,
        device: &mut Device,
        session_vhandles: &HashSet<u32>,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), VtpmError> {
        for (i, vhandle) in session_vhandles.iter().enumerate() {
            let session_handle = self
                .get_session(*vhandle)
                .ok_or(VtpmError::HandleNotFound("vtpm:", *vhandle))?
                .context
                .saved_handle;

            match device.save_context(session_handle.0) {
                Ok(new_context) => {
                    let session = self
                        .get_mut_session(*vhandle)
                        .ok_or(VtpmError::HandleNotFound("vtpm:", *vhandle))?;
                    session.context = new_context;
                    let auth = auth_responses[i];
                    session.nonce_tpm = auth.nonce;
                    session.attributes = auth.session_attributes;
                }
                Err(e) => {
                    if let Err(flush_err) = device.flush_context(session_handle) {
                        log::warn!("{session_handle}: {flush_err}");
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}
