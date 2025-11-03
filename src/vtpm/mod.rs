//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys and sessions.

use crate::{
    device::{Device, DeviceError},
    key::Tpm2shAlgId,
    write_object,
};
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    fs, io,
    num::TryFromIntError,
    path::Path,
    rc::Rc,
};
use thiserror::Error;
use tpm2_crypto::CryptoError;
use tpm2_policy_language::{Auth, Handle, HandleClass};
use tpm2_protocol::{
    basic::{TpmBuffer, TpmList},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bPublic, TpmAlgId, TpmHt, TpmRc, TpmsContext, TpmtPublic},
    TpmHandle, TpmMarshalError, TpmUnmarshalError,
};

mod key;
mod session;

pub use key::*;
pub use session::*;

/// A local constant for the max commands, as tpm2-protocol 0.12 does not export this.
type TpmPolicyCommandBlob = TpmBuffer<{ TPM_MAX_COMMAND_SIZE as usize }>;

#[derive(Debug, Error)]
pub enum VtpmError {
    #[error("already tracked: {0}")]
    AlreadyTracked(TpmHandle),
    #[error("capacity exceeded")]
    CapacityExceeded,
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
    #[error("parent not found")]
    ParentNotFound,
    #[error("parent not loaded")]
    ParentNotLoaded,
    #[error("trailing authorizations")]
    TrailingAuthorizations,
    #[error("unsupported name algorithm: {0}")]
    UnsupportedNameAlgorithm(Tpm2shAlgId),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("policy language: {0}")]
    PolicyLanguage(#[from] tpm2_policy_language::Error),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("protocol marshal: {0}")]
    ProtocolMarshal(tpm2_protocol::TpmMarshalError),
    #[error("protocol unmarshal: {0}")]
    ProtocolUnmarshal(tpm2_protocol::TpmUnmarshalError),
}

impl From<TpmMarshalError> for VtpmError {
    fn from(err: TpmMarshalError) -> Self {
        Self::ProtocolMarshal(err)
    }
}

impl From<TpmUnmarshalError> for VtpmError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::ProtocolUnmarshal(err)
    }
}

impl From<TpmRc> for VtpmError {
    fn from(rc: TpmRc) -> Self {
        Self::Device(DeviceError::TpmRc(rc))
    }
}

/// Outcome of refreshing [`VtpmContext`](crate::vtpm::VtpmContext) against the
/// TPM.
#[derive(Debug)]
pub enum RefreshAction {
    /// The context is still valid.
    Keep,
    /// The context is no longer valid.
    Stale,
    /// A new [`TpmsContext`](tpm2_protocol::data::TpmsContext) substituting
    /// the old one.
    Updated(Box<TpmsContext>),
}

/// A VTPM object.
pub trait VtpmContext: 'static {
    /// Immutable cast.
    fn as_any(&self) -> &dyn Any;

    /// Mutable cast.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns the VTPM handle.
    fn handle(&self) -> u32;

    /// Returns class string.
    fn class(&self) -> &'static str;

    /// Returns details string.
    fn details(&self) -> String;

    /// Saves a context to a file.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::vtpm::VtpmError::Io) when an I/O operation fails.
    /// Returns [`Tpm`](crate::vtpm::VtpmError::Tpm) when writing the object
    /// fails.
    fn save(&self, path: &Path) -> Result<(), VtpmError>;

    /// Deletes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::vtpm::VtpmError::Device) when the TPM
    /// transmission fails.
    /// Returns [`Io`](crate::vtpm::VtpmError::Io) when an I/O operation fails.
    fn delete(&self, device: &mut Device, cache_dir: &Path, vhandle: u32) -> Result<(), VtpmError>;

    /// Refreshes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::vtpm::VtpmError::Device) when the TPM
    /// transmission fails.
    fn refresh(&mut self, device: &mut Device) -> Result<RefreshAction, VtpmError>;
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
    /// Returns [`Io`](crate::vtpm::VtpmError::Io) when reading the cache
    /// directory fails.
    /// Returns [`Tpm`](crate::vtpm::VtpmError::Tpm) when parsing loaded context
    /// data fails.
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

    /// Finds a VTPM key corresponding to a `TpmtPublic`.
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
    /// Returns [`HandleNotFound`](crate::vtpm::VtpmError::HandleNotFound) when
    /// a key with the corresponding public area is not found in the cache.
    /// Returns [`Device`](crate::vtpm::VtpmError::Device) when `TPM2_ReadPublic`
    /// fails.
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
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::vtpm::VtpmError::HandleNotFound) when
    /// context with the given `vhandle` is not found or is not a key.
    pub fn find_by_vhandle(&self, vhandle: u32) -> Result<&VtpmKey, VtpmError> {
        self.contexts
            .get(&vhandle)
            .and_then(|ctx| ctx.as_any().downcast_ref::<VtpmKey>())
            .ok_or(VtpmError::HandleNotFound("vtpm:", vhandle))
    }

    /// Finds the ancestor chain for a given VTPM handle.
    ///
    /// Traverses up the parent hierarchy from the target `vhandle`, checking
    /// both the cache and persistent TPM handles, until it finds the root. The
    /// root can be a persistent physical handle or a non-persistent primary key
    /// stored in the VTPM cache.
    ///
    /// Returns a list of `Handle`s representing the path from the
    /// root *down* to the target, ready for loading.
    ///
    /// # Errors
    ///
    /// Returns [`Device`](crate::vtpm::VtpmError::Device) when an underlying TPM
    /// command fails.
    /// Returns [`HandleNotFound`](crate::vtpm::VtpmError::HandleNotFound) when the
    /// `target_vhandle` doesn't exist in the cache or is not a key.
    /// Returns [`ParentNotFound`](crate::vtpm::VtpmError::ParentNotFound) when an
    /// intermediate parent cannot be found in the cache or as a persistent
    /// handle.
    pub fn fetch_ancestor_chain(
        &self,
        target_vhandle: u32,
        device: &mut Device,
    ) -> Result<Vec<Handle>, VtpmError> {
        let mut current_vhandle = target_vhandle;
        let mut vtp_chain: VecDeque<Handle> = VecDeque::new();
        let mut physical_primary: Option<Handle> = None;

        loop {
            let key = self.find_by_vhandle(current_vhandle)?;

            if key.parent.inner.object_type == TpmAlgId::Null {
                break;
            }

            if let Some(parent_key) = self.find_by_public(&key.parent.inner) {
                let parent_vhandle = parent_key.handle();
                vtp_chain.push_front(Handle::new(HandleClass::Vtpm, current_vhandle));
                current_vhandle = parent_vhandle;
            } else {
                match device.find_persistent(&key.parent.inner)? {
                    Some((phandle, _)) => {
                        physical_primary = Some(Handle::new(HandleClass::Tpm, phandle.0));
                        break;
                    }
                    None => {
                        return Err(VtpmError::ParentNotFound);
                    }
                }
            }
        }

        vtp_chain.push_front(Handle::new(HandleClass::Vtpm, current_vhandle));

        let mut final_chain: Vec<Handle> = vtp_chain.into();

        if let Some(root_handle) = physical_primary {
            final_chain.insert(0, root_handle);
        }

        Ok(final_chain)
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
                log::warn!("invalid vtpm handle: {}", path.display());
                continue;
            };

            let ht = (vhandle >> 24) as u8;
            let context_result: Result<Box<dyn VtpmContext>, VtpmError> =
                if ht == TpmHt::Transient as u8 {
                    VtpmKey::load_from_path(&path).map(|k| Box::new(k) as Box<dyn VtpmContext>)
                } else if ht == TpmHt::HmacSession as u8 || ht == TpmHt::PolicySession as u8 {
                    VtpmSession::load_from_path(&path).map(|s| Box::new(s) as Box<dyn VtpmContext>)
                } else {
                    log::warn!("invalid type prefix: {}", path.display());
                    continue;
                };

            match context_result {
                Ok(context) => {
                    self.contexts.insert(vhandle, context);
                }
                Err(e) => {
                    log::warn!("{}: {}", path.display(), e);
                }
            }
        }
        Ok(())
    }

    /// Saves all dirty contexts to disk.
    ///
    /// # Errors
    ///
    /// Returns [`VtpmError::Io`] when saving any of the dirty contexts fails.
    /// Returns [`VtpmError::Tpm`] when serializing context data fails.
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
    /// Returns [`VtpmError::Device`] when flushing the context from TPM fails.
    /// Returns [`VtpmError::Io`] when removing the cache file fails.
    pub fn remove(&mut self, device: &mut Device, vhandle: u32) -> Result<Vec<u32>, VtpmError> {
        let mut deleted_handles = Vec::new();

        let maybe_public = if let Some(context) = self.contexts.remove(&vhandle) {
            deleted_handles.push(vhandle);
            context.delete(device, self.cache_dir(), vhandle)?;
            self.dirty.remove(&vhandle);

            context
                .as_any()
                .downcast_ref::<VtpmKey>()
                .map(|key| key.public.inner.clone())
        } else {
            return Ok(deleted_handles);
        };

        if let Some(public_key) = maybe_public {
            let deleted_children = self.remove_subtree(device, &public_key)?;
            deleted_handles.extend(deleted_children);
        }

        Ok(deleted_handles)
    }

    fn remove_subtree(
        &mut self,
        dev: &mut Device,
        first_public: &TpmtPublic,
    ) -> Result<Vec<u32>, VtpmError> {
        let mut parent_to_children: HashMap<Vec<u8>, Vec<(u32, TpmtPublic)>> = HashMap::new();
        for (vhandle, key) in self.key_iter() {
            let parent_key_bytes =
                write_object(&key.parent.inner).map_err(VtpmError::ProtocolMarshal)?;
            parent_to_children
                .entry(parent_key_bytes)
                .or_default()
                .push((*vhandle, key.public.inner.clone()));
        }

        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());
        let mut deleted_children = Vec::new();

        while let Some(parent_public) = ancestor_list.pop_front() {
            let parent_key_bytes =
                write_object(&parent_public).map_err(VtpmError::ProtocolMarshal)?;
            if let Some(children_to_process) = parent_to_children.get(&parent_key_bytes) {
                for (child_vhandle, child_public) in children_to_process.clone() {
                    if let Some(context) = self.contexts.remove(&child_vhandle) {
                        context.delete(dev, self.cache_dir(), child_vhandle)?;
                        self.dirty.remove(&child_vhandle);
                        deleted_children.push(child_vhandle);
                        ancestor_list.push_back(child_public);
                    }
                }
            }
        }
        Ok(deleted_children)
    }

    /// Tracks a transient handle for automatic cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`VtpmError::AlreadyTracked`] if the handle is already being
    /// tracked.
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
    /// Returns [`VtpmError::Device`] when saving the context to the TPM fails.
    /// Returns [`VtpmError::NoHandles`] when no free VTPM handle slot is found.
    /// Returns [`VtpmError::Io`] when writing the cache file fails.
    /// Returns [`VtpmError::Tpm`] when serializing context data fails.
    pub fn save_context(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        public: &Tpm2bPublic,
        parent_public: &Tpm2bPublic,
        policy: &Option<Vec<Vec<u8>>>,
    ) -> Result<u32, VtpmError> {
        let context = device.save_context(handle)?;
        for vhandle in 0x8000_0000u32..=0x80FF_FFFF {
            if let Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let mut policy_list = TpmList::new();
                if let Some(blobs) = policy {
                    for blob in blobs {
                        let buffer = TpmPolicyCommandBlob::try_from(blob.as_slice())
                            .map_err(|_| VtpmError::CapacityExceeded)?;
                        policy_list
                            .push(buffer)
                            .map_err(|_| VtpmError::CapacityExceeded)?;
                    }
                }

                let key = VtpmKey {
                    context,
                    handle: TpmHandle(vhandle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                    policy: policy_list,
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
            if let Auth::Session(vhandle) = auth {
                let session = self
                    .get_session(*vhandle)
                    .ok_or(VtpmError::HandleNotFound("vtpm:", *vhandle))?;
                activated_handles.push(device.load_context(session.context.clone())?);
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
        auth_responses: &tpm2_protocol::frame::TpmAuthResponses,
    ) -> Result<(), VtpmError> {
        for (i, vhandle) in session_vhandles.iter().enumerate() {
            let session_handle = self
                .get_session(*vhandle)
                .ok_or(VtpmError::HandleNotFound("vtpm:", *vhandle))?
                .context
                .saved_handle;

            match device.save_context(session_handle) {
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
                    if let Err(e) = device.flush_context(session_handle) {
                        log::warn!("{session_handle}: {e}");
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}
