//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys.

use crate::{
    device::{Device, DeviceError},
    write_object,
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    fs, io,
    num::TryFromIntError,
    path::Path,
};
use thiserror::Error;
use tpm2_crypto::{tpm_make_name, Error as CryptoError};
use tpm2_policy_language::{Error as PolicyLanguageError, TpmHandleClass, TpmHandleRef};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bName, Tpm2bPublic, TpmAlgId, TpmHt, TpmRc, TpmsContext, TpmtPublic},
    TpmHandle, TpmMarshal, TpmProtocolError, TpmSized, TpmUnmarshal, TpmWriter,
};
use tpm2_tpmkey::Error as TpmKeyError;

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub context: TpmsContext,
    pub handle: TpmHandle,
    pub public: TpmtPublic,
    pub parent: TpmtPublic,
    pub empty_auth: u32,
    pub policy: Vec<u8>,
}

impl VtpmKey {
    pub(super) fn load_from_path(path: &Path) -> Result<Self, VtpmError> {
        let content = fs::read(path)?;
        let (key, remainder) = Self::unmarshal(&content).map_err(VtpmError::Protocol)?;
        if !remainder.is_empty() {
            log::warn!("trailing data");
        }
        Ok(key)
    }

    /// Returns the VTPM handle.
    #[must_use]
    pub fn handle(&self) -> u32 {
        self.handle.0
    }

    /// Returns class string.
    #[must_use]
    pub fn class(&self) -> &'static str {
        "transient"
    }

    /// Returns details string.
    #[must_use]
    pub fn details(&self) -> String {
        crate::alg::alg_details(&self.public)
    }

    /// Saves a context to a file.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::vtpm::VtpmError::Io) when an I/O operation fails.
    /// Returns [`Tpm`](crate::vtpm::VtpmError::Tpm) when writing the object
    /// fails.
    pub fn save(&self, path: &Path) -> Result<(), VtpmError> {
        let bytes = write_object(self).map_err(VtpmError::Protocol)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    /// Deletes a context.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::vtpm::VtpmError::Io) when an I/O operation fails.
    pub fn delete(&self, cache_dir: &Path) -> Result<(), VtpmError> {
        let vhandle = self.handle();
        let path = cache_dir.join(format!("{vhandle:08x}.bin"));
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }
}

impl TpmSized for VtpmKey {
    const SIZE: usize = 0;
    fn len(&self) -> usize {
        self.context.len()
            + self.handle.len()
            + Tpm2bPublic {
                inner: self.public.clone(),
            }
            .len()
            + Tpm2bPublic {
                inner: self.parent.clone(),
            }
            .len()
            + u32::SIZE
            + TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::SIZE
    }
}

impl TpmMarshal for VtpmKey {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.context.marshal(writer)?;
        self.handle.marshal(writer)?;
        Tpm2bPublic {
            inner: self.public.clone(),
        }
        .marshal(writer)?;
        Tpm2bPublic {
            inner: self.parent.clone(),
        }
        .marshal(writer)?;
        self.empty_auth.marshal(writer)?;
        TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(self.policy.as_slice())?
            .marshal(writer)?;
        Ok(())
    }
}

impl TpmUnmarshal for VtpmKey {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmProtocolError> {
        let (context, remainder) = TpmsContext::unmarshal(buffer)?;
        let (handle, remainder) = TpmHandle::unmarshal(remainder)?;
        let (public_2b, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (parent_2b, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (empty_auth, remainder) = u32::unmarshal(remainder)?;
        let (policy_blob, remainder) =
            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)?;

        Ok((
            Self {
                context,
                handle,
                public: public_2b.inner,
                parent: parent_2b.inner,
                empty_auth,
                policy: policy_blob.to_vec(),
            },
            remainder,
        ))
    }
}
#[derive(Debug, Error)]
pub enum VtpmError {
    #[error("already tracked: {0}")]
    AlreadyTracked(TpmHandle),
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("handle not found: {0}{1:08x}")]
    HandleNotFound(&'static str, u32),
    #[error("invalid key bits: {0}")]
    InvalidKeyBits(String),
    #[error("no handles")]
    NoHandles,
    #[error("parent not found")]
    ParentNotFound,
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("policy data: {0}")]
    PolicyData(#[from] TpmKeyError),
    #[error("policy language: {0}")]
    PolicyLanguage(#[from] PolicyLanguageError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
}

impl From<TpmRc> for VtpmError {
    fn from(rc: TpmRc) -> Self {
        Self::Device(DeviceError::TpmRc(rc))
    }
}

pub struct VtpmCache<'a> {
    pub contexts: HashMap<u32, VtpmKey>,
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
            .find(|(_, key)| key.public == *public)
            .map(|(_, key)| key)
    }

    /// Finds a VTPM key by its `Tpm2bName`.
    ///
    /// # Errors
    ///
    /// Returns [`Crypto`](crate::vtpm::VtpmError::Crypto) if name calculation fails.
    pub fn find_by_name(&self, target_name: &Tpm2bName) -> Result<Option<&VtpmKey>, VtpmError> {
        for (_, key) in self.key_iter() {
            let name = tpm_make_name(&key.public)?;
            if name == *target_name {
                return Ok(Some(key));
            }
        }
        Ok(None)
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
            .ok_or(VtpmError::HandleNotFound("vtpm:", vhandle))
    }

    /// Fetches the policy blob, name algorithm, and `empty_auth` status for a cached key.
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::vtpm::VtpmError::HandleNotFound) if
    /// the `vhandle` does not exist or is not a `VtpmKey`.
    pub fn fetch_policy(&self, vhandle: u32) -> Result<(Vec<u8>, TpmAlgId, bool), VtpmError> {
        let key = self.find_by_vhandle(vhandle)?;
        Ok((key.policy.clone(), key.public.name_alg, key.empty_auth != 0))
    }

    /// Finds the ancestor chain for a given VTPM handle.
    ///
    /// Traverses up the parent hierarchy from the target `vhandle`, checking
    /// both the cache and persistent TPM handles, until it finds the root. The
    /// root can be a persistent physical handle or a non-persistent primary key
    /// stored in the VTPM cache.
    ///
    /// Returns a list of `TpmHandleRef`s representing the path from the
    /// root *down* to the target, ready for loading.
    ///
    /// # Errors
    ///
    /// Returns [`Protocol`](crate::vtpm::VtpmError::Protocol) when serializing a
    /// public key fails.
    /// Returns [`HandleNotFound`](crate::vtpm::VtpmError::HandleNotFound) when the
    /// `target_vhandle` doesn't exist in the cache or is not a key.
    /// Returns [`ParentNotFound`](crate::vtpm::VtpmError::ParentNotFound) when an
    /// intermediate parent cannot be found in the cache or as a persistent
    /// handle.
    pub fn fetch_ancestor_chain(
        &self,
        target_vhandle: u32,
        persistent_keys: &HashMap<Vec<u8>, TpmHandle>,
    ) -> Result<Vec<TpmHandleRef>, VtpmError> {
        let mut current_vhandle = target_vhandle;
        let mut vtp_chain: VecDeque<TpmHandleRef> = VecDeque::new();
        let mut physical_primary: Option<TpmHandleRef> = None;

        loop {
            let key = self.find_by_vhandle(current_vhandle)?;

            if key.parent.object_type == TpmAlgId::Null {
                break;
            }

            if let Some(parent_key) = self.find_by_public(&key.parent) {
                let parent_vhandle = parent_key.handle.0;
                vtp_chain.push_front(TpmHandleRef::new(TpmHandleClass::Vtpm, current_vhandle));
                current_vhandle = parent_vhandle;
            } else {
                let parent_key_bytes = write_object(&key.parent).map_err(VtpmError::Protocol)?;
                match persistent_keys.get(&parent_key_bytes) {
                    Some(phandle) => {
                        physical_primary = Some(TpmHandleRef::new(TpmHandleClass::Tpm, phandle.0));
                        break;
                    }
                    None => {
                        return Err(VtpmError::ParentNotFound);
                    }
                }
            }
        }

        vtp_chain.push_front(TpmHandleRef::new(TpmHandleClass::Vtpm, current_vhandle));

        let mut final_chain: Vec<TpmHandleRef> = vtp_chain.into();

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
            if ht == TpmHt::Transient as u8 {
                match VtpmKey::load_from_path(&path) {
                    Ok(key) => {
                        self.contexts.insert(vhandle, key);
                    }
                    Err(e) => {
                        log::warn!("{}: {}", path.display(), e);
                    }
                }
            } else if ht == TpmHt::HmacSession as u8 || ht == TpmHt::PolicySession as u8 {
                log::debug!("removing stale session file: {}", path.display());
                if let Err(e) = fs::remove_file(&path) {
                    log::warn!("failed to remove stale session {}: {}", path.display(), e);
                }
            } else {
                log::warn!("invalid type prefix: {}", path.display());
            }
        }
        Ok(())
    }

    /// Saves all dirty contexts to disk.
    ///
    /// # Errors
    ///
    /// Returns [`VtpmError::Io`] when saving any of the dirty contexts fails.
    /// Returns [`Tpm`](crate::vtpm::VtpmError::Tpm) when serializing context data fails.
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
    /// Returns [`VtpmError::Io`] when removing the cache file fails.
    pub fn remove(&mut self, vhandle: u32) -> Result<Vec<u32>, VtpmError> {
        let mut deleted_handles = Vec::new();

        let maybe_public = if let Some(key) = self.contexts.remove(&vhandle) {
            deleted_handles.push(vhandle);
            key.delete(self.cache_dir())?;
            self.dirty.remove(&vhandle);
            Some(key.public)
        } else {
            return Ok(deleted_handles);
        };

        if let Some(public_key) = maybe_public {
            let deleted_children = self.remove_subtree(&public_key)?;
            deleted_handles.extend(deleted_children);
        }

        Ok(deleted_handles)
    }

    fn remove_subtree(&mut self, first_public: &TpmtPublic) -> Result<Vec<u32>, VtpmError> {
        let mut parent_to_children: HashMap<Vec<u8>, Vec<(u32, TpmtPublic)>> = HashMap::new();
        for (vhandle, key) in self.key_iter() {
            let parent_key_bytes = write_object(&key.parent).map_err(VtpmError::Protocol)?;
            parent_to_children
                .entry(parent_key_bytes)
                .or_default()
                .push((*vhandle, key.public.clone()));
        }

        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());
        let mut deleted_children = Vec::new();

        while let Some(parent_public) = ancestor_list.pop_front() {
            let parent_key_bytes = write_object(&parent_public).map_err(VtpmError::Protocol)?;
            if let Some(children_to_process) = parent_to_children.get(&parent_key_bytes) {
                for (child_vhandle, child_public) in children_to_process.clone() {
                    if let Some(context) = self.contexts.remove(&child_vhandle) {
                        context.delete(self.cache_dir())?;
                        self.dirty.remove(&child_vhandle);
                        deleted_children.push(child_vhandle);
                        ancestor_list.push_back(child_public);
                    }
                }
            }
        }
        Ok(deleted_children)
    }

    /// Finalizes the cache, saving dirty contexts.
    pub fn teardown(&mut self) {
        if let Err(e) = self.save() {
            log::error!("teardown: {e:#}");
        }
    }

    /// Saves a new key context.
    ///
    /// # Errors
    ///
    /// Returns [`VtpmError::Device`] when saving the context to the TPM fails.
    /// Returns [`VtpmError::NoHandles`] when no free VTPM handle slot is found.
    /// Returns [`VtpmError::Io`] when writing the cache file fails.
    /// Returns [`Tpm`](crate::vtpm::VtpmError::Tpm) when serializing context data fails.
    pub fn save_context(
        &mut self,
        device: &mut Device,
        handle: TpmHandle,
        public: &TpmtPublic,
        parent_public: &TpmtPublic,
        empty_auth: bool,
        policy: &Option<Vec<u8>>,
    ) -> Result<u32, VtpmError> {
        let context = device.save_context(handle)?;
        for vhandle in 0x8000_0000u32..=0x80FF_FFFF {
            if let Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let key = VtpmKey {
                    context,
                    handle: TpmHandle(vhandle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                    empty_auth: u32::from(empty_auth),
                    policy: policy.clone().unwrap_or_default(),
                };
                e.insert(key);
                self.dirty.insert(vhandle);
                return Ok(vhandle);
            }
        }
        Err(VtpmError::NoHandles)
    }

    /// Marks a context as dirty.
    pub fn mark_dirty(&mut self, vhandle: u32) {
        self.dirty.insert(vhandle);
    }

    /// Returns an iterator over the key contexts.
    pub fn key_iter(&self) -> impl Iterator<Item = (&u32, &VtpmKey)> {
        self.contexts.iter()
    }
}
