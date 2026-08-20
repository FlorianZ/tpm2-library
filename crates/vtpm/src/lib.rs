// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod policy;

pub use policy::*;

use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    fs, io,
    path::Path,
};
use tpm2_crypto::tpm_make_name;
use tpm2_protocol::{
    TpmError, TpmMarshal, TpmUnmarshal, TpmWriter,
    basic::{TpmBuffer, TpmHandle, TpmUint32, TpmUint64},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bName, TpmAlgId, TpmHt, TpmRh, TpmsContext, TpmtPublic},
};

const VERSION: u32 = 0x0000_0002;
const TRANSIENT_START: u32 = 0x8000_0000;
const TRANSIENT_END: u32 = 0x80FF_FFFF;
const TRANSIENT_COUNT: u32 = 0x0100_0000;

#[derive(Debug, Clone)]
pub struct VtpmKey {
    version: TpmUint32,
    handle: TpmHandle,
    public: TpmtPublic,
    parent: TpmtPublic,
    context: TpmsContext,
    policy: Vec<Box<dyn VtpmPolicyCommand>>,
}

impl VtpmKey {
    #[must_use]
    pub fn handle(&self) -> TpmHandle {
        self.handle
    }

    #[must_use]
    pub fn public(&self) -> &TpmtPublic {
        &self.public
    }

    #[must_use]
    pub fn parent(&self) -> &TpmtPublic {
        &self.parent
    }

    #[must_use]
    pub fn context(&self) -> &TpmsContext {
        &self.context
    }

    #[must_use]
    pub fn policy(&self) -> &[Box<dyn VtpmPolicyCommand>] {
        &self.policy
    }

    fn load(path: &Path) -> Result<Self, VtpmError> {
        let buffer = fs::read(path)?;
        let (version, tail) = TpmUint32::unmarshal(&buffer).map_err(|_| VtpmError::StaleHandle)?;

        if version.value() != VERSION {
            return Err(VtpmError::StaleHandle);
        }

        let (handle, tail) = TpmHandle::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (public, tail) = TpmtPublic::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (parent, tail) = TpmtPublic::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (context, tail) = TpmsContext::unmarshal(tail).map_err(VtpmError::Unmarshal)?;

        let (policy, tail) = vtpm_unmarshal_policy_list(tail)?;

        if !tail.is_empty() {
            log::warn!("trailing data");
        }

        Ok(Self {
            version,
            handle,
            public,
            parent,
            context,
            policy,
        })
    }

    fn save(&self, path: &Path) -> Result<(), VtpmError> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            self.version
                .marshal(&mut writer)
                .map_err(VtpmError::Marshal)?;
            self.handle
                .marshal(&mut writer)
                .map_err(VtpmError::Marshal)?;
            self.public
                .marshal(&mut writer)
                .map_err(VtpmError::Marshal)?;
            self.parent
                .marshal(&mut writer)
                .map_err(VtpmError::Marshal)?;
            self.context
                .marshal(&mut writer)
                .map_err(VtpmError::Marshal)?;

            vtpm_marshal_policy_list(&self.policy, &mut writer)?;
            writer.len()
        };

        buf.truncate(len);
        fs::write(path, buf)?;
        Ok(())
    }

    fn delete(&self, cache_dir: &Path) -> Result<(), VtpmError> {
        let virtual_handle = self.handle.value();
        let path = cache_dir.join(format!("{virtual_handle:08x}.bin"));
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }
}

/// Error type for VTPM cache operations and TPM serialization.
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `HandleNotFound` becomes `handle not found`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
#[non_exhaustive]
pub enum VtpmError {
    /// Handle not found in the cache.
    HandleNotFound(TpmHandle),

    /// Handle type byte is not valid.
    InvalidHandleType(u8),

    /// No free VTPM handle slots are available.
    NoHandles,

    /// Command code in a policy command is not a valid `TPM_CC`.
    InvalidCc(tpm2_protocol::data::TpmCc),

    /// A policy command body is malformed or invalid for that command.
    InvalidPolicy,

    /// An I/O operation failed.
    Io(io::Error),

    /// Marshaling a TPM protocol encoded object failed.
    Marshal(TpmError),

    /// An operation failed because of an internal error.
    OperationFailed,

    /// A parent key could not be found in the cache or persistent handles.
    ParentNotFound,

    /// A cached handle is stale or incompatible.
    StaleHandle,

    /// Unmarshaling a TPM protocol encoded object failed.
    Unmarshal(TpmError),

    /// While unmarshaling, the end of data was reached unexpectedly.
    UnexpectedEnd,
}

impl core::fmt::Display for VtpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for VtpmError {}

impl From<io::Error> for VtpmError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug)]
pub struct VtpmCache<'a> {
    /// Map from virtual handles to cached keys.
    contexts: HashMap<u32, VtpmKey>,

    /// Map from `Tpm2bName` to live handles.
    handles: HashMap<Tpm2bName, TpmHandle>,

    /// Set of virtual handles, which must be persisted.
    dirty: HashSet<u32>,

    /// Cache root directory.
    cache_dir: &'a Path,

    /// Next available virtual handle.
    next_virtual_handle: u32,
}

impl<'a> VtpmCache<'a> {
    /// Creates a new cache and loads existing contexts from disk.
    ///
    /// The `handles` map contains persistent TPM handles indexed by their `Tpm2bName`.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::VtpmError::Io) when reading the cache directory
    /// or cache files fails.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when cleaning up a stale
    /// context fails.
    /// Returns [`InvalidHandleType`](crate::VtpmError::InvalidHandleType) if
    /// the provided handles map contains non-persistent handles.
    pub fn new(
        cache_dir: &'a Path,
        handles: HashMap<Tpm2bName, TpmHandle>,
    ) -> Result<Self, VtpmError> {
        for handle in handles.values() {
            let ht = (handle.value() >> 24) as u8;
            if ht != TpmHt::Persistent as u8 {
                return Err(VtpmError::InvalidHandleType(ht));
            }
        }

        fs::create_dir_all(cache_dir)?;
        let mut cache = Self {
            contexts: HashMap::new(),
            handles,
            dirty: HashSet::new(),
            cache_dir,
            next_virtual_handle: TRANSIENT_START,
        };
        cache.load()?;

        if let Some(max_handle) = cache.contexts.keys().max() {
            if *max_handle >= cache.next_virtual_handle {
                let next = max_handle.wrapping_add(1);
                cache.next_virtual_handle = if next > TRANSIENT_END {
                    TRANSIENT_START
                } else {
                    next
                };
            }
        }

        Ok(cache)
    }

    fn cache_dir(&self) -> &Path {
        self.cache_dir
    }

    /// Finds a VTPM key by its `Tpm2bName`.
    ///
    /// Live handles are consulted first, then the cache is scanned.
    #[must_use]
    pub fn find_by_name(&self, target_name: &Tpm2bName) -> Option<&VtpmKey> {
        if let Some(handle) = self.handles.get(target_name) {
            if let Some(key) = self.contexts.get(&handle.value()) {
                return Some(key);
            }
        }

        None
    }

    /// Finds a VTPM key corresponding to a virtual handle.
    #[must_use]
    pub fn find_by_handle(&self, handle: TpmHandle) -> Option<&VtpmKey> {
        self.contexts.get(&handle.value())
    }

    /// Finds the ancestor chain for a given VTPM handle.
    ///
    /// Traverses up the parent hierarchy from the target `virtual_handle`, checking
    /// both the cache and persistent TPM handles, until it finds the root. The
    /// root can be a persistent physical handle or a non-persistent primary key
    /// stored in the VTPM cache.
    ///
    /// Returns a list of [`TpmHandle`]s representing the path from the
    /// root *down* to the target, ready for loading.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when serializing a
    /// public key fails.
    /// Returns [`HandleNotFound`](crate::VtpmError::HandleNotFound) when the
    /// `target_virtual_handle` does not exist in the cache.
    /// Returns [`ParentNotFound`](crate::VtpmError::ParentNotFound) when an
    /// intermediate parent cannot be found in the cache or as a persistent
    /// handle.
    pub fn fetch_ancestors(&self, target_handle: TpmHandle) -> Result<Vec<TpmHandle>, VtpmError> {
        let mut current_virtual_handle = target_handle;
        let mut chain: VecDeque<TpmHandle> = VecDeque::new();
        let mut physical_primary: Option<TpmHandle> = None;

        let ht = (target_handle.value() >> 24) as u8;
        if ht == TpmHt::Persistent as u8 {
            for handle in self.handles.values() {
                if *handle == target_handle {
                    return Ok(vec![target_handle]);
                }
            }
        }

        loop {
            let Some(key) = self.find_by_handle(current_virtual_handle) else {
                return Err(VtpmError::HandleNotFound(current_virtual_handle));
            };

            if key.parent.object_type == TpmAlgId::Null {
                break;
            }

            if let Some((&parent_virtual_handle, _)) = self
                .contexts
                .iter()
                .find(|(_, parent_key)| parent_key.public == key.parent)
            {
                chain.push_front(current_virtual_handle);
                current_virtual_handle = TpmUint32::new(parent_virtual_handle);
            } else {
                let parent_name =
                    tpm_make_name(&key.parent).map_err(|_| VtpmError::OperationFailed)?;
                match self.handles.get(&parent_name) {
                    Some(phandle) => {
                        physical_primary = Some(*phandle);
                        break;
                    }
                    None => {
                        return Err(VtpmError::ParentNotFound);
                    }
                }
            }
        }

        chain.push_front(current_virtual_handle);

        let mut final_chain: Vec<TpmHandle> = chain.into();

        if let Some(root_handle) = physical_primary {
            final_chain.insert(0, root_handle);
        }

        Ok(final_chain)
    }

    /// Removes a context from the cache and performs necessary cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::VtpmError::Io) when removing a cache file fails.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when serializing parent
    /// keys during subtree removal fails.
    pub fn remove(&mut self, handle: TpmHandle) -> Result<Vec<TpmHandle>, VtpmError> {
        let virtual_handle = handle.value();
        let mut deleted_handles = Vec::new();

        let Some(key) = self.contexts.get(&virtual_handle) else {
            return Ok(deleted_handles);
        };

        let name = tpm_make_name(&key.public).map_err(|_| VtpmError::OperationFailed)?;

        key.delete(self.cache_dir())?;

        if let Some(key) = self.contexts.remove(&virtual_handle) {
            deleted_handles.push(handle);
            self.dirty.remove(&virtual_handle);
            self.handles.remove(&name);

            let deleted_children = self.remove_subtree(&key.public)?;
            deleted_handles.extend(deleted_children.into_iter().map(TpmUint32::new));
        }

        Ok(deleted_handles)
    }

    /// Flushes all dirty contexts to disk.
    ///
    /// # Errors
    ///
    /// Propagates any failure that occurs while saving dirty contexts.
    pub fn flush(&mut self) -> Result<(), VtpmError> {
        self.save()
    }

    /// Finalizes the cache by saving all dirty contexts.
    ///
    /// This method is called automatically when the cache is dropped, but can
    /// be invoked earlier to force a flush at a known point. Calling it
    /// multiple times is safe.
    pub fn teardown(&mut self) {
        if let Err(e) = self.flush() {
            log::error!("teardown: {e:#}");
        }
    }

    /// Creates a new [`VtpmKey`](crate::VtpmKey) instance for a transient key,
    /// and saves the given context to the cache together with its associated
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns [`NoHandles`](crate::VtpmError::NoHandles) when no free VTPM
    /// handle slot is found.
    pub fn save_transient(
        &mut self,
        context: TpmsContext,
        public: &TpmtPublic,
        parent_public: &TpmtPublic,
        policy: Option<&[Box<dyn VtpmPolicyCommand>]>,
    ) -> Result<TpmHandle, VtpmError> {
        for i in 0..TRANSIENT_COUNT {
            let virtual_handle = self.next_virtual_handle.wrapping_add(i);

            let virtual_handle = if virtual_handle > TRANSIENT_END {
                TRANSIENT_START + (virtual_handle - TRANSIENT_END - 1)
            } else {
                virtual_handle
            };

            if let Entry::Vacant(e) = self.contexts.entry(virtual_handle) {
                let key = VtpmKey {
                    version: TpmUint32::new(VERSION),
                    handle: TpmUint32::new(virtual_handle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                    context,
                    policy: policy.map(<[_]>::to_vec).unwrap_or_default(),
                };

                let name = tpm_make_name(&key.public).map_err(|_| VtpmError::OperationFailed)?;

                e.insert(key);

                self.handles.insert(name, TpmUint32::new(virtual_handle));
                self.dirty.insert(virtual_handle);

                let next = virtual_handle.wrapping_add(1);
                self.next_virtual_handle = if next > TRANSIENT_END {
                    TRANSIENT_START
                } else {
                    next
                };

                return Ok(TpmUint32::new(virtual_handle));
            }
        }
        Err(VtpmError::NoHandles)
    }

    /// Caches metadata for a persistent key.
    ///
    /// The context is initialized to defaults, as persistent keys reside
    /// in the TPM's NVRAM.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHandleType`](crate::VtpmError::InvalidHandleType)
    /// if `handle` is not a persistent handle.
    /// Returns [`OperationFailed`](crate::VtpmError::OperationFailed) if name
    /// calculation fails.
    pub fn save_persistent(
        &mut self,
        handle: TpmHandle,
        public: &TpmtPublic,
        parent_public: &TpmtPublic,
        policy: Option<&[Box<dyn VtpmPolicyCommand>]>,
    ) -> Result<(), VtpmError> {
        let ht = (handle.value() >> 24) as u8;
        if ht != TpmHt::Persistent as u8 {
            return Err(VtpmError::InvalidHandleType(ht));
        }

        let key = VtpmKey {
            version: TpmUint32::new(VERSION),
            handle,
            public: public.clone(),
            parent: parent_public.clone(),
            context: TpmsContext {
                sequence: TpmUint64::new(0),
                saved_handle: TpmHandle::default(),
                hierarchy: TpmRh::Owner,
                context_blob: TpmBuffer::default(),
            },
            policy: policy.map(<[_]>::to_vec).unwrap_or_default(),
        };

        let name = tpm_make_name(&key.public).map_err(|_| VtpmError::OperationFailed)?;

        self.contexts.insert(handle.value(), key);
        self.handles.insert(name, handle);
        self.dirty.insert(handle.value());

        Ok(())
    }

    /// Marks a context as dirty.
    pub fn mark_dirty(&mut self, handle: TpmHandle) {
        self.dirty.insert(handle.value());
    }

    /// Returns an iterator over the key contexts.
    pub fn key_iter(&self) -> impl Iterator<Item = (TpmHandle, &VtpmKey)> {
        self.contexts
            .iter()
            .map(|(handle, key)| (TpmUint32::new(*handle), key))
    }

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
            let Ok(virtual_handle) = u32::from_str_radix(stem, 16) else {
                log::warn!("invalid vtpm handle: {}", path.display());
                continue;
            };

            let ht = (virtual_handle >> 24) as u8;
            if ht == TpmHt::Transient as u8 || ht == TpmHt::Persistent as u8 {
                match VtpmKey::load(&path) {
                    Ok(key) => {
                        let name =
                            tpm_make_name(&key.public).map_err(|_| VtpmError::OperationFailed)?;
                        self.contexts.insert(virtual_handle, key);
                        self.handles.insert(name, TpmUint32::new(virtual_handle));
                    }
                    Err(VtpmError::StaleHandle) => {
                        log::debug!("removing stale vtpm file: {}", path.display());
                        if let Err(e) = fs::remove_file(&path) {
                            log::warn!(
                                "failed to remove stale vtpm file {}: {}",
                                path.display(),
                                e
                            );
                        }
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

    fn save(&mut self) -> Result<(), VtpmError> {
        let virtual_handles_to_save: Vec<u32> = self.dirty.iter().copied().collect();

        for virtual_handle in virtual_handles_to_save {
            match self.contexts.get(&virtual_handle) {
                Some(context) => {
                    let path = self.cache_dir().join(format!("{virtual_handle:08x}.bin"));
                    context.save(&path)?;
                    self.dirty.remove(&virtual_handle);
                }
                None => {
                    self.dirty.remove(&virtual_handle);
                }
            }
        }

        Ok(())
    }

    fn remove_subtree(&mut self, first_public: &TpmtPublic) -> Result<Vec<u32>, VtpmError> {
        let mut parent_to_children: HashMap<Vec<u8>, Vec<(u32, TpmtPublic)>> = HashMap::new();
        for (virtual_handle, key) in self.key_iter() {
            let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut buf);
                key.parent
                    .marshal(&mut writer)
                    .map_err(VtpmError::Marshal)?;
                writer.len()
            };
            buf.truncate(len);
            let parent_key_bytes = buf;

            parent_to_children
                .entry(parent_key_bytes)
                .or_default()
                .push((virtual_handle.value(), key.public.clone()));
        }

        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());
        let mut deleted_children = Vec::new();

        while let Some(parent_public) = ancestor_list.pop_front() {
            let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut buf);
                parent_public
                    .marshal(&mut writer)
                    .map_err(VtpmError::Marshal)?;
                writer.len()
            };
            buf.truncate(len);
            let parent_key_bytes = buf;

            if let Some(children_to_process) = parent_to_children.get(&parent_key_bytes) {
                for (child_virtual_handle, child_public) in children_to_process.clone() {
                    if let Some(context) = self.contexts.get(&child_virtual_handle) {
                        let name = tpm_make_name(&context.public)
                            .map_err(|_| VtpmError::OperationFailed)?;
                        context.delete(self.cache_dir())?;
                        if self.contexts.remove(&child_virtual_handle).is_some() {
                            self.handles.remove(&name);
                            self.dirty.remove(&child_virtual_handle);
                            deleted_children.push(child_virtual_handle);
                            ancestor_list.push_back(child_public);
                        }
                    }
                }
            }
        }
        Ok(deleted_children)
    }
}

impl Drop for VtpmCache<'_> {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tpm2_protocol::TpmMarshal;

    #[test]
    fn load_removes_stale_transient_entries() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path();
        let stale_path = cache_path.join("80000000.bin");

        let mut buffer = vec![0u8; std::mem::size_of::<u32>()];
        let len = {
            let mut writer = TpmWriter::new(&mut buffer);
            let stale_version = TpmUint32::new(VERSION + 1);
            stale_version.marshal(&mut writer).unwrap();
            writer.len()
        };
        buffer.truncate(len);

        fs::write(&stale_path, &buffer).unwrap();

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        assert!(cache.key_iter().next().is_none());
        assert!(!stale_path.exists());
    }
}
