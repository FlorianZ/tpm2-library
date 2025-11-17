// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    fs, io,
    path::Path,
};
use thiserror::Error;
use tpm2_crypto::tpm_make_name;
use tpm2_policy_language::{TpmHandleClass, TpmHandleRef};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bName, TpmAlgId, TpmHt, TpmsContext, TpmtPublic},
    TpmHandle, TpmMarshal, TpmProtocolError, TpmSized, TpmUnmarshal, TpmWriter,
};

const VERSION: u32 = 0x0000_0001;
const TRANSIENT_START: u32 = 0x8000_0000;
const TRANSIENT_END: u32 = 0x80FF_FFFF;
const TRANSIENT_COUNT: u32 = 0x0100_0000;

fn tpm_marshal_array(objs: &[&dyn TpmMarshal]) -> Result<Vec<u8>, TpmProtocolError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        for obj in objs {
            obj.marshal(&mut writer)?;
        }
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub version: u32,
    pub handle: TpmHandle,
    pub public: TpmtPublic,
    pub parent: TpmtPublic,
    pub context: TpmsContext,
    pub empty_auth: u32,
    pub policy: TpmBuffer<{ TPM_MAX_COMMAND_SIZE as usize }>,
}

impl VtpmKey {
    fn load_from_path(path: &Path) -> Result<Self, VtpmError> {
        let buffer = fs::read(path)?;
        let (version, _) = u32::unmarshal(&buffer).map_err(|_| VtpmError::StaleHandle)?;
        if version != VERSION {
            return Err(VtpmError::StaleHandle);
        }
        let (key, remainder) = Self::unmarshal(&buffer).map_err(VtpmError::Unmarshal)?;
        if !remainder.is_empty() {
            log::warn!("trailing data");
        }
        Ok(key)
    }

    fn save_to_path(&self, path: &Path) -> Result<(), VtpmError> {
        let bytes = tpm_marshal_array(&[self]).map_err(VtpmError::Marshal)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn delete(&self, cache_dir: &Path) -> Result<(), VtpmError> {
        let vhandle = self.handle.0;
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
    const SIZE: usize = u32::SIZE
        + TpmHandle::SIZE
        + TpmtPublic::SIZE
        + TpmtPublic::SIZE
        + TpmsContext::SIZE
        + u32::SIZE
        + TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::SIZE;

    fn len(&self) -> usize {
        u32::SIZE
            + self.handle.len()
            + self.public.len()
            + self.parent.len()
            + self.context.len()
            + u32::SIZE
            + self.policy.len()
    }
}

impl TpmMarshal for VtpmKey {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.version.marshal(writer)?;
        self.handle.marshal(writer)?;
        self.public.marshal(writer)?;
        self.parent.marshal(writer)?;
        self.context.marshal(writer)?;
        self.empty_auth.marshal(writer)?;
        self.policy.marshal(writer)?;

        Ok(())
    }
}

impl TpmUnmarshal for VtpmKey {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmProtocolError> {
        let (version, remainder) = u32::unmarshal(buffer)?;
        let (handle, remainder) = TpmHandle::unmarshal(remainder)?;
        let (public, remainder) = TpmtPublic::unmarshal(remainder)?;
        let (parent, remainder) = TpmtPublic::unmarshal(remainder)?;
        let (context, remainder) = TpmsContext::unmarshal(remainder)?;
        let (empty_auth, remainder) = u32::unmarshal(remainder)?;
        let (policy, remainder) =
            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)?;

        Ok((
            Self {
                version,
                handle,
                public,
                parent,
                context,
                empty_auth,
                policy,
            },
            remainder,
        ))
    }
}

/// Error type for VTPM cache operations and TPM serialization.
#[derive(Debug, Error)]
pub enum VtpmError {
    #[error("handle not found: vtpm:{0:08x}")]
    HandleNotFound(TpmHandle),
    #[error("no handles")]
    NoHandles,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),
    #[error("operation failed")]
    OperationFailed,
    #[error("parent not found")]
    ParentNotFound,
    #[error("stale handle")]
    StaleHandle,
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
}

#[derive(Debug)]
pub struct VtpmCache<'a> {
    contexts: HashMap<u32, VtpmKey>,
    dirty: HashSet<u32>,
    cache_dir: &'a Path,
    next_vhandle: u32,
}

impl<'a> VtpmCache<'a> {
    /// Creates a new cache and loads existing contexts from disk.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::VtpmError::Io) when reading the cache directory
    /// or cache files fails.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when cleaning up a stale
    /// context fails.
    pub fn new(cache_dir: &'a Path) -> Result<Self, VtpmError> {
        fs::create_dir_all(cache_dir)?;
        let mut cache = Self {
            contexts: HashMap::new(),
            dirty: HashSet::new(),
            cache_dir,
            next_vhandle: TRANSIENT_START,
        };
        cache.load()?;

        if let Some(max_handle) = cache.contexts.keys().max() {
            if *max_handle >= cache.next_vhandle {
                let next = max_handle.wrapping_add(1);
                cache.next_vhandle = if next > TRANSIENT_END {
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
    /// Returns [`OperationFailed`](crate::VtpmError::OperationFailed) if name
    /// calculation fails.
    pub fn find_by_name(&self, target_name: &Tpm2bName) -> Result<Option<&VtpmKey>, VtpmError> {
        for (_, key) in self.key_iter() {
            let name = tpm_make_name(&key.public).map_err(|_| VtpmError::OperationFailed)?;
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
    /// Returns [`HandleNotFound`](crate::VtpmError::HandleNotFound) when
    /// no context with the given `vhandle` exists.
    pub fn find_by_vhandle(&self, vhandle: u32) -> Result<&VtpmKey, VtpmError> {
        self.contexts
            .get(&vhandle)
            .ok_or(VtpmError::HandleNotFound(TpmHandle(vhandle)))
    }

    /// Fetches the policy blob, name algorithm, and `empty_auth` status for a cached key.
    ///
    /// # Errors
    ///
    /// Returns [`HandleNotFound`](crate::VtpmError::HandleNotFound) if the
    /// `vhandle` does not exist.
    pub fn fetch_policy(&self, vhandle: u32) -> Result<(Vec<u8>, TpmAlgId, bool), VtpmError> {
        let key = self.find_by_vhandle(vhandle)?;
        Ok((
            key.policy.to_vec(),
            key.public.name_alg,
            key.empty_auth != 0,
        ))
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
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when serializing a
    /// public key fails.
    /// Returns [`HandleNotFound`](crate::VtpmError::HandleNotFound) when the
    /// `target_vhandle` does not exist in the cache.
    /// Returns [`ParentNotFound`](crate::VtpmError::ParentNotFound) when an
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
                let parent_key_bytes =
                    tpm_marshal_array(&[&key.parent]).map_err(VtpmError::Marshal)?;
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

    /// Removes a context from the cache and performs necessary cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::VtpmError::Io) when removing a cache file fails.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when serializing parent
    /// keys during subtree removal fails.
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

    /// Finalizes the cache by saving all dirty contexts.
    ///
    /// This method is called automatically when the cache is dropped, but can
    /// be invoked earlier to force a flush at a known point. Calling it
    /// multiple times is safe.
    pub fn teardown(&mut self) {
        if let Err(e) = self.save() {
            log::error!("teardown: {e:#}");
        }
    }

    /// Saves a new key context.
    ///
    /// # Errors
    ///
    /// Returns [`NoHandles`](crate::VtpmError::NoHandles) when no free VTPM
    /// handle slot is found.
    #[allow(clippy::needless_pass_by_value)]
    pub fn save_context(
        &mut self,
        context: TpmsContext,
        public: &TpmtPublic,
        parent_public: &TpmtPublic,
        empty_auth: bool,
        policy: &Option<Vec<u8>>,
    ) -> Result<u32, VtpmError> {
        for i in 0..TRANSIENT_COUNT {
            let vhandle = self.next_vhandle.wrapping_add(i);

            let vhandle = if vhandle > TRANSIENT_END {
                TRANSIENT_START + (vhandle - TRANSIENT_END - 1)
            } else {
                vhandle
            };

            if let Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let policy_vec = policy.as_deref().unwrap_or_default();
                let policy_buf = TpmBuffer::try_from(policy_vec).map_err(VtpmError::Marshal)?;

                let key = VtpmKey {
                    version: VERSION,
                    handle: TpmHandle(vhandle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                    context,
                    empty_auth: u32::from(empty_auth),
                    policy: policy_buf,
                };
                e.insert(key);
                self.dirty.insert(vhandle);

                let next = vhandle.wrapping_add(1);
                self.next_vhandle = if next > TRANSIENT_END {
                    TRANSIENT_START
                } else {
                    next
                };

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
        let vhandles_to_save: Vec<u32> = self.dirty.iter().copied().collect();

        for vhandle in vhandles_to_save {
            match self.contexts.get(&vhandle) {
                Some(context) => {
                    let path = self.cache_dir().join(format!("{vhandle:08x}.bin"));
                    context.save_to_path(&path)?;
                    self.dirty.remove(&vhandle);
                }
                None => {
                    self.dirty.remove(&vhandle);
                }
            }
        }

        Ok(())
    }

    fn remove_subtree(&mut self, first_public: &TpmtPublic) -> Result<Vec<u32>, VtpmError> {
        let mut parent_to_children: HashMap<Vec<u8>, Vec<(u32, TpmtPublic)>> = HashMap::new();
        for (vhandle, key) in self.key_iter() {
            let parent_key_bytes = tpm_marshal_array(&[&key.parent]).map_err(VtpmError::Marshal)?;
            parent_to_children
                .entry(parent_key_bytes)
                .or_default()
                .push((*vhandle, key.public.clone()));
        }

        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());
        let mut deleted_children = Vec::new();

        while let Some(parent_public) = ancestor_list.pop_front() {
            let parent_key_bytes =
                tpm_marshal_array(&[&parent_public]).map_err(VtpmError::Marshal)?;
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
}

impl Drop for VtpmCache<'_> {
    fn drop(&mut self) {
        self.teardown();
    }
}
