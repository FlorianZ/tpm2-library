// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Manages caching for TPM keys.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod policy;

pub use policy::*;

use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    fmt, fs, io,
    path::Path,
    str::FromStr,
};
use thiserror::Error;
use tpm2_crypto::tpm_make_name;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bName, TpmAlgId, TpmCc, TpmHt, TpmlDigest, TpmlPcrSelection, TpmsContext,
        TpmtPublic,
    },
    TpmHandle, TpmMarshal, TpmUnmarshal, TpmWriter,
};

const VERSION: u32 = 0x0000_0001;
const TRANSIENT_START: u32 = 0x8000_0000;
const TRANSIENT_END: u32 = 0x80FF_FFFF;
const TRANSIENT_COUNT: u32 = 0x0100_0000;

pub(crate) fn tpm_marshal_array(objs: &[&dyn TpmMarshal]) -> Result<Vec<u8>, VtpmError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        for obj in objs {
            obj.marshal(&mut writer).map_err(VtpmError::Marshal)?;
        }
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// Handle classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpmHandleClass {
    Tpm,
    Vtpm,
}

/// TPM and vTPM handles, with support for pattern matching.
///
/// A [`VtpmHandle`] can represent either a single, specific handle value (e.g.,
/// `tpm:81000001`) or a pattern for matching multiple handles (e.g., `tpm:81*`,
/// `vtpm:????????`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtpmHandle {
    class: VtpmHandleClass,
    mask: u32,
    value: u32,
}

impl VtpmHandle {
    /// Creates a new handle that represents a single, specific handle value.
    #[must_use]
    pub fn new(class: VtpmHandleClass, value: u32) -> Self {
        Self {
            class,
            mask: 0xFFFF_FFFF,
            value,
        }
    }

    /// Returns the class of the handle (`Tpm` or `Vtpm`).
    #[must_use]
    pub fn class(&self) -> VtpmHandleClass {
        self.class
    }

    /// Returns the value of the handle if it represents a single handle.
    ///
    /// Returns `Some(value)` when the handle was created without wildcards.
    /// Returns `None` when the handle is a pattern.
    #[must_use]
    pub fn value(&self) -> Option<u32> {
        if self.mask == 0xFFFF_FFFF {
            Some(self.value)
        } else {
            None
        }
    }

    /// Checks if a given handle value matches the handle's pattern.
    #[must_use]
    pub fn matches(&self, handle: u32) -> bool {
        (handle & self.mask) == self.value
    }
}

impl fmt::Display for VtpmHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scheme = match self.class {
            VtpmHandleClass::Tpm => "tpm",
            VtpmHandleClass::Vtpm => "vtpm",
        };
        write!(f, "{scheme}:")?;

        if self.mask == 0 {
            write!(f, "*")
        } else {
            for i in (0..8).rev() {
                let shift = i * 4;
                let nibble_mask = (self.mask >> shift) & 0xF;
                if nibble_mask == 0xF {
                    let val = (self.value >> shift) & 0xF;
                    write!(f, "{val:x}")?;
                } else {
                    write!(f, "?")?;
                }
            }
            Ok(())
        }
    }
}

impl FromStr for VtpmHandle {
    type Err = VtpmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme_str, value_str) = s.split_once(':').ok_or(VtpmError::HandlePrefixMissing)?;

        let class = match scheme_str {
            "tpm" => VtpmHandleClass::Tpm,
            "vtpm" => VtpmHandleClass::Vtpm,
            _ => return Err(VtpmError::InvalidHandlePrefix),
        };

        if value_str == "*" {
            return Ok(Self {
                class,
                mask: 0,
                value: 0,
            });
        }

        let asterisk_count = value_str.chars().filter(|&c| c == '*').count();
        if asterisk_count > 1 {
            return Err(VtpmError::HandleHasTooManyAsterisks);
        }

        let explicit_len = value_str.len() - asterisk_count;

        if asterisk_count == 0 {
            if explicit_len < 8 {
                return Err(VtpmError::HandleTooShort);
            }
            if explicit_len > 8 {
                return Err(VtpmError::HandleTooLong);
            }
        } else if explicit_len > 8 {
            return Err(VtpmError::HandleTooLong);
        }

        let padding = 8 - explicit_len;
        let mut mask: u32 = 0;
        let mut value: u32 = 0;
        let mut nibble_idx = 7_i32;

        for c in value_str.chars() {
            if c == '*' {
                nibble_idx -= i32::try_from(padding).unwrap();
                continue;
            }

            #[allow(clippy::cast_sign_loss)]
            let shift = (nibble_idx * 4) as u32;

            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => {
                    let c = if c.is_alphanumeric() { c } else { '?' };
                    return Err(VtpmError::InvalidHandleCharacter(c));
                }
            }
            nibble_idx -= 1;
        }

        Ok(Self { class, mask, value })
    }
}

impl TryFrom<VtpmHandle> for TpmHt {
    type Error = VtpmError;

    fn try_from(handle: VtpmHandle) -> Result<Self, Self::Error> {
        let raw_handle = handle.value().ok_or(VtpmError::HandlePatternNotAllowed)?;
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|_| VtpmError::InvalidHandleType(ht_byte))
    }
}

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub version: u32,
    pub handle: TpmHandle,
    pub public: TpmtPublic,
    pub parent: TpmtPublic,
    pub context: TpmsContext,
    pub empty_auth: u32,
    pub policy: Vec<Box<dyn VtpmPolicyCommand>>,
}

impl VtpmKey {
    /// Fetches the policy blob.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when marshaling TPM
    /// encoded data fails.
    /// Returns [`OperationFailed`](crate::VtpmError::OperationFailed) when the
    /// policy commands cannot be serialized because of an internal failure.
    pub fn policy_into_bytes(&self) -> Result<Vec<u8>, VtpmError> {
        let mut buf = vec![];

        let count = u32::try_from(self.policy.len()).map_err(|_| VtpmError::OperationFailed)?;
        buf.extend_from_slice(&tpm_marshal_array(&[&count])?);

        for command in &self.policy {
            let cc = command.cc();
            buf.extend_from_slice(&tpm_marshal_array(&[&cc])?);

            let body_len =
                u32::try_from(command.body().len()).map_err(|_| VtpmError::OperationFailed)?;
            buf.extend_from_slice(&tpm_marshal_array(&[&body_len])?);
            buf.extend_from_slice(&command.body());
        }

        Ok(buf)
    }

    fn load(path: &Path) -> Result<Self, VtpmError> {
        let buffer = fs::read(path)?;
        let (version, tail) = u32::unmarshal(&buffer).map_err(|_| VtpmError::StaleHandle)?;

        if version != VERSION {
            return Err(VtpmError::StaleHandle);
        }

        let (handle, tail) = TpmHandle::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (public, tail) = TpmtPublic::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (parent, tail) = TpmtPublic::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (context, tail) = TpmsContext::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (empty_auth, tail) = u32::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
        let (count, mut tail) = u32::unmarshal(tail).map_err(VtpmError::Unmarshal)?;

        let mut policy = Vec::new();

        for _ in 0..count {
            let (cc, tail_next) = TpmCc::unmarshal(tail).map_err(VtpmError::Unmarshal)?;
            let (len_u32, tail_next) = u32::unmarshal(tail_next).map_err(VtpmError::Unmarshal)?;
            let len = len_u32 as usize;

            if tail_next.len() < len {
                return Err(VtpmError::UnexpectedEnd);
            }

            let (body, tail_next) = tail_next.split_at(len);
            tail = tail_next;

            policy.push(VtpmKey::policy_command_from_parts(cc, body.to_vec())?);
        }

        if !tail.is_empty() {
            log::warn!("trailing data");
        }

        Ok(Self {
            version,
            handle,
            public,
            parent,
            context,
            empty_auth,
            policy,
        })
    }

    fn save(&self, path: &Path) -> Result<(), VtpmError> {
        let mut buf = vec![];

        let key_bytes = tpm_marshal_array(&[
            &self.version,
            &self.handle,
            &self.public,
            &self.parent,
            &self.context,
            &self.empty_auth,
        ])?;

        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&self.policy_into_bytes()?);

        fs::write(path, buf)?;
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

    /// Creates a `VtpmPolicyCommand` from a command code and raw body.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCc`](crate::VtpmError::InvalidCc) when `cc` is not valid.
    /// Returns [`InvalidPolicy`](crate::VtpmError::InvalidPolicy) when `body`
    /// violates command-specific constraints.
    fn policy_command_from_parts(
        cc: TpmCc,
        body: Vec<u8>,
    ) -> Result<Box<dyn VtpmPolicyCommand>, VtpmError> {
        match cc {
            TpmCc::PolicyAuthValue
            | TpmCc::PolicyPassword
            | TpmCc::PolicyGetDigest
            | TpmCc::PolicyRestart
            | TpmCc::PolicyPhysicalPresence => {
                if !body.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }

                Ok(Box::new(VtpmPolicyDefaultCommand { cc, body }))
            }
            TpmCc::PolicyAuthorize => {
                let (command, remainder) =
                    VtpmPolicyAuthorizeCommand::unmarshal(&body).map_err(VtpmError::Unmarshal)?;

                if !remainder.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }

                Ok(Box::new(command))
            }
            TpmCc::PolicySecret => {
                let (command, remainder) =
                    VtpmPolicySecretCommand::unmarshal(&body).map_err(VtpmError::Unmarshal)?;

                if !remainder.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }

                Ok(Box::new(command))
            }
            TpmCc::PolicyPcr => {
                let (pcr_digest, rest) =
                    Tpm2bDigest::unmarshal(body.as_slice()).map_err(VtpmError::Unmarshal)?;
                let (pcrs, rest) =
                    TpmlPcrSelection::unmarshal(rest).map_err(VtpmError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }
                let _ = (pcr_digest, pcrs);
                Ok(Box::new(VtpmPolicyDefaultCommand { cc, body }))
            }
            TpmCc::PolicyOr => {
                let (p_hash_list, rest) =
                    TpmlDigest::unmarshal(body.as_slice()).map_err(VtpmError::Unmarshal)?;
                if !rest.is_empty() {
                    return Err(VtpmError::InvalidPolicy);
                }
                let _ = p_hash_list;
                Ok(Box::new(VtpmPolicyDefaultCommand { cc, body }))
            }
            _ => Err(VtpmError::InvalidCc(cc)),
        }
    }
}

/// Error type for VTPM cache operations and TPM serialization.
#[derive(Debug, Error)]
pub enum VtpmError {
    /// Handle has more than one asterisk (`*`).
    #[error("handle has more than one asterisk")]
    HandleHasTooManyAsterisks,

    /// Handle not found in the cache.
    #[error("handle not found: vtpm:{0:08x}")]
    HandleNotFound(TpmHandle),

    /// Handle contains a pattern (e.g., `*` or `?`).
    #[error("handle pattern is not allowed")]
    HandlePatternNotAllowed,

    /// Handle prefix (e.g., `tpm:` or `vtpm:`) is missing.
    #[error("handle prefix is missing")]
    HandlePrefixMissing,

    /// Handle is less than eight characters.
    #[error("handle is less than eight characters")]
    HandleTooShort,

    /// Handle is more than eight characters.
    #[error("handle has more than eight characters")]
    HandleTooLong,

    /// Handle contains an invalid character.
    #[error("invalid handle character: {0}")]
    InvalidHandleCharacter(char),

    /// Handle prefix is not valid.
    #[error("invalid handle prefix")]
    InvalidHandlePrefix,

    /// Handle type byte is not valid.
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),

    /// No free VTPM handle slots are available.
    #[error("no handles")]
    NoHandles,

    /// Command code in a policy command is not a valid `TPM_CC`.
    #[error("invalid CC: {0}")]
    InvalidCc(tpm2_protocol::data::TpmCc),

    /// A policy command body is malformed or invalid for that command.
    #[error("invalid policy")]
    InvalidPolicy,

    /// An I/O operation failed.
    #[error("I/O: {0}")]
    Io(#[from] io::Error),

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    /// An operation failed because of an internal error.
    #[error("operation failed")]
    OperationFailed,

    /// A parent key could not be found in the cache or persistent handles.
    #[error("parent not found")]
    ParentNotFound,

    /// A cached handle is stale or incompatible.
    #[error("stale handle")]
    StaleHandle,

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),

    /// While unmarshaling, the end of data was reached unexpectedly.
    #[error("unexpected end of data")]
    UnexpectedEnd,
}

#[derive(Debug)]
pub struct VtpmCache<'a> {
    /// Map from virtual handles to cached keys.
    contexts: HashMap<u32, VtpmKey>,

    /// Map from `TpmtPublic` to live handles.
    handles: HashMap<Vec<u8>, TpmHandle>,

    /// Set of virtual handles, which must be persisted.
    dirty: HashSet<u32>,

    /// Cache root directory.
    cache_dir: &'a Path,

    /// Next available virtual handle.
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
    pub fn new(
        cache_dir: &'a Path,
        persistent: HashMap<Vec<u8>, TpmHandle>,
    ) -> Result<Self, VtpmError> {
        fs::create_dir_all(cache_dir)?;
        let mut cache = Self {
            contexts: HashMap::new(),
            handles: persistent,
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

    /// Finds the ancestor chain for a given VTPM handle.
    ///
    /// Traverses up the parent hierarchy from the target `vhandle`, checking
    /// both the cache and persistent TPM handles, until it finds the root. The
    /// root can be a persistent physical handle or a non-persistent primary key
    /// stored in the VTPM cache.
    ///
    /// Returns a list of [`VtpmHandle`]s representing the path from the
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
    pub fn fetch_ancestor_chain(&self, target_vhandle: u32) -> Result<Vec<VtpmHandle>, VtpmError> {
        let mut current_vhandle = target_vhandle;
        let mut vtp_chain: VecDeque<VtpmHandle> = VecDeque::new();
        let mut physical_primary: Option<VtpmHandle> = None;

        loop {
            let key = self.find_by_vhandle(current_vhandle)?;

            if key.parent.object_type == TpmAlgId::Null {
                break;
            }

            if let Some(parent_key) = self.find_by_public(&key.parent) {
                let parent_vhandle = parent_key.handle.0;
                vtp_chain.push_front(VtpmHandle::new(VtpmHandleClass::Vtpm, current_vhandle));
                current_vhandle = parent_vhandle;
            } else {
                let parent_key_bytes = tpm_marshal_array(&[&key.parent])?;
                match self.handles.get(&parent_key_bytes) {
                    Some(phandle) => {
                        physical_primary = Some(VtpmHandle::new(VtpmHandleClass::Tpm, phandle.0));
                        break;
                    }
                    None => {
                        return Err(VtpmError::ParentNotFound);
                    }
                }
            }
        }

        vtp_chain.push_front(VtpmHandle::new(VtpmHandleClass::Vtpm, current_vhandle));

        let mut final_chain: Vec<VtpmHandle> = vtp_chain.into();

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

        if let Some(key) = self.contexts.get(&vhandle) {
            key.delete(self.cache_dir())?;
        } else {
            return Ok(deleted_handles);
        }

        if let Some(key) = self.contexts.remove(&vhandle) {
            deleted_handles.push(vhandle);
            self.dirty.remove(&vhandle);

            let deleted_children = self.remove_subtree(&key.public)?;
            deleted_handles.extend(deleted_children);
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
        policy: &Option<Vec<Box<dyn VtpmPolicyCommand>>>,
    ) -> Result<u32, VtpmError> {
        for i in 0..TRANSIENT_COUNT {
            let vhandle = self.next_vhandle.wrapping_add(i);

            let vhandle = if vhandle > TRANSIENT_END {
                TRANSIENT_START + (vhandle - TRANSIENT_END - 1)
            } else {
                vhandle
            };

            if let Entry::Vacant(e) = self.contexts.entry(vhandle) {
                let key = VtpmKey {
                    version: VERSION,
                    handle: TpmHandle(vhandle),
                    public: public.clone(),
                    parent: parent_public.clone(),
                    context,
                    empty_auth: u32::from(empty_auth),
                    policy: policy.clone().unwrap_or_default(),
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
                match VtpmKey::load(&path) {
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
                    context.save(&path)?;
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
            let parent_key_bytes = tpm_marshal_array(&[&key.parent])?;
            parent_to_children
                .entry(parent_key_bytes)
                .or_default()
                .push((*vhandle, key.public.clone()));
        }

        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());
        let mut deleted_children = Vec::new();

        while let Some(parent_public) = ancestor_list.pop_front() {
            let parent_key_bytes = tpm_marshal_array(&[&parent_public])?;
            if let Some(children_to_process) = parent_to_children.get(&parent_key_bytes) {
                for (child_vhandle, child_public) in children_to_process.clone() {
                    if let Some(context) = self.contexts.get(&child_vhandle) {
                        context.delete(self.cache_dir())?;

                        if self.contexts.remove(&child_vhandle).is_some() {
                            self.dirty.remove(&child_vhandle);
                            deleted_children.push(child_vhandle);
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
