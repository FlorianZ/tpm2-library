//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use nix::{
    fcntl,
    poll::{poll, PollFd, PollFlags},
};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    num::TryFromIntError,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    rc::Rc,
    time::Instant,
};

use thiserror::Error;
use tpm2_crypto::{tpm_make_name, TpmCryptoError};
use tpm2_protocol::{
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bName, TpmCap, TpmCc, TpmHt, TpmPt, TpmRc, TpmRcBase, TpmSt, TpmsAlgProperty,
        TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmtPublic, TpmuCapabilities,
    },
    frame::{
        tpm_marshal_command, tpm_unmarshal_response, TpmAuthResponses, TpmContextLoadCommand,
        TpmContextSaveCommand, TpmEvictControlCommand, TpmFlushContextCommand, TpmFrame,
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmReadPublicCommand, TpmResponse,
    },
    TpmHandle, TpmWriter,
};
use tracing::trace;

/// A type-erased object safe TPM command object.
pub trait TpmCommandObject: TpmFrame {}
impl<T> TpmCommandObject for T where T: TpmFrame {}

/// Errors that can occur when talking to a TPM device.
#[derive(Debug, Error)]
pub enum TpmDeviceError {
    #[error("device is already borrowed")]
    AlreadyBorrowed,
    #[error("capability not found: {0}")]
    CapabilityMissing(TpmCap),

    /// A cryptographic operation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),

    #[error("operation interrupted by user")]
    Interrupted,
    #[error("invalid response")]
    InvalidResponse,
    #[error("device not available")]
    NotAvailable,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),

    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("TPM command timed out")]
    Timeout,
    #[error("unexpected EOF")]
    UnexpectedEof,
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("syscall: {0}")]
    Nix(#[from] nix::Error),
    #[error("TPM return code: {0}")]
    TpmRc(TpmRc),
}

impl From<TpmRc> for TpmDeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

/// Executes a closure with a mutable reference to a `TpmDevice`.
///
/// This helper function centralizes the boilerplate for safely acquiring a
/// mutable borrow of a `TpmDevice` from the shared `Rc<RefCell<...>>`.
///
/// # Errors
///
/// Returns [`TpmDeviceError::NotAvailable`] when no device is present and
/// [`TpmDeviceError::AlreadyBorrowed`] when the device is already mutably
/// borrowed, both converted into the caller's error type `E`.
/// Propagates any error returned by the closure `f`.
pub fn with_device<F, T, E>(device: Option<Rc<RefCell<TpmDevice>>>, f: F) -> Result<T, E>
where
    F: FnOnce(&mut TpmDevice) -> Result<T, E>,
    E: From<TpmDeviceError>,
{
    let device_rc = device.ok_or(TpmDeviceError::NotAvailable)?;
    let mut device_guard = device_rc
        .try_borrow_mut()
        .map_err(|_| TpmDeviceError::AlreadyBorrowed)?;
    f(&mut device_guard)
}

pub struct TpmDevice {
    file: File,
    name_cache: HashMap<u32, (TpmtPublic, Tpm2bName)>,
    interrupt_check: Box<dyn Fn() -> bool>,
    resp_buf: Vec<u8>,
}

impl std::fmt::Debug for TpmDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("file", &self.file)
            .field("name_cache", &self.name_cache)
            .finish_non_exhaustive()
    }
}

impl TpmDevice {
    const NO_SESSIONS: &'static [TpmsAuthCommand] = &[];

    /// Opens the TPM device file and sets it to non-blocking mode.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError::Io`] if the device file cannot be opened and
    /// [`TpmDeviceError::Nix`] if configuring the file descriptor flags fails.
    pub fn open(
        path: &Path,
        interrupt_check: Box<dyn Fn() -> bool>,
    ) -> Result<Self, TpmDeviceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(TpmDeviceError::Io)?;

        let fd = file.as_raw_fd();
        let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?;
        let mut oflags = fcntl::OFlag::from_bits_truncate(flags);
        oflags.insert(fcntl::OFlag::O_NONBLOCK);
        fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(oflags))?;

        Ok(Self {
            file,
            name_cache: HashMap::new(),
            interrupt_check,
            resp_buf: Vec::with_capacity(TPM_MAX_COMMAND_SIZE as usize),
        })
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TpmDeviceError> {
        let fd = self.file.as_fd();
        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];

        let num_events = match poll(&mut fds, 100u16) {
            Ok(num) => num,
            Err(nix::Error::EINTR) => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        if num_events == 0 {
            return Ok(0);
        }

        let revents = fds[0].revents().unwrap_or(PollFlags::empty());

        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            return Err(TpmDeviceError::UnexpectedEof);
        }

        if revents.contains(PollFlags::POLLIN) {
            match self.file.read(buf) {
                Ok(0) => Err(TpmDeviceError::UnexpectedEof),
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(0),
                Err(e) => Err(e.into()),
            }
        } else if revents.contains(PollFlags::POLLHUP) {
            Err(TpmDeviceError::UnexpectedEof)
        } else {
            Ok(0)
        }
    }

    /// Performs the whole TPM command transmission process.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError::Interrupted`] when the interrupt callback
    /// requests cancellation.
    /// Returns [`TpmDeviceError::Timeout`] when the TPM does not respond within
    /// the configured timeout.
    /// Returns [`TpmDeviceError::Io`] when a write, flush, or read operation on
    /// the device file fails.
    /// Returns [`TpmDeviceError::Nix`] when polling the device file descriptor
    /// fails.
    /// Returns [`TpmDeviceError::InvalidResponse`] or
    /// [`TpmDeviceError::UnexpectedEof`] when the TPM reply is malformed,
    /// truncated, or longer than the announced size.
    /// Returns [`TpmDeviceError::Marshal`] or [`TpmDeviceError::Unmarshal`]
    /// when encoding the command or decoding the response fails.
    /// Returns [`TpmDeviceError::TpmRc`] when the TPM returns an error code.
    pub fn transmit<C: TpmCommandObject>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponse, TpmAuthResponses), TpmDeviceError> {
        let command_vec = TpmDevice::build_command_buffer(command, sessions)?;
        let cc = command.cc();

        self.file.write_all(&command_vec)?;
        self.file.flush()?;

        let start_time = Instant::now();
        self.resp_buf.clear();
        let mut total_size: Option<usize> = None;
        let mut temp_buf = [0u8; 1024];

        loop {
            if (self.interrupt_check)() {
                return Err(TpmDeviceError::Interrupted);
            }
            if start_time.elapsed() > std::time::Duration::from_secs(120) {
                return Err(TpmDeviceError::Timeout);
            }

            let n = self.receive(&mut temp_buf)?;
            if n > 0 {
                self.resp_buf.extend_from_slice(&temp_buf[..n]);
            }

            if total_size.is_none() && self.resp_buf.len() >= 10 {
                let Ok(size_bytes): Result<[u8; 4], _> = self.resp_buf[2..6].try_into() else {
                    return Err(TpmDeviceError::InvalidResponse);
                };
                let size = u32::from_be_bytes(size_bytes) as usize;
                if !(10..=TPM_MAX_COMMAND_SIZE as usize).contains(&size) {
                    return Err(TpmDeviceError::InvalidResponse);
                }
                total_size = Some(size);
            }

            if let Some(size) = total_size {
                if self.resp_buf.len() == size {
                    break;
                }
                if self.resp_buf.len() > size {
                    return Err(TpmDeviceError::InvalidResponse);
                }
            }
        }

        let result = tpm_unmarshal_response(cc, &self.resp_buf).map_err(TpmDeviceError::Unmarshal);
        trace!("{} R: {}", cc, hex::encode(&self.resp_buf));
        Ok(result??)
    }

    fn build_command_buffer<C: TpmCommandObject>(
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<Vec<u8>, TpmDeviceError> {
        let cc = command.cc();
        let tag = if sessions.is_empty() {
            TpmSt::NoSessions
        } else {
            TpmSt::Sessions
        };
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_marshal_command(command, tag, sessions, &mut writer)
                .map_err(TpmDeviceError::Marshal)?;
            writer.len()
        };
        buf.truncate(len);

        trace!("{} C: {}", cc, hex::encode(&buf));
        Ok(buf)
    }

    /// Fetches a complete list of capabilities from the TPM, handling pagination.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] returned by
    /// [`TpmDevice::get_capability_page`] or by the `extract` closure.
    pub fn get_capability<T, F, N>(
        &mut self,
        cap: TpmCap,
        property_start: u32,
        count: u32,
        mut extract: F,
        next_prop: N,
    ) -> Result<Vec<T>, TpmDeviceError>
    where
        T: Copy,
        F: for<'a> FnMut(&'a TpmuCapabilities) -> Result<&'a [T], TpmDeviceError>,
        N: Fn(&T) -> u32,
    {
        let mut results = Vec::new();
        let mut prop = property_start;
        loop {
            let (more_data, cap_data) = self.get_capability_page(cap, prop, count)?;
            let items: &[T] = extract(&cap_data.data)?;
            results.extend_from_slice(items);

            if more_data {
                if let Some(last) = items.last() {
                    prop = next_prop(last);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(results)
    }

    /// Retrieves all algorithm properties supported by the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError::IntDecode`] if the handle count cannot be
    /// represented as `u32`. Propagates any [`TpmDeviceError`] from
    /// [`TpmDevice::get_capability`], including
    /// [`TpmDeviceError::CapabilityMissing`] when the TPM does not report
    /// algorithm properties.
    pub fn fetch_algorithm_properties(&mut self) -> Result<Vec<TpmsAlgProperty>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Algs,
            0,
            u32::try_from(MAX_HANDLES)?,
            |caps| match caps {
                TpmuCapabilities::Algs(algs) => Ok(algs),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Algs)),
            },
            |last| last.alg as u32 + 1,
        )
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError::IntDecode`] if the handle count cannot be
    /// represented as `u32`. Propagates any [`TpmDeviceError`] from
    /// [`TpmDevice::get_capability`], including
    /// [`TpmDeviceError::CapabilityMissing`] when the TPM does not report
    /// handles of the requested class.
    pub fn fetch_handles(&mut self, class: u32) -> Result<Vec<TpmHandle>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Handles,
            class,
            u32::try_from(MAX_HANDLES)?,
            |caps| match caps {
                TpmuCapabilities::Handles(handles) => Ok(handles),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Handles)),
            },
            |last| *last + 1,
        )
        .map(|handles| handles.into_iter().map(TpmHandle).collect())
    }

    /// Fetches and returns one page of capabilities of a certain type from the
    /// TPM.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`]. Returns
    /// [`TpmDeviceError::ResponseMismatch`] when the TPM response does not
    /// contain `TPM2_GetCapability` data.
    pub fn get_capability_page(
        &mut self,
        cap: TpmCap,
        property: u32,
        count: u32,
    ) -> Result<(bool, TpmsCapabilityData), TpmDeviceError> {
        let cmd = TpmGetCapabilityCommand {
            cap,
            property,
            property_count: count,
        };

        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let TpmGetCapabilityResponse {
            more_data,
            capability_data,
        } = resp
            .GetCapability()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::GetCapability))?;

        Ok((more_data.into(), capability_data))
    }

    /// Reads a specific TPM property.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError::CapabilityMissing`] if the TPM does not report
    /// the requested property. Propagates any [`TpmDeviceError`] from
    /// [`TpmDevice::get_capability_page`].
    pub fn get_tpm_property(&mut self, property: TpmPt) -> Result<u32, TpmDeviceError> {
        let (_, cap_data) = self.get_capability_page(TpmCap::TpmProperties, property as u32, 1)?;

        let TpmuCapabilities::TpmProperties(props) = &cap_data.data else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        let Some(prop) = props.first() else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        Ok(prop.value)
    }

    /// Reads the public area of a TPM object.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`]. Returns
    /// [`TpmDeviceError::ResponseMismatch`] when the TPM response does not
    /// contain `TPM2_ReadPublic` data.
    pub fn read_public(
        &mut self,
        handle: TpmHandle,
    ) -> Result<(TpmtPublic, Tpm2bName), TpmDeviceError> {
        if let Some(cached) = self.name_cache.get(&handle.0) {
            return Ok(cached.clone());
        }

        let cmd = TpmReadPublicCommand {
            object_handle: handle,
        };
        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;

        let read_public_resp = resp
            .ReadPublic()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ReadPublic))?;

        let public = read_public_resp.out_public.inner;
        let name = read_public_resp.name;

        self.name_cache.insert(handle.0, (public.clone(), name));
        Ok((public, name))
    }

    /// Finds a persistent handle by its public area.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::fetch_handles`] and
    /// [`TpmDevice::read_public`], except for TPM reference and handle errors
    /// with base [`TpmRcBase::ReferenceH0`] or [`TpmRcBase::Handle`], which are
    /// treated as invalid handles and skipped.
    pub fn find_persistent(
        &mut self,
        target: &TpmtPublic,
    ) -> Result<Option<(TpmHandle, Tpm2bName)>, TpmDeviceError> {
        for handle in self.fetch_handles((TpmHt::Persistent as u32) << 24)? {
            match self.read_public(handle) {
                Ok((public, name)) => {
                    if public == *target {
                        return Ok(Some((handle, name)));
                    }
                }
                Err(TpmDeviceError::TpmRc(rc)) => {
                    let base = rc.base();
                    if base == TpmRcBase::ReferenceH0 || base == TpmRcBase::Handle {
                        continue;
                    }
                    return Err(TpmDeviceError::TpmRc(rc));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Finds a persistent handle by its `Tpm2bName`.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::fetch_handles`] and
    /// [`TpmDevice::read_public`], except for TPM reference and handle errors
    /// with base [`TpmRcBase::ReferenceH0`] or [`TpmRcBase::Handle`], which are
    /// treated as invalid handles and skipped. Returns
    /// [`TpmDeviceError::InvalidCrypto`] when computing the calculated name
    /// with [`tpm_make_name`] fails.
    pub fn find_persistent_by_name(
        &mut self,
        target_name: &Tpm2bName,
    ) -> Result<Option<TpmHandle>, TpmDeviceError> {
        for handle in self.fetch_handles((TpmHt::Persistent as u32) << 24)? {
            match self.read_public(handle) {
                Ok((public, name)) => {
                    if name == *target_name {
                        return Ok(Some(handle));
                    }
                    let calculated_name = tpm_make_name(&public)?;
                    if calculated_name == *target_name {
                        return Ok(Some(handle));
                    }
                }
                Err(TpmDeviceError::TpmRc(rc)) => {
                    let base = rc.base();
                    if base == TpmRcBase::ReferenceH0 || base == TpmRcBase::Handle {
                        continue;
                    }
                    return Err(TpmDeviceError::TpmRc(rc));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Saves the context of a transient object or session.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`]. Returns
    /// [`TpmDeviceError::ResponseMismatch`] when the TPM response does not
    /// contain `TPM2_ContextSave` data.
    pub fn save_context(&mut self, save_handle: TpmHandle) -> Result<TpmsContext, TpmDeviceError> {
        let cmd = TpmContextSaveCommand { save_handle };
        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let save_resp = resp
            .ContextSave()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ContextSave))?;
        Ok(save_resp.context)
    }

    /// Loads a TPM context and returns the handle.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`]. Returns
    /// [`TpmDeviceError::ResponseMismatch`] when the TPM response does not
    /// contain `TPM2_ContextLoad` data.
    pub fn load_context(&mut self, context: TpmsContext) -> Result<TpmHandle, TpmDeviceError> {
        let cmd = TpmContextLoadCommand { context };
        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let resp_inner = resp
            .ContextLoad()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ContextLoad))?;
        Ok(resp_inner.loaded_handle)
    }

    /// Flushes a transient object or session from the TPM and removes it from the
    /// cache.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`].
    pub fn flush_context(&mut self, handle: TpmHandle) -> Result<(), TpmDeviceError> {
        self.name_cache.remove(&handle.0);
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
        };
        self.transmit(&cmd, Self::NO_SESSIONS)?;
        Ok(())
    }

    /// Loads a session context and then flushes the resulting handle.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::load_context`] or
    /// [`TpmDevice::flush_context`] except for TPM reference errors with base
    /// [`TpmRcBase::ReferenceH0`] or [`TpmRcBase::Handle`], which are treated
    /// as a successful no-op.
    pub fn flush_session(&mut self, context: TpmsContext) -> Result<(), TpmDeviceError> {
        match self.load_context(context) {
            Ok(handle) => self.flush_context(handle),
            Err(TpmDeviceError::TpmRc(rc)) => {
                let base = rc.base();
                if base == TpmRcBase::ReferenceH0 || base == TpmRcBase::Handle {
                    Ok(())
                } else {
                    Err(TpmDeviceError::TpmRc(rc))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Evicts a persistent object or makes a transient object persistent.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::transmit`]. Returns
    /// [`TpmDeviceError::ResponseMismatch`] when the TPM response does not
    /// contain `TPM2_EvictControl` data.
    pub fn evict_control(
        &mut self,
        auth: TpmHandle,
        object_handle: TpmHandle,
        persistent_handle: TpmHandle,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(), TpmDeviceError> {
        let cmd = TpmEvictControlCommand {
            auth,
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let (resp, _) = self.transmit(&cmd, sessions)?;

        resp.EvictControl()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    /// Refreshes a key context. Returns `true` if the context is still valid,
    /// and `false` if it is stale.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`] from [`TpmDevice::load_context`] or
    /// [`TpmDevice::flush_context`] except for TPM reference errors with base
    /// [`TpmRcBase::ReferenceH0`], which are treated as a stale context and
    /// reported as `Ok(false)`.
    pub fn refresh_key(&mut self, context: TpmsContext) -> Result<bool, TpmDeviceError> {
        match self.load_context(context) {
            Ok(handle) => match self.flush_context(handle) {
                Ok(()) => Ok(true),
                Err(e) => Err(e),
            },
            Err(TpmDeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => Ok(false),
            Err(e) => Err(e),
        }
    }
}
