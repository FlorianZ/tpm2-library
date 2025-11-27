// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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
    os::fd::{AsFd, AsRawFd},
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use thiserror::Error;
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bName, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmHt, TpmPt, TpmRc, TpmRcBase, TpmSt,
        TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsPcrSelect,
        TpmsPcrSelection, TpmtPublic, TpmuCapabilities,
    },
    frame::{
        tpm_marshal_command, tpm_unmarshal_response, TpmAuthResponses, TpmContextLoadCommand,
        TpmContextSaveCommand, TpmFlushContextCommand, TpmFrame, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmReadPublicCommand, TpmResponse,
    },
    TpmWriter,
};
use tracing::{debug, trace};

/// Errors that can occur when talking to a TPM device.
#[derive(Debug, Error)]
pub enum TpmDeviceError {
    #[error("device is already borrowed")]
    AlreadyBorrowed,
    #[error("capability not found: {0}")]
    CapabilityMissing(TpmCap),
    #[error("operation interrupted by user")]
    Interrupted,
    #[error("invalid response")]
    InvalidResponse,

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    #[error("device not available")]
    NotAvailable,
    #[error("operation failed")]
    OperationFailed,
    #[error("PCR banks not available")]
    PcrBanksNotAvailable,
    #[error("PCR bank selection mismatch")]
    PcrBankSelectionMismatch,

    /// The TPM response did not match the expected command code.
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),

    #[error("TPM command timed out")]
    Timeout,
    #[error("TPM return code: {0}")]
    TpmRc(TpmRc),

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),

    #[error("unexpected EOF")]
    UnexpectedEof,
}

impl From<TpmRc> for TpmDeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

impl From<nix::Error> for TpmDeviceError {
    fn from(err: nix::Error) -> Self {
        Self::Io(std::io::Error::from_raw_os_error(err as i32))
    }
}

/// Executes a closure with a mutable reference to a `TpmDevice`.
///
/// This helper function centralizes the boilerplate for safely acquiring a
/// mutable borrow of a `TpmDevice` from the shared `Rc<RefCell<...>>`.
///
/// # Errors
///
/// Returns [`NotAvailable`](crate::TpmDeviceError::NotAvailable) when no device
/// is present and [`AlreadyBorrowed`](crate::TpmDeviceError::AlreadyBorrowed)
/// when the device is already mutably borrowed, both converted into the caller's
/// error type `E`. Propagates any error returned by the closure `f`.
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

/// A builder for constructing a `TpmDevice`.
pub struct TpmDeviceBuilder {
    path: PathBuf,
    timeout: Duration,
    interrupted: Box<dyn Fn() -> bool>,
}

impl Default for TpmDeviceBuilder {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/dev/tpmrm0"),
            timeout: Duration::from_secs(120),
            interrupted: Box::new(|| false),
        }
    }
}

impl TpmDeviceBuilder {
    /// Sets the device file path.
    #[must_use]
    pub fn with_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = path.as_ref().to_path_buf();
        self
    }

    /// Sets the operation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the interruption check callback.
    #[must_use]
    pub fn with_interrupted<F>(mut self, handler: F) -> Self
    where
        F: Fn() -> bool + 'static,
    {
        self.interrupted = Box::new(handler);
        self
    }

    /// Opens the TPM device file and constructs the `TpmDevice`.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::TpmDeviceError::Io) when the device file cannot be
    /// opened or when configuring the file descriptor flags fails.
    pub fn build(self) -> Result<TpmDevice, TpmDeviceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(TpmDeviceError::Io)?;

        let fd = file.as_raw_fd();
        let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?;
        let mut oflags = fcntl::OFlag::from_bits_truncate(flags);
        oflags.insert(fcntl::OFlag::O_NONBLOCK);
        fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(oflags))?;

        Ok(TpmDevice {
            file,
            name_cache: HashMap::new(),
            interrupted: self.interrupted,
            timeout: self.timeout,
            command: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
            response: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
        })
    }
}

pub struct TpmDevice {
    file: File,
    name_cache: HashMap<u32, (TpmtPublic, Tpm2bName)>,
    interrupted: Box<dyn Fn() -> bool>,
    timeout: Duration,
    command: Vec<u8>,
    response: Vec<u8>,
}

impl std::fmt::Debug for TpmDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("file", &self.file)
            .field("name_cache", &self.name_cache)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl TpmDevice {
    const NO_SESSIONS: &'static [TpmsAuthCommand] = &[];

    /// Creates a new builder for `TpmDevice`.
    #[must_use]
    pub fn builder() -> TpmDeviceBuilder {
        TpmDeviceBuilder::default()
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
    /// Returns [`Interrupted`](crate::TpmDeviceError::Interrupted) when the
    /// interrupt callback requests cancellation.
    /// Returns [`Timeout`](crate::TpmDeviceError::Timeout) when the TPM does
    /// not respond within the configured timeout.
    /// Returns [`Io`](crate::TpmDeviceError::Io) when a write, flush, or read
    /// operation on the device file fails, or when polling the device file
    /// descriptor fails.
    /// Returns [`InvalidResponse`](crate::TpmDeviceError::InvalidResponse) or
    /// [`UnexpectedEof`](crate::TpmDeviceError::UnexpectedEof) when the TPM
    /// reply is malformed, truncated, or longer than the announced size.
    /// Returns [`Marshal`](crate::TpmDeviceError::Marshal) or
    /// [`Unmarshal`](crate::TpmDeviceError::Unmarshal) when encoding the
    /// command or decoding the response fails.
    /// Returns [`TpmRc`](crate::TpmDeviceError::TpmRc) when the TPM returns an
    /// error code.
    pub fn transmit<C: TpmFrame>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponse, TpmAuthResponses), TpmDeviceError> {
        self.prepare_command(command, sessions)?;
        let cc = command.cc();

        self.file.write_all(&self.command)?;
        self.file.flush()?;

        let start_time = Instant::now();
        self.response.clear();
        let mut total_size: Option<usize> = None;
        let mut temp_buf = [0u8; 1024];

        loop {
            if (self.interrupted)() {
                return Err(TpmDeviceError::Interrupted);
            }
            if start_time.elapsed() > self.timeout {
                return Err(TpmDeviceError::Timeout);
            }

            let n = self.receive(&mut temp_buf)?;
            if n > 0 {
                self.response.extend_from_slice(&temp_buf[..n]);
            }

            if total_size.is_none() && self.response.len() >= 10 {
                let Ok(size_bytes): Result<[u8; 4], _> = self.response[2..6].try_into() else {
                    return Err(TpmDeviceError::InvalidResponse);
                };
                let size = u32::from_be_bytes(size_bytes) as usize;
                if !(10..={ TPM_MAX_COMMAND_SIZE }).contains(&size) {
                    return Err(TpmDeviceError::InvalidResponse);
                }
                total_size = Some(size);
            }

            if let Some(size) = total_size {
                if self.response.len() == size {
                    break;
                }
                if self.response.len() > size {
                    return Err(TpmDeviceError::InvalidResponse);
                }
            }
        }

        let result = tpm_unmarshal_response(cc, &self.response).map_err(TpmDeviceError::Unmarshal);
        trace!("{} R: {}", cc, hex::encode(&self.response));
        Ok(result??)
    }

    fn prepare_command<C: TpmFrame>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(), TpmDeviceError> {
        let cc = command.cc();
        let tag = if sessions.is_empty() {
            TpmSt::NoSessions
        } else {
            TpmSt::Sessions
        };

        self.command.resize(TPM_MAX_COMMAND_SIZE, 0);

        let len = {
            let mut writer = TpmWriter::new(&mut self.command);
            tpm_marshal_command(command, tag, sessions, &mut writer)
                .map_err(TpmDeviceError::Marshal)?;
            writer.len()
        };
        self.command.truncate(len);

        trace!("{} C: {}", cc, hex::encode(&self.command));
        Ok(())
    }

    /// Fetches a complete list of capabilities from the TPM, handling
    /// pagination.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) returned by
    /// [`get_capability_page`](TpmDevice::get_capability_page) or by the
    /// `extract` closure.
    fn get_capability<T, F, N>(
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
            let (more_data, cap_data) =
                self.get_capability_page(cap, TpmUint32(prop), TpmUint32(count))?;
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
    /// Returns [`OperationFailed`](crate::TpmDeviceError::OperationFailed) when
    /// the handle count cannot be represented as `u32`. Propagates any
    /// [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`get_capability`](TpmDevice::get_capability), including
    /// [`CapabilityMissing`](crate::TpmDeviceError::CapabilityMissing) when the
    /// TPM does not report algorithm properties.
    pub fn fetch_algorithm_properties(&mut self) -> Result<Vec<TpmsAlgProperty>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Algs,
            0,
            u32::try_from(MAX_HANDLES).map_err(|_| TpmDeviceError::OperationFailed)?,
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
    /// Returns [`OperationFailed`](crate::TpmDeviceError::OperationFailed) when
    /// the handle count cannot be represented as `u32`. Propagates any
    /// [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`get_capability`](TpmDevice::get_capability), including
    /// [`CapabilityMissing`](crate::TpmDeviceError::CapabilityMissing) when the
    /// TPM does not report handles of the requested class.
    pub fn fetch_handles(&mut self, class: TpmHt) -> Result<Vec<TpmHandle>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Handles,
            (class as u32) << 24,
            u32::try_from(MAX_HANDLES).map_err(|_| TpmDeviceError::OperationFailed)?,
            |caps| match caps {
                TpmuCapabilities::Handles(handles) => Ok(handles),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Handles)),
            },
            |last| last.value() + 1,
        )
        .map(|handles| handles.into_iter().collect())
    }

    /// Retrieves all available ECC curves supported by the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`OperationFailed`](crate::TpmDeviceError::OperationFailed) when
    /// the handle count cannot be represented as `u32`. Propagates any
    /// [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`get_capability`](TpmDevice::get_capability), including
    /// [`CapabilityMissing`](crate::TpmDeviceError::CapabilityMissing) when the
    /// TPM does not report ECC curves.
    pub fn fetch_ecc_curves(&mut self) -> Result<Vec<TpmEccCurve>, TpmDeviceError> {
        self.get_capability(
            TpmCap::EccCurves,
            0,
            u32::try_from(MAX_HANDLES).map_err(|_| TpmDeviceError::OperationFailed)?,
            |caps| match caps {
                TpmuCapabilities::EccCurves(curves) => Ok(curves),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::EccCurves)),
            },
            |last| *last as u32 + 1,
        )
    }

    /// Retrieves the list of active PCR banks and the bank selection mask.
    ///
    /// # Errors
    ///
    /// Returns [`OperationFailed`](crate::TpmDeviceError::OperationFailed) when
    /// the handle count cannot be represented as `u32`. Propagates any
    /// [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`get_capability`](TpmDevice::get_capability), including
    /// [`CapabilityMissing`](crate::TpmDeviceError::CapabilityMissing) when the
    /// TPM does not report PCRs.
    /// Returns [`PcrBanksNotAvailable`](crate::TpmDeviceError::PcrBanksNotAvailable)
    /// if the list of banks is empty or if no banks have allocated PCRs.
    /// Returns [`PcrBankSelectionMismatch`](crate::TpmDeviceError::PcrBankSelectionMismatch)
    /// if the PCR selection mask is not identical across all active banks.
    pub fn fetch_pcr_bank_list(
        &mut self,
    ) -> Result<(Vec<TpmAlgId>, TpmsPcrSelect), TpmDeviceError> {
        let pcrs: Vec<TpmsPcrSelection> = self.get_capability(
            TpmCap::Pcrs,
            0,
            u32::try_from(MAX_HANDLES).map_err(|_| TpmDeviceError::OperationFailed)?,
            |caps| match caps {
                TpmuCapabilities::Pcrs(pcrs) => Ok(pcrs),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Pcrs)),
            },
            |last| last.hash as u32 + 1,
        )?;

        if pcrs.is_empty() {
            return Err(TpmDeviceError::PcrBanksNotAvailable);
        }

        let mut common_select: Option<TpmsPcrSelect> = None;
        let mut algs = Vec::with_capacity(pcrs.len());

        for bank in pcrs {
            if bank.pcr_select.iter().all(|&b| b == 0) {
                debug!(
                    "skipping unallocated bank {:?} (mask: {})",
                    bank.hash,
                    hex::encode(&*bank.pcr_select)
                );
                continue;
            }

            if let Some(ref select) = common_select {
                if bank.pcr_select != *select {
                    return Err(TpmDeviceError::PcrBankSelectionMismatch);
                }
            } else {
                common_select = Some(bank.pcr_select);
            }
            algs.push(bank.hash);
        }

        let select = common_select.ok_or(TpmDeviceError::PcrBanksNotAvailable)?;

        algs.sort();
        Ok((algs, select))
    }

    /// Fetches and returns one page of capabilities of a certain type from the
    /// TPM.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`transmit`](TpmDevice::transmit). Returns
    /// [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch) when the
    /// TPM response does not contain `TPM2_GetCapability` data.
    fn get_capability_page(
        &mut self,
        cap: TpmCap,
        property: TpmUint32,
        property_count: TpmUint32,
    ) -> Result<(bool, TpmsCapabilityData), TpmDeviceError> {
        let cmd = TpmGetCapabilityCommand {
            cap,
            property,
            property_count,
            handles: [],
        };

        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let TpmGetCapabilityResponse {
            more_data,
            capability_data,
            handles: [],
        } = resp
            .GetCapability()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::GetCapability))?;

        Ok((more_data.into(), capability_data))
    }

    /// Reads a specific TPM property.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityMissing`](crate::TpmDeviceError::CapabilityMissing)
    /// when the TPM does not report the requested property. Propagates any
    /// [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`get_capability_page`](TpmDevice::get_capability_page).
    pub fn get_tpm_property(&mut self, property: TpmPt) -> Result<TpmUint32, TpmDeviceError> {
        let (_, cap_data) = self.get_capability_page(
            TpmCap::TpmProperties,
            TpmUint32(property as u32),
            TpmUint32(1),
        )?;

        let TpmuCapabilities::TpmProperties(props) = &cap_data.data else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        let Some(prop) = props.iter().find(|prop| prop.property == property) else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        Ok(prop.value)
    }

    /// Reads the public area of a TPM object.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`transmit`](TpmDevice::transmit). Returns
    /// [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch) when the
    /// TPM response does not contain `TPM2_ReadPublic` data.
    pub fn read_public(
        &mut self,
        handle: TpmHandle,
    ) -> Result<(TpmtPublic, Tpm2bName), TpmDeviceError> {
        if let Some(cached) = self.name_cache.get(&handle.0) {
            return Ok(cached.clone());
        }

        let cmd = TpmReadPublicCommand { handles: [handle] };
        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;

        let read_public_resp = resp
            .ReadPublic()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ReadPublic))?;

        let public = read_public_resp.out_public.inner;
        let name = read_public_resp.name;

        self.name_cache.insert(handle.0, (public.clone(), name));
        Ok((public, name))
    }

    /// Finds a persistent handle by its `Tpm2bName`.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`fetch_handles`](TpmDevice::fetch_handles) and
    /// [`read_public`](TpmDevice::read_public), except for TPM reference and
    /// handle errors with base
    /// [`ReferenceH0`](tpm2_protocol::data::TpmRcBase::ReferenceH0) or
    /// [`Handle`](tpm2_protocol::data::TpmRcBase::Handle), which are treated as
    /// invalid handles and skipped.
    pub fn find_persistent(
        &mut self,
        target_name: &Tpm2bName,
    ) -> Result<Option<TpmHandle>, TpmDeviceError> {
        for handle in self.fetch_handles(TpmHt::Persistent)? {
            match self.read_public(handle) {
                Ok((_, name)) => {
                    if name == *target_name {
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
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`transmit`](TpmDevice::transmit). Returns
    /// [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch) when the
    /// TPM response does not contain `TPM2_ContextSave` data.
    pub fn save_context(&mut self, save_handle: TpmHandle) -> Result<TpmsContext, TpmDeviceError> {
        let cmd = TpmContextSaveCommand {
            handles: [save_handle],
        };
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
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`transmit`](TpmDevice::transmit). Returns
    /// [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch) when the
    /// TPM response does not contain `TPM2_ContextLoad` data.
    pub fn load_context(&mut self, context: TpmsContext) -> Result<TpmHandle, TpmDeviceError> {
        let cmd = TpmContextLoadCommand {
            context,
            handles: [],
        };
        let (resp, _) = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let resp_inner = resp
            .ContextLoad()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ContextLoad))?;
        Ok(resp_inner.handles[0])
    }

    /// Flushes a transient object or session from the TPM and removes it from
    /// the cache.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`transmit`](TpmDevice::transmit).
    pub fn flush_context(&mut self, handle: TpmHandle) -> Result<(), TpmDeviceError> {
        self.name_cache.remove(&handle.0);
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
            handles: [],
        };
        self.transmit(&cmd, Self::NO_SESSIONS)?;
        Ok(())
    }

    /// Loads a session context and then flushes the resulting handle.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`load_context`](TpmDevice::load_context) or
    /// [`flush_context`](TpmDevice::flush_context) except for TPM reference
    /// errors with base
    /// [`ReferenceH0`](tpm2_protocol::data::TpmRcBase::ReferenceH0) or
    /// [`Handle`](tpm2_protocol::data::TpmRcBase::Handle), which are treated as
    /// a successful no-op.
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

    /// Refreshes a key context. Returns `true` if the context is still valid,
    /// and `false` if it is stale.
    ///
    /// # Errors
    ///
    /// Propagates any [`TpmDeviceError`](crate::TpmDeviceError) from
    /// [`load_context`](TpmDevice::load_context) or
    /// [`flush_context`](TpmDevice::flush_context) except for TPM reference
    /// errors with base
    /// [`ReferenceH0`](tpm2_protocol::data::TpmRcBase::ReferenceH0), which are
    /// treated as a stale context and reported as `Ok(false)`.
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
