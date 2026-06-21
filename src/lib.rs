// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use nix::{
    fcntl,
    poll::{PollFd, PollFlags, poll},
};
use rand::{RngCore, thread_rng};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd},
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use core::fmt;
use tpm2_crypto::TpmHash;
use tpm2_protocol::{
    TpmCast, TpmError, TpmField, TpmWriter,
    basic::{Tpm2b as Tpm2bWire, TpmBuffer, TpmHandle, TpmList, TpmUint16, TpmUint32, TpmUint64},
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
        Tpm2bPublicKeyRsa, Tpm2bSymKey, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmHt, TpmPt, TpmRc,
        TpmRcBase, TpmRh, TpmSe, TpmSt, TpmaAlgorithm, TpmaCc, TpmaObject, TpmaSession, TpmiYesNo,
        TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsEccParms,
        TpmsEccPoint, TpmsKeyedhashParms, TpmsPcrSelect, TpmsPcrSelection, TpmsRsaParms,
        TpmsSchemeHash, TpmsSchemeXor, TpmsSymcipherParms, TpmsTaggedProperty, TpmtEccScheme,
        TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject,
        TpmuAsymScheme, TpmuCapabilities, TpmuKdfScheme, TpmuKeyedhashScheme, TpmuPublicId,
        TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    frame::{
        TpmAuthCommands, TpmCommandValue as TpmCommand, TpmContextLoadCommand,
        TpmContextSaveCommand, TpmFlushContextCommand, TpmFrame, TpmGetCapabilityCommand,
        TpmReadPublicCommand, TpmResponse, TpmResponseOutcome, TpmResponseView,
        TpmStartAuthSessionCommand,
        tpm_marshal_command,
    },
};
use tracing::{debug, trace};

/// Errors that can occur when talking to a TPM device.
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `UnexpectedEof` becomes `unexpected eof`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
#[non_exhaustive]
pub enum TpmDeviceError {
    /// The TPM device is already mutably borrowed.
    AlreadyBorrowed,

    /// The requested capability is not available from the TPM.
    CapabilityMissing(TpmCap),

    /// The operation was interrupted by the caller.
    Interrupted,

    /// An invalid command code was used.
    InvalidCc(tpm2_protocol::data::TpmCc),

    /// The TPM returned an invalid or malformed response.
    InvalidResponse,

    /// An I/O error occurred when accessing the TPM device.
    Io(std::io::Error),

    /// Marshaling a TPM protocol encoded object failed.
    Marshal(TpmError),

    /// No TPM device is available.
    NotAvailable,

    /// No PCR banks are available on the TPM.
    PcrBanksNotAvailable,

    /// The PCR selection masks differ between active banks.
    PcrBankSelectionMismatch,

    /// The TPM response did not match the expected command code.
    ResponseMismatch(TpmCc),

    /// The TPM command timed out.
    Timeout,

    /// The TPM returned an error code.
    TpmRc(TpmRc),

    /// Trailing data after the response.
    TrailingData,

    /// Unmarshaling a TPM protocol encoded object failed.
    Unmarshal(TpmError),

    /// An unexpected end-of-file was encountered.
    UnexpectedEof,

    /// The requested algorithm is not supported.
    UnsupportedAlgorithm(TpmAlgId),
}

impl fmt::Display for TpmDeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for TpmDeviceError {}

impl PartialEq for TpmDeviceError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::CapabilityMissing(a), Self::CapabilityMissing(b)) => a == b,
            (Self::InvalidCc(a), Self::InvalidCc(b))
            | (Self::ResponseMismatch(a), Self::ResponseMismatch(b)) => a == b,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::Marshal(a), Self::Marshal(b)) | (Self::Unmarshal(a), Self::Unmarshal(b)) => {
                a == b
            }
            (Self::TpmRc(a), Self::TpmRc(b)) => a == b,
            (Self::UnsupportedAlgorithm(a), Self::UnsupportedAlgorithm(b)) => a == b,
            (Self::AlreadyBorrowed, Self::AlreadyBorrowed)
            | (Self::Interrupted, Self::Interrupted)
            | (Self::InvalidResponse, Self::InvalidResponse)
            | (Self::NotAvailable, Self::NotAvailable)
            | (Self::PcrBanksNotAvailable, Self::PcrBanksNotAvailable)
            | (Self::PcrBankSelectionMismatch, Self::PcrBankSelectionMismatch)
            | (Self::Timeout, Self::Timeout)
            | (Self::TrailingData, Self::TrailingData)
            | (Self::UnexpectedEof, Self::UnexpectedEof) => true,
            _ => false,
        }
    }
}

impl Eq for TpmDeviceError {}

impl From<TpmRc> for TpmDeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

impl From<std::io::Error> for TpmDeviceError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
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
/// is present.
/// Returns [`AlreadyBorrowed`](crate::TpmDeviceError::AlreadyBorrowed) when the
/// device is already mutably borrowed.
/// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants depending
/// on function.
pub fn with_device<F, T, E>(device: Option<&Rc<RefCell<TpmDevice>>>, function: F) -> Result<T, E>
where
    F: FnOnce(&mut TpmDevice) -> Result<T, E>,
    E: From<TpmDeviceError>,
{
    let device_rc = device.ok_or(TpmDeviceError::NotAvailable)?;
    let mut device_guard = device_rc
        .try_borrow_mut()
        .map_err(|_| TpmDeviceError::AlreadyBorrowed)?;
    function(&mut device_guard)
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
            interrupted: self.interrupted,
            timeout: self.timeout,
            command: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
            response: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
        })
    }
}

pub struct TpmDevice {
    file: File,
    interrupted: Box<dyn Fn() -> bool>,
    timeout: Duration,
    command: Vec<u8>,
    response: Vec<u8>,
}

impl std::fmt::Debug for TpmDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("file", &self.file)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl TpmDevice {
    const NO_SESSIONS: &'static [TpmsAuthCommand] = &[];

    /// Number of items requested per paginated `GetCapability` query.
    #[allow(clippy::cast_possible_truncation)]
    const CAPABILITY_PAGE_SIZE: u32 = MAX_HANDLES as u32;

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
    /// Returns [`Io`](crate::TpmDeviceError::Io) when a write, flush, or read
    /// operation on the device file fails, or when polling the device file
    /// descriptor fails.
    /// Returns [`Marshal`](crate::TpmDeviceError::Marshal) when marshal
    /// operation on TPM protocol compliant data fails.
    /// Returns [`Timeout`](crate::TpmDeviceError::Timeout) when the TPM does
    /// not respond within the configured timeout.
    /// Returns [`TpmRc`](crate::TpmDeviceError::TpmRc) when the TPM returns an
    /// error code.
    /// Returns [`Unmarshal`](crate::TpmDeviceError::Unmarshal) when unmarshal
    /// operation on TPM protocol compliant data fails.
    pub fn transmit<C: TpmFrame>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<&TpmResponse, TpmDeviceError> {
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
                    return Err(TpmDeviceError::TrailingData);
                }
            }
        }

        let response = TpmResponse::cast(&self.response).map_err(TpmDeviceError::Unmarshal)?;
        let outcome = TpmResponseView::cast(cc, response).map_err(TpmDeviceError::Unmarshal)?;
        trace!("{} R: {}", cc, hex::encode(&self.response));
        match outcome {
            TpmResponseOutcome::Dispatched(_) => Ok(response),
            TpmResponseOutcome::Rejected(rc) => Err(TpmDeviceError::TpmRc(rc)),
        }
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
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
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
                self.get_capability_page(cap, TpmUint32::from(prop), TpmUint32::from(count))?;
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
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn fetch_algorithm_properties(&mut self) -> Result<Vec<TpmsAlgProperty>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Algs,
            0,
            Self::CAPABILITY_PAGE_SIZE,
            |caps| match caps {
                TpmuCapabilities::Algs(algs) => Ok(algs),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Algs)),
            },
            |last| u32::from(last.alg.value()) + 1,
        )
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn fetch_handles(&mut self, class: TpmHt) -> Result<Vec<TpmHandle>, TpmDeviceError> {
        self.get_capability(
            TpmCap::Handles,
            (class as u32) << 24,
            Self::CAPABILITY_PAGE_SIZE,
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
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn fetch_ecc_curves(&mut self) -> Result<Vec<TpmEccCurve>, TpmDeviceError> {
        self.get_capability(
            TpmCap::EccCurves,
            0,
            Self::CAPABILITY_PAGE_SIZE,
            |caps| match caps {
                TpmuCapabilities::EccCurves(curves) => Ok(curves),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::EccCurves)),
            },
            |last| u32::from(last.value()) + 1,
        )
    }

    /// Retrieves the list of active PCR banks and the bank selection mask.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`PcrBanksNotAvailable`](crate::TpmDeviceError::PcrBanksNotAvailable)
    /// when no PCR banks are available.
    /// Return
    /// [`PcrBankSelectionMismatch`](crate::TpmDeviceError::PcrBankSelectionMismatch)
    /// when the PCR selection masks differ between active banks.
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn fetch_pcr_bank_list(
        &mut self,
    ) -> Result<(Vec<TpmAlgId>, TpmsPcrSelect), TpmDeviceError> {
        let pcrs: Vec<TpmsPcrSelection> = self.get_capability(
            TpmCap::Pcrs,
            0,
            Self::CAPABILITY_PAGE_SIZE,
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
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
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

        let response = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let (_, parameters) = response_parts(response, 0)?;
        let (more_data, parameters) = parse_field_value::<TpmiYesNo>(parameters)?;
        let (capability_data, rest) = parse_capability_data(parameters)?;
        ensure_empty(rest)?;

        Ok((more_data.into(), capability_data))
    }

    /// Reads a specific TPM property.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn fetch_tpm_property(&mut self, property: TpmPt) -> Result<u32, TpmDeviceError> {
        let (_, cap_data) = self.get_capability_page(
            TpmCap::TpmProperties,
            TpmUint32::from(property as u32),
            TpmUint32::from(1),
        )?;

        let TpmuCapabilities::TpmProperties(props) = &cap_data.data else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        let Some(prop) = props.iter().find(|prop| prop.property == property) else {
            return Err(TpmDeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        Ok(prop.value.value())
    }

    /// Reads the public area of a TPM object.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn read_public(
        &mut self,
        handle: TpmHandle,
    ) -> Result<(TpmtPublic, Tpm2bName), TpmDeviceError> {
        let cmd = TpmReadPublicCommand { handles: [handle] };
        let response = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let (_, parameters) = response_parts(response, 0)?;
        let (public, parameters) = parse_tpm2b_public(parameters)?;
        let (name, parameters): (Tpm2bName, _) = parse_tpm2b_buffer(parameters)?;
        let (_qualified_name, rest): (Tpm2bName, _) = parse_tpm2b_buffer(parameters)?;
        ensure_empty(rest)?;

        Ok((public, name))
    }

    /// Finds a persistent handle by its `Tpm2bName`.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
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
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn save_context(&mut self, save_handle: TpmHandle) -> Result<TpmsContext, TpmDeviceError> {
        let cmd = TpmContextSaveCommand {
            handles: [save_handle],
        };
        let response = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let (_, parameters) = response_parts(response, 0)?;
        let (context, rest) = parse_tpms_context(parameters)?;
        ensure_empty(rest)?;

        Ok(context)
    }

    /// Loads a TPM context and returns the handle.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch)
    /// when receiving unepected TPM response.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn load_context(&mut self, context: TpmsContext) -> Result<TpmHandle, TpmDeviceError> {
        let cmd = TpmContextLoadCommand {
            context,
            handles: [],
        };
        let response = self.transmit(&cmd, Self::NO_SESSIONS)?;
        let (handles, parameters) = response_parts(response, 1)?;
        let (handle, rest) = parse_wire_copy::<TpmHandle>(handles)?;
        ensure_empty(rest)?;
        ensure_empty(parameters)?;

        Ok(handle)
    }

    /// Flushes a transient object or session from the TPM and removes it from
    /// the cache.
    ///
    /// # Errors
    ///
    /// Returns [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn flush_context(&mut self, handle: TpmHandle) -> Result<(), TpmDeviceError> {
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
    /// Returns [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
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
}

fn ensure_empty(buf: &[u8]) -> Result<(), TpmDeviceError> {
    if buf.is_empty() {
        Ok(())
    } else {
        Err(TpmDeviceError::TrailingData)
    }
}

fn response_parts(
    response: &TpmResponse,
    response_handles: usize,
) -> Result<(&[u8], &[u8]), TpmDeviceError> {
    let handle_len = response_handles
        .checked_mul(core::mem::size_of::<TpmHandle>())
        .ok_or(TpmDeviceError::InvalidResponse)?;
    let body = response.body();
    if body.len() < handle_len {
        return Err(TpmDeviceError::InvalidResponse);
    }

    let (handles, after_handles) = body.split_at(handle_len);
    if response.tag().map_err(TpmDeviceError::Unmarshal)? != TpmSt::Sessions {
        return Ok((handles, after_handles));
    }

    let (parameter_size, after_size) = parse_wire_copy::<TpmUint32>(after_handles)?;
    let parameter_size =
        usize::try_from(parameter_size.value()).map_err(|_| TpmDeviceError::InvalidResponse)?;
    if after_size.len() < parameter_size {
        return Err(TpmDeviceError::InvalidResponse);
    }

    let (parameters, _auth_area) = after_size.split_at(parameter_size);
    Ok((handles, parameters))
}

fn parse_wire_copy<'a, T>(buf: &'a [u8]) -> Result<(T, &'a [u8]), TpmDeviceError>
where
    T: TpmCast + Copy + 'a,
{
    let (value, rest) = T::cast_prefix(buf).map_err(TpmDeviceError::Unmarshal)?;
    Ok((*value, rest))
}

fn parse_field_value<'a, T>(buf: &'a [u8]) -> Result<(T, &'a [u8]), TpmDeviceError>
where
    T: TpmField<'a, View = T>,
{
    <T as TpmField<'a>>::cast_prefix_field(buf).map_err(TpmDeviceError::Unmarshal)
}

fn parse_tpm2b_buffer<const CAPACITY: usize>(
    buf: &[u8],
) -> Result<(TpmBuffer<CAPACITY>, &[u8]), TpmDeviceError> {
    let (value, rest) =
        Tpm2bWire::<CAPACITY>::cast_prefix(buf).map_err(TpmDeviceError::Unmarshal)?;
    let value = TpmBuffer::<CAPACITY>::try_from(value.data()).map_err(TpmDeviceError::Unmarshal)?;

    Ok((value, rest))
}

fn parse_tpms_scheme_hash(buf: &[u8]) -> Result<(TpmsSchemeHash, &[u8]), TpmDeviceError> {
    let (hash_alg, rest) = parse_field_value::<TpmAlgId>(buf)?;

    Ok((TpmsSchemeHash { hash_alg }, rest))
}

fn parse_tpmt_kdf_scheme(buf: &[u8]) -> Result<(TpmtKdfScheme, &[u8]), TpmDeviceError> {
    let (scheme, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (details, rest) = parse_tpmu_kdf_scheme(scheme, buf)?;

    Ok((TpmtKdfScheme { scheme, details }, rest))
}

fn parse_tpmu_kdf_scheme(
    scheme: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuKdfScheme, &[u8]), TpmDeviceError> {
    match scheme {
        TpmAlgId::Mgf1 => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuKdfScheme::Mgf1(details), rest))
        }
        TpmAlgId::Kdf1Sp800_56A => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuKdfScheme::Kdf1Sp800_56a(details), rest))
        }
        TpmAlgId::Kdf2 => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuKdfScheme::Kdf2(details), rest))
        }
        TpmAlgId::Kdf1Sp800_108 => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuKdfScheme::Kdf1Sp800_108(details), rest))
        }
        TpmAlgId::Null => Ok((TpmuKdfScheme::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpms_scheme_xor(buf: &[u8]) -> Result<(TpmsSchemeXor, &[u8]), TpmDeviceError> {
    let (hash_alg, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (kdf, rest) = parse_tpmt_kdf_scheme(buf)?;

    Ok((TpmsSchemeXor { hash_alg, kdf }, rest))
}

fn parse_tpmu_keyedhash_scheme(
    scheme: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuKeyedhashScheme, &[u8]), TpmDeviceError> {
    match scheme {
        TpmAlgId::Hmac => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuKeyedhashScheme::Hmac(details), rest))
        }
        TpmAlgId::Xor => {
            let (details, rest) = parse_tpms_scheme_xor(buf)?;
            Ok((TpmuKeyedhashScheme::Xor(details), rest))
        }
        TpmAlgId::Null => Ok((TpmuKeyedhashScheme::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpmt_keyedhash_scheme(buf: &[u8]) -> Result<(TpmtKeyedhashScheme, &[u8]), TpmDeviceError> {
    let (scheme, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (details, rest) = parse_tpmu_keyedhash_scheme(scheme, buf)?;

    Ok((TpmtKeyedhashScheme { scheme, details }, rest))
}

fn parse_tpmu_asym_scheme(
    scheme: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuAsymScheme, &[u8]), TpmDeviceError> {
    match scheme {
        TpmAlgId::Rsassa
        | TpmAlgId::Rsapss
        | TpmAlgId::Ecdsa
        | TpmAlgId::Ecdaa
        | TpmAlgId::Sm2
        | TpmAlgId::Ecschnorr
        | TpmAlgId::Oaep
        | TpmAlgId::Ecdh
        | TpmAlgId::Ecmqv => {
            let (details, rest) = parse_tpms_scheme_hash(buf)?;
            Ok((TpmuAsymScheme::Hash(details), rest))
        }
        TpmAlgId::Rsaes | TpmAlgId::Null => Ok((TpmuAsymScheme::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpmt_rsa_scheme(buf: &[u8]) -> Result<(TpmtRsaScheme, &[u8]), TpmDeviceError> {
    let (scheme, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (details, rest) = parse_tpmu_asym_scheme(scheme, buf)?;

    Ok((TpmtRsaScheme { scheme, details }, rest))
}

fn parse_tpmt_ecc_scheme(buf: &[u8]) -> Result<(TpmtEccScheme, &[u8]), TpmDeviceError> {
    let (scheme, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (details, rest) = parse_tpmu_asym_scheme(scheme, buf)?;

    Ok((TpmtEccScheme { scheme, details }, rest))
}

fn parse_tpmu_sym_key_bits(
    algorithm: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuSymKeyBits, &[u8]), TpmDeviceError> {
    match algorithm {
        TpmAlgId::Aes => {
            let (value, rest) = parse_wire_copy::<TpmUint16>(buf)?;
            Ok((TpmuSymKeyBits::Aes(value), rest))
        }
        TpmAlgId::Sm4 => {
            let (value, rest) = parse_wire_copy::<TpmUint16>(buf)?;
            Ok((TpmuSymKeyBits::Sm4(value), rest))
        }
        TpmAlgId::Camellia => {
            let (value, rest) = parse_wire_copy::<TpmUint16>(buf)?;
            Ok((TpmuSymKeyBits::Camellia(value), rest))
        }
        TpmAlgId::Xor => {
            let (value, rest) = parse_field_value::<TpmAlgId>(buf)?;
            Ok((TpmuSymKeyBits::Xor(value), rest))
        }
        TpmAlgId::Null => Ok((TpmuSymKeyBits::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpmu_sym_mode(
    algorithm: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuSymMode, &[u8]), TpmDeviceError> {
    match algorithm {
        TpmAlgId::Aes => {
            let (value, rest) = parse_field_value::<TpmAlgId>(buf)?;
            Ok((TpmuSymMode::Aes(value), rest))
        }
        TpmAlgId::Sm4 => {
            let (value, rest) = parse_field_value::<TpmAlgId>(buf)?;
            Ok((TpmuSymMode::Sm4(value), rest))
        }
        TpmAlgId::Camellia => {
            let (value, rest) = parse_field_value::<TpmAlgId>(buf)?;
            Ok((TpmuSymMode::Camellia(value), rest))
        }
        TpmAlgId::Xor => {
            let (value, rest) = parse_field_value::<TpmAlgId>(buf)?;
            Ok((TpmuSymMode::Xor(value), rest))
        }
        TpmAlgId::Null => Ok((TpmuSymMode::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpmt_sym_def(buf: &[u8]) -> Result<(TpmtSymDefObject, &[u8]), TpmDeviceError> {
    let (algorithm, buf) = parse_field_value::<TpmAlgId>(buf)?;
    if algorithm == TpmAlgId::Null {
        return Ok((TpmtSymDefObject::default(), buf));
    }

    let (key_bits, buf) = parse_tpmu_sym_key_bits(algorithm, buf)?;
    let (mode, rest) = parse_tpmu_sym_mode(algorithm, buf)?;

    Ok((
        TpmtSymDefObject {
            algorithm,
            key_bits,
            mode,
        },
        rest,
    ))
}

fn parse_tpmu_public_parms(
    object_type: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuPublicParms, &[u8]), TpmDeviceError> {
    match object_type {
        TpmAlgId::KeyedHash => {
            let (scheme, rest) = parse_tpmt_keyedhash_scheme(buf)?;
            Ok((
                TpmuPublicParms::KeyedHash(TpmsKeyedhashParms { scheme }),
                rest,
            ))
        }
        TpmAlgId::SymCipher => {
            let (sym, rest) = parse_tpmt_sym_def(buf)?;
            Ok((TpmuPublicParms::SymCipher(TpmsSymcipherParms { sym }), rest))
        }
        TpmAlgId::Rsa => {
            let (symmetric, buf) = parse_tpmt_sym_def(buf)?;
            let (scheme, buf) = parse_tpmt_rsa_scheme(buf)?;
            let (key_bits, buf) = parse_wire_copy::<TpmUint16>(buf)?;
            let (exponent, rest) = parse_wire_copy::<TpmUint32>(buf)?;
            Ok((
                TpmuPublicParms::Rsa(TpmsRsaParms {
                    symmetric,
                    scheme,
                    key_bits,
                    exponent,
                }),
                rest,
            ))
        }
        TpmAlgId::Ecc => {
            let (symmetric, buf) = parse_tpmt_sym_def(buf)?;
            let (scheme, buf) = parse_tpmt_ecc_scheme(buf)?;
            let (curve_id, buf) = parse_field_value::<TpmEccCurve>(buf)?;
            let (kdf, rest) = parse_tpmt_kdf_scheme(buf)?;
            Ok((
                TpmuPublicParms::Ecc(TpmsEccParms {
                    symmetric,
                    scheme,
                    curve_id,
                    kdf,
                }),
                rest,
            ))
        }
        TpmAlgId::Null => Ok((TpmuPublicParms::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpms_ecc_point(buf: &[u8]) -> Result<(TpmsEccPoint, &[u8]), TpmDeviceError> {
    let (x, buf): (Tpm2bEccParameter, _) = parse_tpm2b_buffer(buf)?;
    let (y, rest): (Tpm2bEccParameter, _) = parse_tpm2b_buffer(buf)?;

    Ok((TpmsEccPoint { x, y }, rest))
}

fn parse_tpmu_public_id(
    object_type: TpmAlgId,
    buf: &[u8],
) -> Result<(TpmuPublicId, &[u8]), TpmDeviceError> {
    match object_type {
        TpmAlgId::KeyedHash => {
            let (value, rest): (Tpm2bDigest, _) = parse_tpm2b_buffer(buf)?;
            Ok((TpmuPublicId::KeyedHash(value), rest))
        }
        TpmAlgId::SymCipher => {
            let (value, rest): (Tpm2bSymKey, _) = parse_tpm2b_buffer(buf)?;
            Ok((TpmuPublicId::SymCipher(value), rest))
        }
        TpmAlgId::Rsa => {
            let (value, rest): (Tpm2bPublicKeyRsa, _) = parse_tpm2b_buffer(buf)?;
            Ok((TpmuPublicId::Rsa(value), rest))
        }
        TpmAlgId::Ecc => {
            let (value, rest) = parse_tpms_ecc_point(buf)?;
            Ok((TpmuPublicId::Ecc(value), rest))
        }
        TpmAlgId::Null => Ok((TpmuPublicId::Null, buf)),
        _ => Err(TpmDeviceError::InvalidResponse),
    }
}

fn parse_tpmt_public(buf: &[u8]) -> Result<(TpmtPublic, &[u8]), TpmDeviceError> {
    let (object_type, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (name_alg, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (object_attributes, buf) = parse_field_value::<TpmaObject>(buf)?;
    let (auth_policy, buf): (Tpm2bDigest, _) = parse_tpm2b_buffer(buf)?;
    let (parameters, buf) = parse_tpmu_public_parms(object_type, buf)?;
    let (unique, rest) = parse_tpmu_public_id(object_type, buf)?;

    Ok((
        TpmtPublic {
            object_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        },
        rest,
    ))
}

fn parse_tpm2b_public(buf: &[u8]) -> Result<(TpmtPublic, &[u8]), TpmDeviceError> {
    let (size, buf) = parse_wire_copy::<TpmUint16>(buf)?;
    let size = usize::from(size.value());
    if buf.len() < size {
        return Err(TpmDeviceError::InvalidResponse);
    }

    let (public, rest) = buf.split_at(size);
    let (public, public_rest) = parse_tpmt_public(public)?;
    ensure_empty(public_rest)?;

    Ok((public, rest))
}

fn parse_tpms_context(buf: &[u8]) -> Result<(TpmsContext, &[u8]), TpmDeviceError> {
    let (sequence, buf) = parse_wire_copy::<TpmUint64>(buf)?;
    let (saved_handle, buf) = parse_wire_copy::<TpmHandle>(buf)?;
    let (hierarchy, buf) = parse_field_value::<TpmRh>(buf)?;
    let (context_blob, rest): (TpmBuffer<TPM_MAX_COMMAND_SIZE>, _) = parse_tpm2b_buffer(buf)?;

    Ok((
        TpmsContext {
            sequence,
            saved_handle,
            hierarchy,
            context_blob,
        },
        rest,
    ))
}

fn parse_list<'a, T, const CAPACITY: usize>(
    buf: &'a [u8],
    mut parse_item: impl FnMut(&'a [u8]) -> Result<(T, &'a [u8]), TpmDeviceError>,
) -> Result<(TpmList<T, CAPACITY>, &'a [u8]), TpmDeviceError>
where
    T: Copy,
{
    let (count, mut cursor) = parse_wire_copy::<TpmUint32>(buf)?;
    let mut list = TpmList::<T, CAPACITY>::new();

    for _ in 0..count.value() {
        let (item, rest) = parse_item(cursor)?;
        list.try_push(item).map_err(TpmDeviceError::Unmarshal)?;
        cursor = rest;
    }

    Ok((list, cursor))
}

fn parse_tpms_alg_property(buf: &[u8]) -> Result<(TpmsAlgProperty, &[u8]), TpmDeviceError> {
    let (alg, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (alg_properties, rest) = parse_field_value::<TpmaAlgorithm>(buf)?;

    Ok((
        TpmsAlgProperty {
            alg,
            alg_properties,
        },
        rest,
    ))
}

fn parse_tpms_tagged_property(buf: &[u8]) -> Result<(TpmsTaggedProperty, &[u8]), TpmDeviceError> {
    let (property, buf) = parse_field_value::<TpmPt>(buf)?;
    let (value, rest) = parse_wire_copy::<TpmUint32>(buf)?;

    Ok((TpmsTaggedProperty { property, value }, rest))
}

fn parse_tpms_pcr_selection(buf: &[u8]) -> Result<(TpmsPcrSelection, &[u8]), TpmDeviceError> {
    let (hash, buf) = parse_field_value::<TpmAlgId>(buf)?;
    let (pcr_select, rest) =
        <TpmsPcrSelect as TpmField>::cast_prefix_field(buf).map_err(TpmDeviceError::Unmarshal)?;
    let pcr_select = TpmsPcrSelect::try_from(pcr_select).map_err(TpmDeviceError::Unmarshal)?;

    Ok((TpmsPcrSelection { hash, pcr_select }, rest))
}

fn parse_capability_data(buf: &[u8]) -> Result<(TpmsCapabilityData, &[u8]), TpmDeviceError> {
    let (capability, buf) = parse_field_value::<TpmCap>(buf)?;
    let (data, rest) = match capability {
        TpmCap::Algs => {
            let (list, rest) = parse_list::<TpmsAlgProperty, 64>(buf, parse_tpms_alg_property)?;
            (TpmuCapabilities::Algs(list), rest)
        }
        TpmCap::Handles => {
            let (list, rest) = parse_list::<TpmHandle, 128>(buf, parse_wire_copy::<TpmHandle>)?;
            (TpmuCapabilities::Handles(list), rest)
        }
        TpmCap::Pcrs => {
            let (list, rest) = parse_list::<TpmsPcrSelection, 8>(buf, parse_tpms_pcr_selection)?;
            (TpmuCapabilities::Pcrs(list), rest)
        }
        TpmCap::Commands => {
            let (list, rest) = parse_list::<TpmaCc, 256>(buf, parse_field_value::<TpmaCc>)?;
            (TpmuCapabilities::Commands(list), rest)
        }
        TpmCap::TpmProperties => {
            let (list, rest) =
                parse_list::<TpmsTaggedProperty, 64>(buf, parse_tpms_tagged_property)?;
            (TpmuCapabilities::TpmProperties(list), rest)
        }
        TpmCap::EccCurves => {
            let (list, rest) =
                parse_list::<TpmEccCurve, 64>(buf, parse_field_value::<TpmEccCurve>)?;
            (TpmuCapabilities::EccCurves(list), rest)
        }
        TpmCap::PpCommands | TpmCap::AuditCommands | TpmCap::AuthPolicies | TpmCap::Act => {
            return Err(TpmDeviceError::InvalidResponse);
        }
        _ => return Err(TpmDeviceError::InvalidResponse),
    };

    Ok((TpmsCapabilityData { capability, data }, rest))
}

/// A builder for creating a TPM policy session.
pub struct TpmPolicySessionBuilder {
    bind: TpmHandle,
    tpm_key: TpmHandle,
    nonce_caller: Option<Tpm2bNonce>,
    encrypted_salt: Option<Tpm2bEncryptedSecret>,
    session_type: TpmSe,
    symmetric: TpmtSymDefObject,
    auth_hash: TpmAlgId,
}

impl Default for TpmPolicySessionBuilder {
    fn default() -> Self {
        Self {
            bind: (TpmRh::Null as u32).into(),
            tpm_key: (TpmRh::Null as u32).into(),
            nonce_caller: None,
            encrypted_salt: None,
            session_type: TpmSe::Policy,
            symmetric: TpmtSymDefObject::default(),
            auth_hash: TpmAlgId::Sha256,
        }
    }
}

impl TpmPolicySessionBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_bind(mut self, bind: TpmHandle) -> Self {
        self.bind = bind;
        self
    }

    #[must_use]
    pub fn with_tpm_key(mut self, tpm_key: TpmHandle) -> Self {
        self.tpm_key = tpm_key;
        self
    }

    #[must_use]
    pub fn with_nonce_caller(mut self, nonce: Tpm2bNonce) -> Self {
        self.nonce_caller = Some(nonce);
        self
    }

    #[must_use]
    pub fn with_encrypted_salt(mut self, salt: Tpm2bEncryptedSecret) -> Self {
        self.encrypted_salt = Some(salt);
        self
    }

    #[must_use]
    pub fn with_session_type(mut self, session_type: TpmSe) -> Self {
        self.session_type = session_type;
        self
    }

    #[must_use]
    pub fn with_symmetric(mut self, symmetric: TpmtSymDefObject) -> Self {
        self.symmetric = symmetric;
        self
    }

    #[must_use]
    pub fn with_auth_hash(mut self, auth_hash: TpmAlgId) -> Self {
        self.auth_hash = auth_hash;
        self
    }

    /// Opens the policy session on the provided device.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseMismatch`](crate::TpmDeviceError::ResponseMismatch) if
    /// the TPM response is unexpected.
    /// Returns [`Unmarshal`](crate::TpmDeviceError::Unmarshal) when unmarshal
    /// operation on TPM protocol compliant data fails.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants depending
    /// on function.
    pub fn open(self, device: &mut TpmDevice) -> Result<TpmPolicySession, TpmDeviceError> {
        let nonce_caller = if let Some(nonce) = self.nonce_caller {
            nonce
        } else {
            let digest_len = TpmHash::try_from(self.auth_hash)
                .map_err(|_| TpmDeviceError::UnsupportedAlgorithm(self.auth_hash))?
                .size();
            let mut nonce_bytes = vec![0; digest_len];
            thread_rng().fill_bytes(&mut nonce_bytes);
            Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(TpmDeviceError::Unmarshal)?
        };

        let cmd = TpmStartAuthSessionCommand {
            nonce_caller,
            encrypted_salt: self.encrypted_salt.unwrap_or_default(),
            session_type: self.session_type,
            symmetric: self.symmetric,
            auth_hash: self.auth_hash,
            handles: [self.tpm_key, self.bind],
        };

        let response = device.transmit(&cmd, TpmDevice::NO_SESSIONS)?;
        let (handles, parameters) = response_parts(response, 1)?;
        let (handle, rest) = parse_wire_copy::<TpmHandle>(handles)?;
        ensure_empty(rest)?;
        let (nonce_tpm, rest): (Tpm2bNonce, _) = parse_tpm2b_buffer(parameters)?;
        ensure_empty(rest)?;

        Ok(TpmPolicySession {
            handle,
            attributes: TpmaSession::CONTINUE_SESSION,
            hash_alg: self.auth_hash,
            nonce_tpm,
        })
    }
}

/// Represents an active TPM policy session.
#[derive(Debug, Clone)]
pub struct TpmPolicySession {
    handle: TpmHandle,
    attributes: TpmaSession,
    hash_alg: TpmAlgId,
    nonce_tpm: Tpm2bNonce,
}

impl TpmPolicySession {
    /// Creates a new builder for `TpmPolicySession`.
    #[must_use]
    pub fn builder() -> TpmPolicySessionBuilder {
        TpmPolicySessionBuilder::new()
    }

    /// Returns the session handle.
    #[must_use]
    pub fn handle(&self) -> TpmHandle {
        self.handle
    }

    /// Returns the session attributes.
    #[must_use]
    pub fn attributes(&self) -> TpmaSession {
        self.attributes
    }

    /// Returns the hash algorithm used by the session.
    #[must_use]
    pub fn hash_alg(&self) -> TpmAlgId {
        self.hash_alg
    }

    /// Returns the nonce generated by the TPM.
    #[must_use]
    pub fn nonce_tpm(&self) -> &Tpm2bNonce {
        &self.nonce_tpm
    }

    /// Applies a list of policy commands to this session.
    ///
    /// This method iterates through the provided commands, updates the first handle
    /// of each command (or second for `PolicySecret`) to point to this session,
    /// and transmits them to the device.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCc`](crate::TpmDeviceError::InvalidCc) when a command is not
    /// a supported policy command.
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn run(
        &self,
        device: &mut TpmDevice,
        commands: impl IntoIterator<Item = (TpmCommand, TpmAuthCommands)>,
    ) -> Result<(), TpmDeviceError> {
        for (mut command_body, auth_sessions) in commands {
            match &mut command_body {
                TpmCommand::PolicyPcr(cmd) => cmd.handles[0] = self.handle,
                TpmCommand::PolicyOr(cmd) => cmd.handles[0] = self.handle,
                TpmCommand::PolicyRestart(cmd) => {
                    cmd.handles[0] = self.handle;
                }
                TpmCommand::PolicySecret(cmd) => {
                    cmd.handles[1] = self.handle;
                }
                _ => {
                    return Err(TpmDeviceError::InvalidCc(command_body.cc()));
                }
            }
            device.transmit(&command_body, auth_sessions.as_ref())?;
        }
        Ok(())
    }

    /// Flushes the session context from the TPM.
    ///
    /// # Errors
    ///
    /// Returns other [`TpmDeviceError`](crate::TpmDeviceError) variants when
    /// [`TpmDevice::transmit`](crate::TpmDevice::transmit) fails.
    pub fn flush(&self, device: &mut TpmDevice) -> Result<(), TpmDeviceError> {
        device.flush_context(self.handle)
    }
}
