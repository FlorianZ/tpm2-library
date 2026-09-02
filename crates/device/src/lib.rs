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
    TpmError, TpmWriter,
    basic::{TpmHandle, TpmUint32},
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmHt,
        TpmPt, TpmRc, TpmRcBase, TpmRh, TpmSe, TpmSt, TpmaSession, TpmsAlgProperty,
        TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsPcrSelect, TpmsPcrSelection,
        TpmtPublic, TpmtSymDefObject, TpmuCapabilities,
    },
    frame::{
        TpmAuthCommands, TpmCommandValue as TpmCommand, TpmContextLoadCommand,
        TpmContextLoadResponse, TpmContextSaveCommand, TpmContextSaveResponse,
        TpmFlushContextCommand, TpmFrame, TpmGetCapabilityCommand, TpmGetCapabilityResponse,
        TpmReadPublicCommand, TpmReadPublicResponse, TpmResponse, TpmResponseOutcome,
        TpmResponseView, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
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

/// A bidirectional, frame-oriented transport for marshaled TPM frames.
///
/// The two endpoints of a TPM exchange are symmetric on the wire: a host sends
/// command frames and receives response frames, while a responder such as an
/// emulator does the reverse. A `TpmTransport` therefore moves whole frames in
/// either direction, decoupling both ends from any concrete byte stream.
pub trait TpmTransport {
    /// Sends one complete marshaled frame.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::TpmDeviceError::Io) when writing the frame fails.
    fn send(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError>;

    /// Receives one complete frame into `buf`, replacing its contents.
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::TpmDeviceError::Io) when reading fails,
    /// [`Timeout`](crate::TpmDeviceError::Timeout) when no complete frame
    /// arrives in time, [`Interrupted`](crate::TpmDeviceError::Interrupted)
    /// when cancellation is requested, or
    /// [`InvalidResponse`](crate::TpmDeviceError::InvalidResponse) /
    /// [`TrailingData`](crate::TpmDeviceError::TrailingData) when the frame
    /// envelope is malformed.
    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError>;
}

const TPM_HEADER_SIZE: usize = 10;

/// Returns the total frame length declared by a TPM frame header.
///
/// # Errors
///
/// Returns [`InvalidResponse`](crate::TpmDeviceError::InvalidResponse) when the
/// header is shorter than its size field or declares a size outside the range
/// `[TPM_HEADER_SIZE, TPM_MAX_COMMAND_SIZE]`.
fn frame_size(header: &[u8]) -> Result<usize, TpmDeviceError> {
    let Some(size_bytes) = header.get(2..6) else {
        return Err(TpmDeviceError::InvalidResponse);
    };
    let Ok(size_bytes): Result<[u8; 4], _> = size_bytes.try_into() else {
        return Err(TpmDeviceError::InvalidResponse);
    };
    let size = u32::from_be_bytes(size_bytes) as usize;
    if !(TPM_HEADER_SIZE..=TPM_MAX_COMMAND_SIZE).contains(&size) {
        return Err(TpmDeviceError::InvalidResponse);
    }
    Ok(size)
}

fn fill_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), TpmDeviceError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(TpmDeviceError::UnexpectedEof)
        }
        Err(e) => Err(TpmDeviceError::Io(e)),
    }
}

/// Reads one complete TPM frame from a blocking stream into `buf`.
///
/// The header is read first to learn the frame's declared size, then exactly
/// that many bytes (header included) are read; `buf` is cleared beforehand. The
/// framing is identical for command and response frames, so this serves a host
/// reading responses and a responder reading commands alike.
///
/// # Errors
///
/// Returns [`UnexpectedEof`](crate::TpmDeviceError::UnexpectedEof) when the
/// stream ends before a complete frame, [`Io`](crate::TpmDeviceError::Io) on any
/// other read failure, or
/// [`InvalidResponse`](crate::TpmDeviceError::InvalidResponse) when the header
/// declares an out-of-range size.
pub fn read_frame<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError> {
    buf.clear();
    buf.resize(TPM_HEADER_SIZE, 0);
    fill_exact(reader, buf)?;

    let size = frame_size(buf)?;
    buf.resize(size, 0);
    fill_exact(reader, &mut buf[TPM_HEADER_SIZE..])?;

    Ok(())
}

/// Writes one complete marshaled TPM frame to a blocking stream and flushes it.
///
/// # Errors
///
/// Returns [`Io`](crate::TpmDeviceError::Io) when writing or flushing fails.
pub fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> Result<(), TpmDeviceError> {
    writer.write_all(frame).map_err(TpmDeviceError::Io)?;
    writer.flush().map_err(TpmDeviceError::Io)?;
    Ok(())
}

/// A [`TpmTransport`] over any blocking byte stream.
///
/// Suitable for TPM endpoints reached over TCP (such as a software TPM),
/// Unix-domain sockets, or in-memory pipes.
pub struct TpmStreamTransport<S: Read + Write> {
    stream: S,
}

impl<S: Read + Write> TpmStreamTransport<S> {
    /// Wraps a stream as a transport.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Consumes the transport and returns the underlying stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> TpmTransport for TpmStreamTransport<S> {
    fn send(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError> {
        write_frame(&mut self.stream, frame)
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError> {
        read_frame(&mut self.stream, buf)
    }
}

/// A [`TpmTransport`] backed by a Linux TPM character device.
pub struct TpmPosixDevice {
    file: File,
    interrupted: Box<dyn Fn() -> bool>,
    timeout: Duration,
}

impl TpmPosixDevice {
    /// Creates a new builder for a `TpmPosixDevice`.
    #[must_use]
    pub fn builder() -> TpmPosixDeviceBuilder {
        TpmPosixDeviceBuilder::default()
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
}

impl TpmTransport for TpmPosixDevice {
    fn send(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError> {
        self.file.write_all(frame)?;
        self.file.flush()?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError> {
        buf.clear();
        let start_time = Instant::now();
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
                buf.extend_from_slice(&temp_buf[..n]);
            }

            if total_size.is_none() && buf.len() >= TPM_HEADER_SIZE {
                total_size = Some(frame_size(buf)?);
            }

            if let Some(size) = total_size {
                if buf.len() == size {
                    break;
                }
                if buf.len() > size {
                    return Err(TpmDeviceError::TrailingData);
                }
            }
        }

        Ok(())
    }
}

/// A builder for constructing a [`TpmPosixDevice`].
pub struct TpmPosixDeviceBuilder {
    path: PathBuf,
    timeout: Duration,
    interrupted: Box<dyn Fn() -> bool>,
}

impl Default for TpmPosixDeviceBuilder {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/dev/tpmrm0"),
            timeout: Duration::from_mins(2),
            interrupted: Box::new(|| false),
        }
    }
}

impl TpmPosixDeviceBuilder {
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

    /// Opens the TPM character device and constructs the [`TpmPosixDevice`].
    ///
    /// # Errors
    ///
    /// Returns [`Io`](crate::TpmDeviceError::Io) when the device file cannot be
    /// opened or when configuring the file descriptor flags fails.
    pub fn build(self) -> Result<TpmPosixDevice, TpmDeviceError> {
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

        Ok(TpmPosixDevice {
            file,
            interrupted: self.interrupted,
            timeout: self.timeout,
        })
    }
}

pub struct TpmDevice {
    transport: Box<dyn TpmTransport>,
    command: Vec<u8>,
    response: Vec<u8>,
}

impl std::fmt::Debug for TpmDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmDevice").finish_non_exhaustive()
    }
}

impl TpmDevice {
    const NO_SESSIONS: &'static [TpmsAuthCommand] = &[];

    /// Number of items requested per paginated `GetCapability` query.
    #[allow(clippy::cast_possible_truncation)]
    const CAPABILITY_PAGE_SIZE: u32 = MAX_HANDLES as u32;

    /// Creates a `TpmDevice` driving the given transport.
    #[must_use]
    pub fn new(transport: Box<dyn TpmTransport>) -> Self {
        Self {
            transport,
            command: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
            response: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
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

        self.transport.send(&self.command)?;
        self.transport.recv(&mut self.response)?;

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

            if !more_data {
                break;
            }

            let Some(last) = items.last() else {
                break;
            };

            let next = next_prop(last);
            if next <= prop {
                break;
            }
            prop = next;
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
        let class_prefix = (class as u32) << 24;

        self.get_capability(
            TpmCap::Handles,
            class_prefix,
            Self::CAPABILITY_PAGE_SIZE,
            |caps| match caps {
                TpmuCapabilities::Handles(handles) => Ok(handles),
                _ => Err(TpmDeviceError::CapabilityMissing(TpmCap::Handles)),
            },
            |last| last.value().saturating_add(1),
        )
        .map(|handles| {
            handles
                .into_iter()
                .filter(|handle| handle.value() >> 24 == class as u32)
                .collect()
        })
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
        let body = response
            .unmarshal::<TpmGetCapabilityResponse>()
            .map_err(TpmDeviceError::Unmarshal)?;

        Ok((body.more_data.into(), body.capability_data))
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
        let body = response
            .unmarshal::<TpmReadPublicResponse>()
            .map_err(TpmDeviceError::Unmarshal)?;

        Ok((body.out_public.inner, body.name))
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
        let body = response
            .unmarshal::<TpmContextSaveResponse>()
            .map_err(TpmDeviceError::Unmarshal)?;

        Ok(body.context)
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
        let body = response
            .unmarshal::<TpmContextLoadResponse>()
            .map_err(TpmDeviceError::Unmarshal)?;
        let [handle] = body.handles;

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

/// The responder end of a [`TpmTransport`], for serving TPM commands.
///
/// Where a [`TpmDevice`] sends commands and receives responses, a `TpmResponder`
/// receives commands and sends responses. Both ends share the same transport
/// and frame codec; only the direction of use differs, which makes this crate
/// usable for the TPM side of an exchange, such as an emulator.
///
/// Command decoding and response marshaling are left to the caller (for example
/// via `tpm2_protocol`), keeping this type focused on transport and framing.
pub struct TpmResponder {
    transport: Box<dyn TpmTransport>,
    command: Vec<u8>,
}

impl std::fmt::Debug for TpmResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmResponder").finish_non_exhaustive()
    }
}

impl TpmResponder {
    /// Creates a `TpmResponder` serving over the given transport.
    #[must_use]
    pub fn new(transport: Box<dyn TpmTransport>) -> Self {
        Self {
            transport,
            command: Vec::with_capacity(TPM_MAX_COMMAND_SIZE),
        }
    }

    /// Receives the next command frame, returning its raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEof`](crate::TpmDeviceError::UnexpectedEof) when the
    /// peer disconnects, or other [`TpmDeviceError`](crate::TpmDeviceError)
    /// variants when the transport fails.
    pub fn recv_command(&mut self) -> Result<&[u8], TpmDeviceError> {
        self.transport.recv(&mut self.command)?;
        Ok(&self.command)
    }

    /// Sends a marshaled response frame.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmDeviceError`](crate::TpmDeviceError) when the transport
    /// fails to send the frame.
    pub fn send_response(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError> {
        self.transport.send(frame)
    }

    /// Serves commands until the peer disconnects.
    ///
    /// Each received command frame is passed to `handler`, whose returned bytes
    /// are written back as the response frame. Returns `Ok(())` once the peer
    /// closes the transport.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmDeviceError`](crate::TpmDeviceError) when receiving a
    /// command or sending a response fails for any reason other than a clean
    /// disconnect.
    pub fn serve<H>(&mut self, mut handler: H) -> Result<(), TpmDeviceError>
    where
        H: FnMut(&[u8]) -> Vec<u8>,
    {
        loop {
            match self.transport.recv(&mut self.command) {
                Ok(()) => {}
                Err(TpmDeviceError::UnexpectedEof) => return Ok(()),
                Err(e) => return Err(e),
            }
            let response = handler(&self.command);
            self.transport.send(&response)?;
        }
    }
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
        let body = response
            .unmarshal::<TpmStartAuthSessionResponse>()
            .map_err(TpmDeviceError::Unmarshal)?;
        let [handle] = body.handles;
        let nonce_tpm = body.nonce_tpm;

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
            // Policy commands take the policy session handle either as the
            // first handle (`sessionHandle`), the second handle for commands
            // with an entity (`authHandle`, `sessionHandle`), or the third
            // handle for commands with two preceding handles.
            let session_handle = self.handle;
            match &mut command_body {
                TpmCommand::PolicyPcr(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyOr(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyRestart(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyAuthorize(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyAuthValue(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyCommandCode(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyCounterTimer(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyCpHash(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyLocality(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyNameHash(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyTicket(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyPhysicalPresence(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyDuplicationSelect(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyGetDigest(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyPassword(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyNvWritten(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyTemplate(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyCapability(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyParameters(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicyTransportSpdm(cmd) => cmd.handles[0] = session_handle,
                TpmCommand::PolicySecret(cmd) => cmd.handles[1] = session_handle,
                TpmCommand::PolicySigned(cmd) => cmd.handles[1] = session_handle,
                TpmCommand::PolicyNv(cmd) => cmd.handles[2] = session_handle,
                TpmCommand::PolicyAuthorizeNv(cmd) => cmd.handles[2] = session_handle,
                TpmCommand::PolicyAcSendSelect(cmd) => cmd.handles[2] = session_handle,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Rc<RefCell<Vec<u8>>>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let size = u32::try_from(TPM_HEADER_SIZE + body.len()).unwrap();
        let mut frame = vec![0x80, 0x01];
        frame.extend_from_slice(&size.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn read_frame_reads_exactly_one_frame() {
        let first = frame(&[0xAA, 0xBB]);
        let mut bytes = first.clone();
        bytes.extend_from_slice(&frame(&[0xCC]));
        let mut reader = Cursor::new(bytes);

        let mut buf = Vec::new();
        read_frame(&mut reader, &mut buf).unwrap();

        assert_eq!(buf, first);
    }

    #[test]
    fn write_then_read_round_trips() {
        let expected = frame(&[1, 2, 3, 4]);
        let mut stream = Cursor::new(Vec::new());
        write_frame(&mut stream, &expected).unwrap();
        stream.set_position(0);

        let mut buf = Vec::new();
        read_frame(&mut stream, &mut buf).unwrap();

        assert_eq!(buf, expected);
    }

    #[test]
    fn stream_transport_sends_and_receives() {
        let response = frame(&[0x11, 0x22]);
        let command = frame(&[0x33]);
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut transport = TpmStreamTransport::new(Duplex {
            input: Cursor::new(response.clone()),
            output: Rc::clone(&output),
        });

        transport.send(&command).unwrap();
        let mut buf = Vec::new();
        transport.recv(&mut buf).unwrap();

        assert_eq!(buf, response);
        assert_eq!(*output.borrow(), command);
    }

    #[test]
    fn responder_serves_commands_until_disconnect() {
        let command = frame(&[0x01]);
        let response = frame(&[0x02, 0x03]);
        let output = Rc::new(RefCell::new(Vec::new()));
        let transport = TpmStreamTransport::new(Duplex {
            input: Cursor::new(command.clone()),
            output: Rc::clone(&output),
        });
        let mut responder = TpmResponder::new(Box::new(transport));

        let reply = response.clone();
        let mut served = 0;
        responder
            .serve(|cmd| {
                assert_eq!(cmd, command.as_slice());
                served += 1;
                reply.clone()
            })
            .unwrap();

        assert_eq!(served, 1);
        assert_eq!(*output.borrow(), response);
    }

    #[test]
    fn frame_size_rejects_short_header() {
        assert!(frame_size(&[0x80, 0x01, 0x00]).is_err());
    }

    #[test]
    fn read_frame_reports_unexpected_eof_on_truncation() {
        let mut reader = Cursor::new(vec![0x80, 0x01]);
        let mut buf = Vec::new();
        assert_eq!(
            read_frame(&mut reader, &mut buf),
            Err(TpmDeviceError::UnexpectedEof)
        );
    }
}
