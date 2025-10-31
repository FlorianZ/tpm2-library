// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::LogFormat, print::TpmPrint, spinner::Spinner, TEARDOWN};
use log::trace;
use nix::poll::{poll, PollFd, PollFlags};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    num::TryFromIntError,
    os::fd::{AsRawFd, BorrowedFd},
    rc::Rc,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use thiserror::Error;
use tpm2_policy_language::{Handle, HandleClass};
use tpm2_protocol::{
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bName, TpmCap, TpmCc, TpmHt, TpmPt, TpmRc, TpmRcBase, TpmSt, TpmsAlgProperty,
        TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmtPublic, TpmuCapabilities,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmBodyBuild,
        TpmContextLoadCommand, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader,
        TpmReadPublicCommand, TpmResponseBody,
    },
    TpmError, TpmHandle, TpmWriter,
};

/// A type-erased object safe TPM command object
pub trait TpmCommandObject: TpmPrint + TpmHeader + TpmBodyBuild {}
impl<T> TpmCommandObject for T where T: TpmHeader + TpmBodyBuild + TpmPrint {}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("device is already borrowed")]
    AlreadyBorrowed,
    #[error("capability not found: {0}")]
    CapabilityMissing(TpmCap),
    #[error("operation interrupted by user")]
    Interrupted,
    #[error("invalid response")]
    InvalidResponse,
    #[error("device not available")]
    NotAvailable,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("TPM command timed out")]
    Timeout,
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("syscall: {0}")]
    Nix(#[from] nix::Error),
    #[error("protocol: {0}")]
    TpmProtocol(TpmError),
    #[error("TPM return code: {0}")]
    TpmRc(TpmRc),
}

impl From<TpmError> for DeviceError {
    fn from(err: TpmError) -> Self {
        Self::TpmProtocol(err)
    }
}

impl From<TpmRc> for DeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

/// Executes a closure with a mutable reference to a `Device`.
///
/// This helper function centralizes the boilerplate for safely acquiring a
/// mutable borrow of a `Device` from the shared `Rc<RefCell<...>>`.
///
/// # Errors
///
/// Returns an error if the device is not available or is already borrowed. The
/// error is converted into the caller's error type `E`.
pub fn with_device<F, T, E>(device: Option<Rc<RefCell<Device>>>, f: F) -> Result<T, E>
where
    F: FnOnce(&mut Device) -> Result<T, E>,
    E: From<DeviceError>,
{
    let device_rc = device.ok_or(DeviceError::NotAvailable)?;
    let mut device_guard = device_rc
        .try_borrow_mut()
        .map_err(|_| DeviceError::AlreadyBorrowed)?;
    f(&mut device_guard)
}

#[derive(Debug)]
pub struct Device {
    file: File,
    log_format: LogFormat,
    name_cache: HashMap<u32, (TpmtPublic, Tpm2bName)>,
}

impl Device {
    /// Creates a new TPM device from an owned transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the system poller cannot be created.
    pub fn new(file: File, log_format: LogFormat) -> Result<Self, DeviceError> {
        Ok(Self {
            file,
            log_format,
            name_cache: HashMap::new(),
        })
    }

    /// Performs the whole TPM command transmission process.
    ///
    /// # Errors
    ///
    /// Returns [`Interrupted`](crate::device::DeviceError::Interrupted) when
    /// user interrupts the program.
    /// Returns [`Io`](crate::device::DeviceError::Io) when an I/O operation
    /// fails.
    /// Returns [`Timeout`](crate::device::DeviceError::Timeout) when the
    /// transmission timeouts.
    /// Returns [`TpmProtocol`](crate::device::DeviceError::TpmProtocol) when
    /// either built command or parsed response is malformed.
    /// Returns [`TpmRc`](crate::device::DeviceError::TpmRc) when the chip
    /// responses with a return code.
    #[allow(clippy::too_many_lines)]
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), DeviceError> {
        let command_vec = self.build_command_buffer(command, sessions)?;
        let cc = command.cc();

        let mut spinner = Spinner::new("Waiting for TPM...");

        self.file.write_all(&command_vec)?;
        self.file.flush()?;

        let raw = self.file.as_raw_fd();
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };

        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];

        let start_time = Instant::now();
        let mut resp_buf = Vec::with_capacity(TPM_MAX_COMMAND_SIZE);
        let mut total_size: Option<usize> = None;
        let mut temp_buf = [0u8; 1024];

        let resp_buf = loop {
            if TEARDOWN.load(Ordering::Relaxed) {
                break Err(DeviceError::Interrupted);
            }
            if start_time.elapsed() > Duration::from_secs(120) {
                break Err(DeviceError::Timeout);
            }

            spinner.tick();

            let num_events = match poll(&mut fds, 100u16) {
                Ok(num) => num,
                Err(nix::Error::EINTR) => continue,
                Err(e) => break Err(e.into()),
            };

            if num_events == 0 {
                continue;
            }

            let revents = fds[0].revents().unwrap_or(PollFlags::empty());

            if revents.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                break Err(DeviceError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }

            if revents.contains(PollFlags::POLLIN) {
                match self.file.read(&mut temp_buf) {
                    Ok(0) => {
                        if let Some(size) = total_size {
                            if resp_buf.len() == size {
                                break Ok(resp_buf);
                            }
                        }
                        break Err(DeviceError::Io(std::io::ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(n) => {
                        resp_buf.extend_from_slice(&temp_buf[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                    Err(e) => break Err(e.into()),
                }
            } else if revents.contains(PollFlags::POLLHUP) {
                if let Some(size) = total_size {
                    if resp_buf.len() == size {
                        break Ok(resp_buf);
                    }
                }
                break Err(DeviceError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }

            if total_size.is_none() && resp_buf.len() >= 10 {
                let Ok(size_bytes): Result<[u8; 4], _> = resp_buf[2..6].try_into() else {
                    break Err(DeviceError::InvalidResponse);
                };
                let size = u32::from_be_bytes(size_bytes) as usize;
                if !(10..=TPM_MAX_COMMAND_SIZE).contains(&size) {
                    break Err(DeviceError::InvalidResponse);
                }
                total_size = Some(size);
            }

            if let Some(size) = total_size {
                if resp_buf.len() == size {
                    break Ok(resp_buf);
                }
                if resp_buf.len() > size {
                    break Err(DeviceError::InvalidResponse);
                }
            }
        }?;

        let result = tpm_parse_response(cc, &resp_buf);
        if self.log_format == LogFormat::Pretty {
            let mut buf = Vec::new();
            match &result {
                Ok(Ok((response, _))) => {
                    response.print(&mut buf, "Response", 1)?;
                    for line in String::from_utf8_lossy(&buf).lines() {
                        trace!(target: "cli::device", "{line}");
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    trace!(
                        target: "cli::device",
                        "Response: {}",
                        hex::encode(&resp_buf)
                    );
                }
            }
        } else {
            trace!(
                target: "cli::device",
                "Response: {}",
                hex::encode(&resp_buf)
            );
        }
        Ok(result??)
    }

    fn build_command_buffer<C: TpmCommandObject>(
        &self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<Vec<u8>, DeviceError> {
        let cc = command.cc();
        let tag = if sessions.is_empty() {
            TpmSt::NoSessions
        } else {
            TpmSt::Sessions
        };
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_build_command(command, tag, sessions, &mut writer)?;
            writer.len()
        };
        buf.truncate(len);

        if self.log_format == LogFormat::Pretty {
            let mut print_buf = Vec::new();
            writeln!(&mut print_buf, "{cc}")?;
            command.print(&mut print_buf, "Command", 1)?;
            for line in String::from_utf8_lossy(&print_buf).lines() {
                trace!(target: "cli::device", "{line}");
            }
        } else {
            trace!(
                target: "cli::device",
                "Command: {}",
                hex::encode(&buf)
            );
        }
        Ok(buf)
    }

    /// Fetches a complete list of capabilities from the TPM, handling pagination.
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying `execute` call fails
    /// or if the TPM returns a response of an unexpected type.
    pub fn get_capability<T, F, N>(
        &mut self,
        cap: TpmCap,
        property_start: u32,
        count: u32,
        mut extract: F,
        next_prop: N,
    ) -> Result<Vec<T>, DeviceError>
    where
        T: Copy,
        F: for<'a> FnMut(&'a TpmuCapabilities) -> Result<&'a [T], DeviceError>,
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
    pub(crate) fn fetch_algorithm_properties(
        &mut self,
    ) -> Result<Vec<TpmsAlgProperty>, DeviceError> {
        self.get_capability(
            TpmCap::Algs,
            0,
            u32::try_from(MAX_HANDLES)?,
            |caps| match caps {
                TpmuCapabilities::Algs(algs) => Ok(algs),
                _ => Err(DeviceError::CapabilityMissing(TpmCap::Algs)),
            },
            |last| last.alg as u32 + 1,
        )
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the `get_capability_page` call to the TPM device fails.
    pub fn fetch_handles(&mut self, class: u32) -> Result<Vec<Handle>, DeviceError> {
        self.get_capability(
            TpmCap::Handles,
            class,
            u32::try_from(MAX_HANDLES)?,
            |caps| match caps {
                TpmuCapabilities::Handles(handles) => Ok(handles),
                _ => Err(DeviceError::CapabilityMissing(TpmCap::Handles)),
            },
            |last| *last + 1,
        )
        .map(|handles| {
            handles
                .into_iter()
                .map(|h| Handle::new(HandleClass::Tpm, h))
                .collect()
        })
    }

    /// Fetches and returns one page of capabilities of a certain type from the TPM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying `execute` call fails
    /// or if the TPM returns a response of an unexpected type.
    pub fn get_capability_page(
        &mut self,
        cap: TpmCap,
        property: u32,
        count: u32,
    ) -> Result<(bool, TpmsCapabilityData), DeviceError> {
        let cmd = TpmGetCapabilityCommand {
            cap,
            property,
            property_count: count,
        };
        let sessions = vec![];

        let (resp, _) = self.execute(&cmd, &sessions)?;
        let TpmGetCapabilityResponse {
            more_data,
            capability_data,
        } = resp
            .GetCapability()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::GetCapability))?;

        Ok((more_data.into(), capability_data))
    }

    /// Reads a specific TPM property.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the capability or property is not found, or
    /// if the `get_capability` call fails.
    pub fn get_tpm_property(&mut self, property: TpmPt) -> Result<u32, DeviceError> {
        let (_, cap_data) = self.get_capability_page(TpmCap::TpmProperties, property as u32, 1)?;

        let TpmuCapabilities::TpmProperties(props) = &cap_data.data else {
            return Err(DeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        let Some(prop) = props.first() else {
            return Err(DeviceError::CapabilityMissing(TpmCap::TpmProperties));
        };

        Ok(prop.value)
    }

    /// Reads the public area of a TPM object.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the underlying `TPM2_ReadPublic` command
    /// execution fails or if the TPM returns a response of an unexpected type.
    pub fn read_public(
        &mut self,
        handle: TpmHandle,
    ) -> Result<(TpmtPublic, Tpm2bName), DeviceError> {
        if let Some(cached) = self.name_cache.get(&handle.0) {
            return Ok(cached.clone());
        }

        let cmd = TpmReadPublicCommand {
            object_handle: handle,
        };
        let sessions = vec![];
        let (resp, _) = self.execute(&cmd, &sessions)?;

        let read_public_resp = resp
            .ReadPublic()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::ReadPublic))?;

        let public = read_public_resp.out_public.inner;
        let name = read_public_resp.name;

        self.name_cache.insert(handle.0, (public.clone(), name));
        Ok((public, name))
    }

    /// Finds a persistent handle by its public area.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if fetching handles or reading public areas fails.
    pub fn find_persistent(
        &mut self,
        target: &TpmtPublic,
    ) -> Result<Option<(TpmHandle, Tpm2bName)>, DeviceError> {
        let handles = self.fetch_handles((TpmHt::Persistent as u32) << 24)?;
        for handle in handles {
            if let Some(handle_val) = handle.value() {
                if let Ok((public, name)) = self.read_public(handle_val.into()) {
                    if public == *target {
                        return Ok(Some((handle_val.into(), name)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Saves the context of a transient object or session.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the underlying `TPM2_ContextSave` command
    /// execution fails or if the TPM returns a response of an unexpected type.
    pub fn save_context(&mut self, save_handle: TpmHandle) -> Result<TpmsContext, DeviceError> {
        let cmd = TpmContextSaveCommand { save_handle };
        let sessions = vec![];
        let (resp, _) = self.execute(&cmd, &sessions)?;
        let save_resp = resp
            .ContextSave()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::ContextSave))?;
        Ok(save_resp.context)
    }

    /// Loads a TPM context and returns the handle.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the `TPM2_ContextLoad` command fails.
    pub fn load_context(&mut self, context: TpmsContext) -> Result<TpmHandle, DeviceError> {
        let cmd = TpmContextLoadCommand { context };
        let sessions = vec![];
        let (resp, _) = self.execute(&cmd, &sessions)?;
        let resp_inner = resp
            .ContextLoad()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::ContextLoad))?;
        Ok(resp_inner.loaded_handle)
    }

    /// Flushes a transient object or session from the TPM and removes it from the cache.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the underlying `TPM2_FlushContext` command
    /// execution fails.
    pub fn flush_context(&mut self, handle: TpmHandle) -> Result<(), DeviceError> {
        self.name_cache.remove(&handle.0);
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
        };
        let sessions = vec![];
        self.execute(&cmd, &sessions)?;
        Ok(())
    }

    /// Loads a session context and then flushes the resulting handle.
    ///
    /// # Errors
    ///
    /// Returns `DeviceError` on `ContextLoad` or `FlushContext` failure.
    pub fn flush_session(&mut self, context: TpmsContext) -> Result<(), DeviceError> {
        match self.load_context(context) {
            Ok(handle) => self.flush_context(handle),
            Err(DeviceError::TpmRc(rc)) => {
                let base = rc.base();
                if base == TpmRcBase::ReferenceH0 || base == TpmRcBase::Handle {
                    Ok(())
                } else {
                    Err(DeviceError::TpmRc(rc))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Evicts a persistent object or makes a transient object persistent.
    ///
    /// # Errors
    ///
    /// Returns `DeviceError` on TPM command failure.
    pub fn evict_control(
        &mut self,
        auth: TpmHandle,
        object_handle: TpmHandle,
        persistent_handle: TpmHandle,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(), DeviceError> {
        let cmd = TpmEvictControlCommand {
            auth,
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let (resp, _) = self.execute(&cmd, sessions)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }
}
