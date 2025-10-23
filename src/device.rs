// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::LogFormat,
    crypto::crypto_hash_size,
    handle::{Handle, HandleClass},
    job::Job,
    print::TpmPrint,
    TEARDOWN,
};

use indicatif::{ProgressBar, ProgressStyle};
use log::trace;
use polling::{Event, Events, Poller};
use rand::{thread_rng, RngCore};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    io::{IsTerminal, Read, Write},
    num::TryFromIntError,
    rc::Rc,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use thiserror::Error;
use tpm2_protocol::{
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmPt, TpmRc,
        TpmRcBase, TpmRh, TpmSe, TpmSt, TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData,
        TpmsContext, TpmsRsaParms, TpmtPublic, TpmtPublicParms, TpmtSymDefObject, TpmuCapabilities,
        TpmuPublicParms,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmBodyBuild,
        TpmContextLoadCommand, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader,
        TpmReadPublicCommand, TpmResponseBody, TpmStartAuthSessionCommand,
        TpmStartAuthSessionResponse, TpmTestParmsCommand,
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
    poller: Poller,
    log_format: LogFormat,
    name_cache: HashMap<u32, (TpmtPublic, Tpm2bName)>,
}

/// Checks if the TPM supports a given set of RSA parameters.
pub(crate) fn test_rsa_parms(device: &mut Device, key_bits: u16) -> Result<(), DeviceError> {
    let cmd = TpmTestParmsCommand {
        parameters: TpmtPublicParms {
            object_type: TpmAlgId::Rsa,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                key_bits,
                ..Default::default()
            }),
        },
    };
    let sessions = vec![];
    device.execute(&cmd, &sessions).map(|(_, _)| ())
}

impl Device {
    /// Creates a new TPM device from an owned transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the system poller cannot be created.
    pub fn new(file: File, log_format: LogFormat) -> Result<Self, DeviceError> {
        let poller = Poller::new()?;
        Ok(Self {
            file,
            poller,
            log_format,
            name_cache: HashMap::new(),
        })
    }

    fn receive_with_progress(&mut self) -> Result<Vec<u8>, DeviceError> {
        let spinner = ProgressBar::new_spinner();
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .expect("Invalid progress spinner template")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
        );
        spinner.set_message("Waiting for TPM...");

        let mut events = Events::new();
        unsafe { self.poller.add(&self.file, Event::readable(0))? };

        let start_time = Instant::now();
        let result = loop {
            if TEARDOWN.load(Ordering::Relaxed) {
                break Err(DeviceError::Interrupted);
            }
            if start_time.elapsed() > Duration::from_secs(60) {
                break Err(DeviceError::Timeout);
            }

            self.poller
                .wait(&mut events, Some(Duration::from_millis(100)))?;
            if !events.is_empty() {
                break self.receive_from_stream();
            }
        };

        spinner.finish_and_clear();
        self.poller.delete(&self.file)?;
        result
    }

    fn receive_from_stream(&mut self) -> Result<Vec<u8>, DeviceError> {
        let mut header = [0u8; 10];
        self.file.read_exact(&mut header)?;
        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            return Err(DeviceError::InvalidResponse);
        };
        let size = u32::from_be_bytes(size_bytes) as usize;
        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            return Err(DeviceError::InvalidResponse);
        }
        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.file.read_exact(&mut resp_buf[header.len()..])?;
        Ok(resp_buf)
    }

    /// Sends a command to the TPM and waits for the response.
    ///
    /// # Errors
    ///
    /// This function will return an error if building the command fails, I/O
    /// with the device fails, or the TPM itself returns an error.
    pub fn execute<C: TpmCommandObject>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), DeviceError> {
        let command_vec = self.build_command_buffer(command, sessions)?;
        let cc = command.cc();
        self.file.write_all(&command_vec)?;
        self.file.flush()?;
        let resp_buf = if std::io::stderr().is_terminal() {
            self.receive_with_progress()?
        } else {
            self.receive_from_stream()?
        };
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
    pub fn fetch_handles(&mut self, handle_type: u32) -> Result<Vec<Handle>, DeviceError> {
        self.get_capability(
            TpmCap::Handles,
            handle_type,
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
                .map(|h| Handle((HandleClass::Tpm, h)))
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

    /// Saves the context of a transient object or session.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the underlying `TPM2_ContextSave` command
    /// execution fails or if the TPM returns a response of an unexpected type.
    pub fn save_context(&mut self, handle: u32) -> Result<TpmsContext, DeviceError> {
        let cmd = TpmContextSaveCommand {
            save_handle: handle.into(),
        };
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
    pub fn load_context(&mut self, context: TpmsContext) -> Result<u32, DeviceError> {
        let cmd = TpmContextLoadCommand { context };
        let sessions = vec![];
        let (resp, _) = self.execute(&cmd, &sessions)?;
        let resp_inner = resp
            .ContextLoad()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::ContextLoad))?;
        Ok(resp_inner.loaded_handle.0)
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
            Ok(live_handle) => self.flush_context(live_handle.into()),
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

    /// Starts a new authorization session.
    ///
    /// This function sends a `TPM2_StartAuthSession` command to the TPM and
    /// returns the raw response, which can be used to construct a higher-level
    /// session object.
    ///
    /// # Errors
    ///
    /// Returns `DeviceError` on TPM command failure.
    pub fn start_session(
        &mut self,
        session_type: TpmSe,
        auth_hash: TpmAlgId,
        bind: TpmHandle,
    ) -> Result<(TpmStartAuthSessionResponse, Tpm2bNonce), DeviceError> {
        let digest_len =
            crypto_hash_size(auth_hash).ok_or(DeviceError::TpmProtocol(TpmError::MalformedData))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind,
            nonce_caller,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: TpmtSymDefObject::default(),
            auth_hash,
        };
        let sessions = vec![];

        let (response_body, _) = self.execute(&cmd, &sessions)?;

        let resp = response_body
            .StartAuthSession()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::StartAuthSession))?;

        Ok((resp, nonce_caller))
    }

    /// Evicts a persistent object or makes a transient object persistent.
    ///
    /// # Errors
    ///
    /// Returns `DeviceError` on TPM command failure.
    pub fn evict_control(
        &mut self,
        job: &mut Job,
        auth: TpmHandle,
        object_handle: TpmHandle,
        persistent_handle: TpmHandle,
        auths: &[Auth],
    ) -> Result<(), DeviceError> {
        let cmd = TpmEvictControlCommand {
            auth,
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let handles_for_session = [auth.0];

        let (resp, _) = job
            .execute(self, &cmd, &handles_for_session, auths)
            .map_err(|e| match e {
                crate::key_cache::KeyCacheError::Device(d) => d,
                other => {
                    log::error!("Unexpected error during evict_control execution: {other}");
                    DeviceError::TpmProtocol(TpmError::MalformedData)
                }
            })?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }
}
