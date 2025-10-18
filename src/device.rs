// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::LogFormat,
    crypto::CryptoError,
    key::{Tpm2shAlgId, Tpm2shEccCurve},
    print::TpmPrint,
    transport::{receive_from_stream, FileTransport, Transport},
    TEARDOWN,
};

use indicatif::{ProgressBar, ProgressStyle};
use log::trace;
use polling::{Event, Events, Poller};
use rand::{thread_rng, RngCore};
use std::{
    cell::RefCell,
    collections::HashMap,
    io::{IsTerminal, Write},
    num::TryFromIntError,
    rc::Rc,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use thiserror::Error;
use tpm2_protocol::{
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmHt, TpmPt, TpmRc,
        TpmRcBase, TpmRh, TpmSe, TpmSt, TpmsAuthCommand, TpmsCapabilityData, TpmsContext,
        TpmsRsaParms, TpmtPublic, TpmtPublicParms, TpmtSymDefObject, TpmuCapabilities,
        TpmuPublicParms,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmBodyBuild,
        TpmContextLoadCommand, TpmContextSaveCommand, TpmFlushContextCommand,
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader, TpmReadPublicCommand,
        TpmResponseBody, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
        TpmTestParmsCommand,
    },
    tpm_hash_size, TpmErrorKind, TpmHandle, TpmWriter,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

/// A type-erased object safe TPM command object
pub trait TpmCommandObject: TpmPrint + TpmHeader + TpmBodyBuild {}
impl<T> TpmCommandObject for T where T: TpmHeader + TpmBodyBuild + TpmPrint {}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("invalid auth: {0}")]
    InvalidAuth(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("syscall: {0}")]
    Nix(#[from] nix::Error),
    #[error("response corrupted")]
    ResponseCorrupted,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("operation interrupted by user")]
    Interrupted,
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("unknown handle name: {0:08x}")]
    UnknownHandleName(u32),
    #[error("TPM: {0}")]
    Tpm(TpmErrorKind),
    #[error("TPM RC: {0}")]
    TpmRc(TpmRc),
    #[error("TPM command timed out")]
    Timeout,
    #[error("device not available")]
    NotAvailable,
    #[error("device is already borrowed")]
    AlreadyBorrowed,
    #[error("capability not found: {0}")]
    CapabilityMissing(TpmCap),
}

impl From<TpmErrorKind> for DeviceError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

impl From<TpmRc> for DeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

impl From<TryFromIntError> for DeviceError {
    fn from(_err: TryFromIntError) -> Self {
        Self::Tpm(TpmErrorKind::InvalidValue)
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
    transport: Box<dyn Transport>,
    poller: Poller,
    log_format: LogFormat,
    name_cache: HashMap<u32, Tpm2bName>,
}

/// Checks if the TPM supports a given set of RSA parameters.
fn test_rsa_parms(device: &mut Device, key_bits: u16) -> Result<(), DeviceError> {
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
    pub fn new(
        transport: impl Transport + 'static,
        log_format: LogFormat,
    ) -> Result<Self, DeviceError> {
        let poller = Poller::new()?;
        Ok(Self {
            transport: Box::new(transport),
            poller,
            log_format,
            name_cache: HashMap::new(),
        })
    }

    /// Adds a transient handle's name to the internal cache.
    pub fn add_name_to_cache(&mut self, handle: u32, name: Tpm2bName) {
        self.name_cache.insert(handle, name);
    }

    /// Retrieves the TPM Name for a handle, required for authorization computations.
    pub(crate) fn get_handle_name(&mut self, handle: u32) -> Result<Tpm2bName, DeviceError> {
        if let Some(name) = self.name_cache.get(&handle) {
            return Ok(*name);
        }

        let mso = (handle >> 24) as u8;
        if mso == TpmHt::Transient as u8 || mso == TpmHt::Persistent as u8 {
            let (_, name) = self.read_public(handle.into())?;
            Ok(name)
        } else {
            Tpm2bName::try_from(handle.to_be_bytes().as_slice()).map_err(Into::into)
        }
    }

    fn receive_with_progress(&mut self) -> Result<Vec<u8>, DeviceError> {
        if let Some(ft) = self.transport.as_any_mut().downcast_mut::<FileTransport>() {
            let spinner = ProgressBar::new_spinner();
            spinner.enable_steady_tick(Duration::from_millis(100));
            spinner.set_style(
                ProgressStyle::with_template("{spinner:.green} {msg}")
                    .expect("Invalid progress spinner template")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
            );
            spinner.set_message("Waiting for TPM...");

            let mut events = Events::new();
            let file = &mut ft.0;
            unsafe { self.poller.add(&*file, Event::readable(0))? };

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
                    break receive_from_stream(file);
                }
            };

            spinner.finish_and_clear();
            self.poller.delete(&*file)?;
            result
        } else {
            self.transport.receive()
        }
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
        self.transport.send(&command_vec)?;
        let resp_buf = if std::io::stderr().is_terminal() {
            self.receive_with_progress()?
        } else {
            self.transport.receive()?
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

    /// Retrieves all supported algorithms from the TPM by probing its capabilities.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if querying the TPM fails.
    pub fn get_all_algorithms(&mut self) -> Result<Vec<(TpmAlgId, String)>, DeviceError> {
        let mut supported_algs = Vec::new();
        let mut all_algs = Vec::new();
        let mut prop = 0;
        loop {
            let (more_data, cap_data) =
                self.get_capability(TpmCap::Algs, prop, u32::try_from(MAX_HANDLES)?)?;

            if let TpmuCapabilities::Algs(p) = cap_data.data {
                all_algs.extend(p.iter().map(|prop| prop.alg));
            } else {
                return Err(DeviceError::CapabilityMissing(TpmCap::Algs));
            }

            if more_data {
                if let TpmuCapabilities::Algs(algs) = cap_data.data {
                    prop = algs.last().map_or(prop, |p| p.alg as u32 + 1);
                }
            } else {
                break;
            }
        }
        let all_algs: std::collections::HashSet<TpmAlgId> = all_algs.into_iter().collect();

        let name_algs: Vec<TpmAlgId> = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512]
            .into_iter()
            .filter(|alg| all_algs.contains(alg))
            .collect();

        if all_algs.contains(&TpmAlgId::Rsa) {
            let rsa_key_sizes = [2048, 3072, 4096];
            for key_bits in rsa_key_sizes {
                match test_rsa_parms(self, key_bits) {
                    Ok(()) => {
                        for &name_alg in &name_algs {
                            supported_algs.push((
                                TpmAlgId::Rsa,
                                format!("rsa-{}:{}", key_bits, Tpm2shAlgId(name_alg)),
                            ));
                        }
                    }
                    Err(DeviceError::TpmRc(rc)) => {
                        if rc.base() != TpmRcBase::Value {
                            return Err(DeviceError::TpmRc(rc));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            let mut supported_curves = Vec::new();
            let mut prop = 0;
            loop {
                let (more_data, cap_data) =
                    self.get_capability(TpmCap::EccCurves, prop, u32::try_from(MAX_HANDLES)?)?;
                if let TpmuCapabilities::EccCurves(curves) = &cap_data.data {
                    supported_curves.extend(curves.iter().copied());
                } else {
                    return Err(DeviceError::CapabilityMissing(TpmCap::EccCurves));
                }
                if more_data {
                    if let TpmuCapabilities::EccCurves(curves) = cap_data.data {
                        prop = curves.last().map_or(prop, |&c| c as u32 + 1);
                    }
                } else {
                    break;
                }
            }
            for curve_id in supported_curves {
                for &name_alg in &name_algs {
                    supported_algs.push((
                        TpmAlgId::Ecc,
                        format!(
                            "ecc-{}:{}",
                            Tpm2shEccCurve::from(curve_id),
                            Tpm2shAlgId(name_alg)
                        ),
                    ));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &name_alg in &name_algs {
                supported_algs.push((
                    TpmAlgId::KeyedHash,
                    format!("keyedhash:{}", Tpm2shAlgId(name_alg)),
                ));
            }
        }

        Ok(supported_algs)
    }

    /// Retrieves all supported hash algorithms from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if querying the TPM fails.
    pub fn get_all_hashes(&mut self) -> Result<Vec<String>, DeviceError> {
        let mut all_algs = Vec::new();
        let mut prop = 0;

        loop {
            let (more_data, cap_data) =
                self.get_capability(TpmCap::Algs, prop, u32::try_from(MAX_HANDLES)?)?;

            if let TpmuCapabilities::Algs(p) = &cap_data.data {
                all_algs.extend(p.iter().map(|prop| prop.alg));
            } else {
                return Err(DeviceError::CapabilityMissing(TpmCap::Algs));
            }

            if more_data {
                if let TpmuCapabilities::Algs(algs) = cap_data.data {
                    prop = algs.last().map_or(prop, |p| p.alg as u32 + 1);
                }
            } else {
                break;
            }
        }

        let hashes: Vec<String> = all_algs
            .iter()
            .filter(|p| tpm_hash_size(p).is_some())
            .map(|p| Tpm2shAlgId(*p).to_string())
            .collect();
        Ok(hashes)
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(&mut self, handle_type: u32) -> Result<Vec<u32>, DeviceError> {
        let mut all_handles = Vec::new();
        let mut prop = handle_type;

        loop {
            let (more_data, cap_data) =
                self.get_capability(TpmCap::Handles, prop, TPM_CAP_PROPERTY_MAX)?;

            if let TpmuCapabilities::Handles(handles) = cap_data.data {
                all_handles.extend(handles.iter().copied());
            } else {
                return Err(DeviceError::CapabilityMissing(TpmCap::Handles));
            }

            if more_data {
                if let TpmuCapabilities::Handles(handles) = cap_data.data {
                    prop = handles.last().map_or(prop, |&h| h + 1);
                }
            } else {
                break;
            }
        }

        Ok(all_handles)
    }

    /// Fetches and returns one page of capabilities of a certain type from the TPM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying `execute` call fails
    /// or if the TPM returns a response of an unexpected type.
    pub fn get_capability(
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
        let (_, cap_data) = self.get_capability(TpmCap::TpmProperties, property as u32, 1)?;

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
        let cmd = TpmReadPublicCommand {
            object_handle: handle,
        };
        let sessions = vec![];
        let (resp, _) = self.execute(&cmd, &sessions)?;
        let read_public_resp = resp
            .ReadPublic()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::ReadPublic))?;
        let name = read_public_resp.name;
        self.add_name_to_cache(handle.0, name);
        Ok((read_public_resp.out_public.inner, name))
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

    /// Flushes a transient object or session from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` if the underlying `TPM2_FlushContext` command
    /// execution fails.
    pub fn flush_context(&mut self, handle: u32) -> Result<(), DeviceError> {
        let cmd = TpmFlushContextCommand {
            flush_handle: handle.into(),
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
            Ok(live_handle) => self.flush_context(live_handle),
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => Ok(()),
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
    ) -> Result<(TpmStartAuthSessionResponse, Tpm2bNonce), DeviceError> {
        let digest_len =
            tpm_hash_size(&auth_hash).ok_or(DeviceError::Tpm(TpmErrorKind::InvalidValue))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind: (TpmRh::Null as u32).into(),
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
}
