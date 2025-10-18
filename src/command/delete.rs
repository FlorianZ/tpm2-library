// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::CommandError,
    device::{with_device, Device, DeviceError},
    job::Job,
    uri::Uri,
};
use clap::Args;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCc, TpmHt, TpmRcBase, TpmRh},
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmHandle,
};

/// Deletes TPM objects, and cached keys and sessions.
#[derive(Args, Debug)]
pub struct Delete {
    /// Inputs: 'tpm:<handle>', 'key:<name grip>', or 'session:<handle>'
    pub inputs: Vec<String>,

    /// Persistent auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

impl Delete {
    fn delete(&self, job: &mut Job, device: &mut Device, uri: &Uri) -> Result<u32, CommandError> {
        let handle = job.key_cache.load_context(device, uri)?.0;

        let mso = (handle >> 24) as u8;
        let result = match TpmHt::try_from(mso) {
            Ok(TpmHt::Persistent) => self.delete_persistent(job, device, TpmHandle(handle)),
            Ok(TpmHt::Transient) => Self::delete_transient(job, device, TpmHandle(handle)),
            Ok(TpmHt::HmacSession | TpmHt::PolicySession) => {
                let cmd = TpmFlushContextCommand {
                    flush_handle: handle.into(),
                };
                let sessions = vec![];
                device.execute(&cmd, &sessions)?;
                job.key_cache.handles.remove(&handle);
                Ok(())
            }
            _ => {
                return Err(CommandError::InvalidInput(format!(
                    "invalid handle: {handle:08x}"
                )))
            }
        };

        match result {
            Ok(()) => Ok(handle),
            Err(CommandError::Device(DeviceError::TpmRc(rc))) if rc.base() == TpmRcBase::Handle => {
                Err(CommandError::InvalidInput(format!(
                    "unknown handle: {handle:08x}"
                )))
            }
            Err(e) => Err(e),
        }
    }

    fn delete_persistent(
        &self,
        job: &mut Job,
        device: &mut Device,
        handle: TpmHandle,
    ) -> Result<(), CommandError> {
        let auth_handle = (TpmRh::Owner as u32).into();
        let mut auths = vec![self.auth.clone().unwrap_or_default()];
        let handles = [u32::from(auth_handle)];

        let cmd = TpmEvictControlCommand {
            auth: auth_handle,
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };

        let (resp, _) = job.execute(device, &cmd, &handles, &mut auths)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    fn delete_transient(
        job: &mut Job,
        device: &mut Device,
        handle: TpmHandle,
    ) -> Result<(), CommandError> {
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
        };
        let sessions = vec![];
        device.execute(&cmd, &sessions)?;
        job.key_cache.handles.remove(&handle.0);
        Ok(())
    }
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        let uris: Vec<Uri> = self
            .inputs
            .iter()
            .map(|s| Uri::from_str(s))
            .collect::<Result<_, _>>()?;

        let (device_ops, local_ops): (Vec<_>, Vec<_>) = uris
            .into_iter()
            .partition(|uri| !matches!(uri, Uri::Path(_)));

        if let Some(uri) = local_ops.into_iter().next() {
            return Err(CommandError::InvalidInput(uri.to_string()));
        }

        if !device_ops.is_empty() {
            with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
                for uri in device_ops {
                    let uri_str = uri.to_string();
                    match uri {
                        Uri::Session(_) => {
                            if let Some(session) = job.session_cache.remove(&uri_str)? {
                                if let Err(err) = dev.flush_session(session.context) {
                                    log::warn!("{uri}: {err}");
                                }
                            }
                            writeln!(job.key_cache.writer, "{uri_str}")?;
                        }
                        Uri::Key(ref grip) => {
                            let handle = self.delete(job, dev, &uri)?;
                            job.key_cache.remove_context(grip)?;
                            writeln!(job.key_cache.writer, "tpm:{handle:08x} ({uri})")?;
                        }
                        Uri::Tpm(_) => {
                            let handle = self.delete(job, dev, &uri)?;
                            writeln!(job.key_cache.writer, "tpm:{handle:08x}")?;
                        }
                        Uri::Path(_) => unreachable!(),
                    }
                }
                Ok(())
            })?;
        }

        Ok(())
    }

    fn is_local(&self) -> bool {
        !self
            .inputs
            .iter()
            .any(|s| s.starts_with("tpm:") || s.starts_with("session:") || s.starts_with("key:"))
    }
}
