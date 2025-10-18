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
use argh::FromArgs;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCc, TpmHt, TpmRcBase, TpmRh},
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmHandle,
};

/// Deletes TPM objects, and cached keys and sessions.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "delete")]
pub struct Delete {
    /// inputs: 'tpm:<handle>', 'key:<name grip>', or 'session:<handle>'
    #[argh(positional)]
    pub inputs: Vec<String>,

    /// persistent auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "auth", short = 'a')]
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

        let object_auth = job.resolve_auth_session(device, self.auth.clone(), auth_handle)?;
        let auth_list = vec![object_auth];

        let cmd = TpmEvictControlCommand {
            auth: auth_handle,
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };
        let handles = [u32::from(auth_handle)];

        let (resp, _) = job.execute(device, &cmd, &handles, &auth_list)?;

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
            .partition(|uri| matches!(uri, Uri::Tpm(_) | Uri::Session(_)));

        for uri in local_ops {
            match uri {
                Uri::Key(ref grip) => {
                    job.key_cache.remove_context(grip)?;
                    writeln!(job.key_cache.writer, "{uri}")?;
                }
                Uri::Path(_) => {
                    return Err(CommandError::InvalidInput(uri.to_string()));
                }
                Uri::Tpm(_) | Uri::Session(_) => unreachable!(),
            }
        }

        if !device_ops.is_empty() {
            with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
                for uri in device_ops {
                    match uri {
                        Uri::Session(_) => {
                            let uri_str = uri.to_string();
                            if let Ok(session) = job.session_cache.get(&uri_str) {
                                if let Err(err) = dev.flush_session(session.context.clone()) {
                                    match err {
                                        DeviceError::TpmRc(rc)
                                            if rc.base() == TpmRcBase::Handle =>
                                        {
                                            log::debug!("{uri}: already flushed");
                                        }
                                        _ => log::warn!("{uri}: {err}"),
                                    }
                                }
                            }
                            job.session_cache.remove(&uri_str)?;
                            writeln!(job.key_cache.writer, "{uri}")?;
                        }
                        Uri::Tpm(_) => {
                            let handle = self.delete(job, dev, &uri)?;
                            writeln!(job.key_cache.writer, "tpm:{handle:08x}")?;
                        }
                        Uri::Key(_) | Uri::Path(_) => {
                            unreachable!()
                        }
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
            .any(|s| Uri::from_str(s).is_ok_and(|uri| matches!(uri, Uri::Tpm(_) | Uri::Session(_))))
    }
}
