// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::CommandError,
    device::{self, Auth, Device, DeviceError},
    uri::Uri,
    Job,
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
    fn delete(
        job: &mut Job,
        device: &mut Device,
        uri: &Uri,
        auths: &[Auth],
    ) -> Result<u32, CommandError> {
        let handle = job.context_cache.load_context(device, uri)?.0;

        let mso = (handle >> 24) as u8;
        let result = match TpmHt::try_from(mso) {
            Ok(TpmHt::Persistent) => Self::delete_persistent(job, device, TpmHandle(handle), auths),
            Ok(TpmHt::Transient) => Self::delete_transient(job, device, TpmHandle(handle)),
            Ok(TpmHt::HmacSession | TpmHt::PolicySession) => {
                let cmd = TpmFlushContextCommand {
                    flush_handle: handle.into(),
                };
                let sessions = vec![];
                device.execute(&cmd, &sessions)?;
                job.context_cache.handles.remove(&handle);
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
        job: &mut Job,
        device: &mut Device,
        handle: TpmHandle,
        auths: &[Auth],
    ) -> Result<(), CommandError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };
        let handles = [auth_handle as u32];

        let (resp, _) = job.execute(device, &cmd, &handles, auths)?;

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
        job.context_cache.handles.remove(&handle.0);
        Ok(())
    }
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        let object_auth = job.resolve_auth_session(self.auth.clone())?;
        let auth_list = vec![object_auth];

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
                    job.context_cache.remove_context(grip)?;
                    writeln!(job.context_cache.writer, "{uri}")?;
                }
                Uri::Path(_) | Uri::Password(_) | Uri::Policy(_) => {
                    return Err(CommandError::InvalidInput(uri.to_string()));
                }
                Uri::Tpm(_) | Uri::Session(_) => unreachable!(),
            }
        }

        if !device_ops.is_empty() {
            device::with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
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
                            writeln!(job.context_cache.writer, "{uri}")?;
                        }
                        Uri::Tpm(_) => {
                            let handle = Self::delete(job, dev, &uri, &auth_list)?;
                            writeln!(job.context_cache.writer, "tpm:{handle:08x}")?;
                        }
                        Uri::Key(_) | Uri::Path(_) | Uri::Policy(_) | Uri::Password(_) => {
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
