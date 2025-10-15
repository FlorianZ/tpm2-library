// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{build_auth_list, SubCommand},
    context::ContextCache,
    device::{self, Auth, Device, DeviceError},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc, str::FromStr};
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

    /// auth for the object: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl Delete {
    fn delete(
        context: &mut ContextCache,
        device: &mut Device,
        uri: &Uri,
        auths: &[Auth],
    ) -> Result<u32, CommandError> {
        let handle = context.load_context(device, uri)?.0;

        let mso = (handle >> 24) as u8;
        let result = match TpmHt::try_from(mso) {
            Ok(TpmHt::Persistent) => {
                Self::delete_persistent(context, device, TpmHandle(handle), auths)
            }
            Ok(TpmHt::Transient) => Self::delete_transient(context, device, TpmHandle(handle)),
            Ok(TpmHt::HmacSession | TpmHt::PolicySession) => {
                let cmd = TpmFlushContextCommand {
                    flush_handle: handle.into(),
                };
                let sessions = vec![];
                device.execute(&cmd, &sessions)?;
                context.handles.remove(&handle);
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
        context: &mut ContextCache,
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
        let handles = [auth_handle as u32, handle.0];

        let (resp, _) = context.execute(device, &cmd, &handles, auths)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }

    fn delete_transient(
        context: &mut ContextCache,
        device: &mut Device,
        handle: TpmHandle,
    ) -> Result<(), CommandError> {
        let cmd = TpmFlushContextCommand {
            flush_handle: handle,
        };
        let sessions = vec![];
        device.execute(&cmd, &sessions)?;
        context.handles.remove(&handle.0);
        Ok(())
    }
}

impl SubCommand for Delete {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth_list = build_auth_list(
            self.auth.as_ref(),
            self.hmac_auth.as_ref(),
            &context.session_map,
        )?;

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
                Uri::Context(ref grip) => {
                    context.remove_context(grip)?;
                    writeln!(context.writer, "{uri}")?;
                }
                Uri::Path(_) | Uri::Password(_) => {
                    return Err(CommandError::InvalidInput(uri.to_string()));
                }
                Uri::Tpm(_) | Uri::Session(_) => unreachable!(),
            }
        }

        if !device_ops.is_empty() {
            device::with_device(device, |dev| -> Result<(), CommandError> {
                for uri in device_ops {
                    match uri {
                        Uri::Session(_) => {
                            let uri_str = uri.to_string();
                            if let Some(session) = context.session_map.remove(&uri_str)? {
                                if let Err(err) = dev.flush_session(session.context) {
                                    log::warn!("{uri}: {err}");
                                }
                            }
                            writeln!(context.writer, "{uri}")?;
                        }
                        Uri::Tpm(_) => {
                            let handle = Self::delete(context, dev, &uri, &auth_list)?;
                            writeln!(context.writer, "tpm:{handle:08x}")?;
                        }
                        Uri::Context(_) | Uri::Path(_) | Uri::Password(_) => unreachable!(),
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
