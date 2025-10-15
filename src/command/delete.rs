// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{build_auth_list, SubCommand},
    context::ContextCache,
    device::{self, Device},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc, str::FromStr};

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
                            let handle = context.delete(dev, &uri, &auth_list)?;
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
