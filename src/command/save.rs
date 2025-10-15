// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::SubCommand,
    context::ContextCache,
    convert::{from_env_to_auth, from_str_to_handle},
    device::{self, Device},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc, str::FromStr};
use tpm2_protocol::{data::TpmHt, data::TpmSe, TpmHandle};

/// Stores a cached key to non-volatile memory.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "save")]
pub struct Save {
    /// input: [<parent>] <name grip> <persistent-handle>
    #[argh(positional)]
    pub input: Vec<String>,

    /// auth for the hierarchy: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Save {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth = from_env_to_auth(
            self.auth.as_ref(),
            "TPM2SH_AUTH",
            &context.session_map,
            Some(TpmSe::Policy),
        )?;
        device::with_device(device, |dev| -> Result<(), CommandError> {
            let (parent_uri_opt, grip_str, handle_str) = match self.input.len() {
                2 => (None, &self.input[0], &self.input[1]),
                3 => (Some(&self.input[0]), &self.input[1], &self.input[2]),
                _ => {
                    return Err(CommandError::InvalidInput(
                        "invalid number of arguments for save command".to_string(),
                    ));
                }
            };

            let handle = from_str_to_handle(handle_str)
                .map_err(|e| CommandError::InvalidInput(e.to_string()))?;
            if (handle.0 >> 24) as u8 != TpmHt::Persistent as u8 {
                return Err(CommandError::InvalidInput(
                    "output handle must be a persistent handle".to_string(),
                ));
            }
            let persistent_handle = TpmHandle(handle.0);

            if let Some(parent_uri_str) = parent_uri_opt {
                let parent_uri = Uri::from_str(parent_uri_str)?;
                let _parent_handle = context.load_parent(dev, &parent_uri)?;
            }

            let grip_uri = Uri::from_str(&format!("key:{grip_str}"))?;
            let transient_handle = context.load_context(dev, &grip_uri)?;

            context.evict_key(dev, transient_handle, persistent_handle, &[auth])?;

            if let Uri::Context(grip) = grip_uri {
                context.remove_context(&grip)?;
            }

            writeln!(context.writer, "tpm:{handle:08x}")?;
            Ok(())
        })
    }
}
