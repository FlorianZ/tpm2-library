// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::{CommandError, ContextError, DeviceError};
use crate::{
    cli::{get_auth, SubCommand},
    context::ContextCache,
    device::{self, Auth, Device},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase, TpmRh, TpmSe},
    message::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "reset-lock")]
pub struct ResetLock {
    /// auth for the lockout hierarchy: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for ResetLock {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth = match (self.auth.as_ref(), self.hmac_auth.as_ref()) {
            (Some(_), Some(_)) => {
                return Err(CommandError::InvalidInput(
                    "Cannot use --auth and --hmac-auth at the same time".to_string(),
                ));
            }
            (Some(auth_str), None) => get_auth(
                Some(auth_str),
                "TPM2SH_AUTH",
                &context.session_map,
                &[TpmSe::Policy],
            )?,
            (None, Some(hmac_auth_str)) => get_auth(
                Some(hmac_auth_str),
                "TPM2SH_HMAC_AUTH",
                &context.session_map,
                &[TpmSe::Hmac],
            )?,
            (None, None) => {
                let auth = get_auth(None, "TPM2SH_AUTH", &context.session_map, &[TpmSe::Policy])?;
                if matches!(&auth, Auth::Password(p) if p.is_empty()) {
                    get_auth(
                        None,
                        "TPM2SH_HMAC_AUTH",
                        &context.session_map,
                        &[TpmSe::Hmac],
                    )?
                } else {
                    auth
                }
            }
        };
        device::with_device(device, |device| {
            let command = TpmDictionaryAttackLockResetCommand {
                lock_handle: (TpmRh::Lockout as u32).into(),
            };
            let handles = [TpmRh::Lockout as u32];
            let auths = &[auth];

            let (resp, _) = match context.execute(device, &command, &handles, auths) {
                Ok(result) => result,
                Err(ContextError::Device(DeviceError::TpmRc(rc)))
                    if rc.base() == TpmRcBase::Lockout =>
                {
                    return Err(CommandError::DictionaryAttackLocked);
                }
                Err(e) => return Err(e.into()),
            };

            resp.DictionaryAttackLockReset()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;

            writeln!(context.writer, "done")?;

            Ok(())
        })
    }
}
