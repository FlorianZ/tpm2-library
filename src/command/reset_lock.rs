// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::{CommandError, ContextError, DeviceError};
use crate::{
    cli::{build_auth_list, SubCommand},
    context::ContextCache,
    device::{self, Device},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase, TpmRh},
    message::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "reset-lock")]
pub struct ResetLock {
    /// auth for the lockout hierarchy: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
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
        let auth_list = build_auth_list(
            self.auth.as_ref(),
            self.hmac_auth.as_ref(),
            &context.session_map,
        )?;
        device::with_device(device, |device| {
            let command = TpmDictionaryAttackLockResetCommand {
                lock_handle: (TpmRh::Lockout as u32).into(),
            };
            let handles = [TpmRh::Lockout as u32];

            let (resp, _) = match context.execute(device, &command, &handles, &auth_list) {
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
