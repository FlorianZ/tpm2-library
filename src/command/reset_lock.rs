// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::CommandError,
    context::ContextError,
    device::{with_device, DeviceError},
    job::Job,
};
use argh::FromArgs;
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase, TpmRh},
    message::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "reset-lock")]
pub struct ResetLock {
    /// hierarchy auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<Auth>,
}

impl SubCommand for ResetLock {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        let object_auth = job.resolve_auth_session(self.auth.clone())?;
        let auth_list = vec![object_auth];

        with_device(job.device.clone(), |device| {
            let command = TpmDictionaryAttackLockResetCommand {
                lock_handle: (TpmRh::Lockout as u32).into(),
            };
            let handles = [TpmRh::Lockout as u32];

            let (resp, _) = match job.execute(device, &command, &handles, &auth_list) {
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

            writeln!(job.context_cache.writer, "done")?;

            Ok(())
        })
    }
}
