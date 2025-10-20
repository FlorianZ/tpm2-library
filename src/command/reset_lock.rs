// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{AuthArgs, CommandError},
    device::{with_device, DeviceError},
    job::Job,
    key_cache::KeyCacheError,
};
use clap::Args;
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase, TpmRh},
    message::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(Args, Debug)]
pub struct ResetLock {
    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl SubCommand for ResetLock {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let lock_handle = (TpmRh::Lockout as u32).into();
            let command = TpmDictionaryAttackLockResetCommand { lock_handle };
            let handles = [TpmRh::Lockout as u32];
            let mut auths = vec![self.auth_args.auth.clone().unwrap_or_default()];

            let (resp, _) = match job.execute(device, &command, &handles, &mut auths) {
                Ok(result) => result,
                Err(KeyCacheError::Device(DeviceError::TpmRc(rc)))
                    if rc.base() == TpmRcBase::Lockout =>
                {
                    return Err(CommandError::DictionaryAttackLocked);
                }
                Err(e) => return Err(e.into()),
            };
            resp.DictionaryAttackLockReset()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;
            Ok(())
        })
    }
}
