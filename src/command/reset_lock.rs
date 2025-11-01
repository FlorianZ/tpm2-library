// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError},
    device::with_device,
    session::Session,
};
use clap::Args;
use tpm2_protocol::{
    data::{TpmCc, TpmRh},
    frame::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(Args, Debug)]
pub struct ResetLock {
    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Job for ResetLock {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let lock_handle = (TpmRh::Lockout as u32).into();
            let command = TpmDictionaryAttackLockResetCommand { lock_handle };
            let handles = [TpmRh::Lockout as u32];

            let (resp, _) = job.execute(device, &command, &handles, &self.auth_args.auths())?;

            resp.DictionaryAttackLockReset()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;
            Ok(())
        })
    }
}
