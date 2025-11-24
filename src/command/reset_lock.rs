// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    task::TaskState,
};
use clap::Args;
use tpm2_device::with_device;
use tpm2_protocol::{
    data::{TpmCc, TpmRh},
    frame::TpmDictionaryAttackLockResetCommand,
    TpmHandle,
};

/// Resets the dictionary attack lockout counter.
#[derive(Args, Debug)]
pub struct ResetLock {
    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for ResetLock {
    fn run(
        &self,
        task_state: &mut TaskState,
        _writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let lock_handle = (TpmRh::Lockout as u32).into();
            let command = TpmDictionaryAttackLockResetCommand {
                handles: [lock_handle],
            };

            let auth_map = self.auth_args.build_auth_map();
            let auth = auth_map
                .get(&TpmHandle(lock_handle.into()))
                .cloned()
                .unwrap_or_default();

            let (resp, _) = task_state.execute(device, &command, &[auth])?;

            resp.DictionaryAttackLockReset()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;
            Ok(())
        })
    }
}
