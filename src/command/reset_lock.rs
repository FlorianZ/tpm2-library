// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Task, command::CommandError, task::TaskState};
use clap::Args;
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::TpmUint32,
    data::{TpmCc, TpmRh},
    frame::TpmDictionaryAttackLockResetCommand,
};

/// Resets the dictionary attack lockout counter.
#[derive(Args, Debug)]
pub struct ResetLock;

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

            let auth = task_state
                .auth_map
                .get(&TpmUint32(lock_handle.into()))
                .cloned()
                .unwrap_or_default();

            let (resp, _) = task_state.execute(device, &command, &[auth])?;

            resp.DictionaryAttackLockReset()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;
            Ok(())
        })
    }
}
