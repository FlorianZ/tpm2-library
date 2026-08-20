// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Task, response::parse_response, task::TaskState};
use anyhow::Result;
use argh::FromArgs;
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::TpmUint32,
    data::TpmRh,
    frame::{TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse},
};

/// Resets the dictionary attack lockout counter.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "reset-lock", help_triggers("-h", "--help", "help"))]
pub struct ResetLock {}

impl Task for ResetLock {
    fn run(
        &self,
        task_state: &mut TaskState,
        _writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        with_device(task_state.device.clone().as_ref(), |device| {
            let lock_handle = (TpmRh::Lockout as u32).into();
            let command = TpmDictionaryAttackLockResetCommand {
                handles: [lock_handle],
            };

            let auth = task_state.auth_for(TpmUint32::new(u32::from(lock_handle)));

            let resp = task_state.execute(device, &command, &[auth])?;
            parse_response::<TpmDictionaryAttackLockResetResponse>(resp)?;
            Ok(())
        })
    }
}
