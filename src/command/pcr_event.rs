//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs},
    device::with_device,
    io::read_file_input,
    parse_hex_u32,
    pcr::pcr_get_bank_list,
    task::TaskState,
};
use clap::Args;
use tpm2_crypto::Hash;
use tpm2_protocol::{
    data::{Tpm2bEvent, TpmCc, TpmuHa},
    frame::TpmPcrEventCommand,
    TpmHandle,
};

fn parse_pcr_index(handle_str: &str) -> Result<TpmHandle, String> {
    parse_hex_u32(handle_str)
        .map(TpmHandle)
        .map_err(|_| "malformed value".to_string())
}

/// Extends a PCR with an event.
#[derive(Args, Debug)]
#[command(name = "pcr-event")]
pub struct PcrEvent {
    /// PCR index
    #[arg(value_name = "pcr-index", value_parser = parse_pcr_index)]
    pub pcr_index: TpmHandle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,
}

impl Task for PcrEvent {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let banks = pcr_get_bank_list(device)?;
            let handles = [self.pcr_index.0];

            let data_bytes = read_file_input(self.input_args.input.as_deref())?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)?;
            let command = TpmPcrEventCommand {
                pcr_handle: handles[0].into(),
                event_data,
            };

            let (resp, _) =
                task_state.execute(device, &command, &handles, &self.auth_args.auths(false))?;

            let pcr_resp = resp
                .PcrEvent()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::PcrEvent))?;

            let clauses: Vec<String> = banks
                .iter()
                .zip(pcr_resp.digests.iter())
                .filter_map(|(bank, digest_struct)| {
                    if let TpmuHa::Digest(bytes) = digest_struct.digest {
                        Some(format!(
                            "{}:{}:{}",
                            Hash::from(bank.alg),
                            self.pcr_index.0,
                            hex::encode(bytes)
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            writeln!(writer, "{}", clauses.join("+"))?;

            Ok(())
        })
    }
}
