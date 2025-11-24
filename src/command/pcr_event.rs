// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs},
    io::{parse_u32, read_file_input},
    task::TaskState,
};
use clap::Args;
use tpm2_crypto::TpmHash;
use tpm2_device::with_device;
use tpm2_protocol::{
    data::{Tpm2bEvent, TpmCc, TpmuHa},
    frame::TpmPcrEventCommand,
    TpmHandle,
};

fn parse_pcr_index(handle_str: &str) -> Result<TpmHandle, String> {
    parse_u32(handle_str)
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
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let (_, banks) = device.fetch_pcr_bank_list()?;
            let handles = [self.pcr_index.0];

            let data_bytes = read_file_input(self.input_args.input.as_deref())?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)?;
            let command = TpmPcrEventCommand {
                event_data,
                handles: [handles[0].into()],
            };

            let (resp, _) =
                task_state.execute(device, &command, &self.auth_args.build_auth_list())?;

            let pcr_resp = resp
                .PcrEvent()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::PcrEvent))?;

            let clauses: Vec<String> = banks
                .iter()
                .zip(pcr_resp.digests.iter())
                .filter_map(|(alg, digest_struct)| {
                    if let TpmuHa::Digest(bytes) = digest_struct.digest {
                        Some(format!(
                            "{}:{}:{}",
                            TpmHash::from(*alg),
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
