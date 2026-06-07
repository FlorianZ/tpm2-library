// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::CommandError,
    io::{parse_u32, read_file_input},
    response::parse_response,
    task::TaskState,
};
use argh::FromArgs;
use std::path::PathBuf;
use tpm2_crypto::TpmHash;
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{Tpm2bEvent, TpmuHa},
    frame::{TpmPcrEventCommand, TpmPcrEventResponse},
};

fn parse_pcr_index(handle_str: &str) -> Result<TpmHandle, String> {
    parse_u32(handle_str)
        .map(TpmUint32::new)
        .map_err(|_| "malformed value".to_string())
}

/// Extends a PCR with an event.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "pcr-event", help_triggers("-h", "--help", "help"))]
pub struct PcrEvent {
    /// PCR index
    #[argh(positional, arg_name = "pcr-index", from_str_fn(parse_pcr_index))]
    pub pcr_index: TpmHandle,

    /// input file path (defaults to stdin as PEM)
    #[argh(option, short = 'I')]
    pub input: Option<PathBuf>,
}

impl Task for PcrEvent {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let data_bytes = read_file_input(self.input.as_deref())?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)?;
            let command = TpmPcrEventCommand {
                event_data,
                handles: [self.pcr_index],
            };

            let auth = task_state
                .auth_map
                .get(&self.pcr_index)
                .cloned()
                .unwrap_or_default();

            let resp = task_state.execute(device, &command, &[auth])?;
            let pcr_resp = parse_response::<TpmPcrEventResponse>(resp)?;

            let clauses: Vec<String> = pcr_resp
                .digests
                .iter()
                .filter_map(|digest_struct| {
                    if let TpmuHa::Digest(bytes) = &digest_struct.digest {
                        let hash = TpmHash::try_from(digest_struct.hash_alg).map_or_else(
                            |_| format!("{:?}", digest_struct.hash_alg),
                            |hash| hash.to_string(),
                        );
                        Some(format!(
                            "{}:{}:{}",
                            hash,
                            self.pcr_index.value(),
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
