// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError},
    device::with_device,
    io::read_file_input,
    key::Tpm2shAlgId,
    parse_hex_u32,
    pcr::pcr_get_bank_list,
    session::Session,
};
use clap::Args;
use tpm2_protocol::{
    data::{Tpm2bEvent, TpmCc, TpmuHa},
    message::TpmPcrEventCommand,
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
}

impl Job for PcrEvent {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let banks = pcr_get_bank_list(device)?;
            let handles = [self.pcr_index.0];

            let data_bytes = read_file_input(None)?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
            let command = TpmPcrEventCommand {
                pcr_handle: handles[0].into(),
                event_data,
            };

            let (resp, _) = job.execute(device, &command, &handles, &self.auth_args.auths())?;

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
                            Tpm2shAlgId(bank.alg),
                            self.pcr_index.0,
                            hex::encode(bytes)
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            writeln!(job.writer, "{}", clauses.join("+"))?;

            Ok(())
        })
    }
}
