// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{CommandError, InputArgs},
    device::with_device,
    io::read_file_input,
    job::Job,
    key::Tpm2shAlgId,
    pcr::pcr_get_bank_list,
};
use clap::Args;
use tpm2_protocol::{
    data::{Tpm2bEvent, TpmCc, TpmuHa},
    message::TpmPcrEventCommand,
    TpmHandle,
};

fn parse_pcr_index(handle_str: &str) -> Result<TpmHandle, String> {
    let handle_str = handle_str.strip_prefix("0x").unwrap_or(handle_str);
    u32::from_str_radix(handle_str, 16)
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
    pub input_args: InputArgs,

    /// Auth for the PCR: 'password:<hex>', 'policy:<hex>' or 'vtpm:<session_handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

impl SubCommand for PcrEvent {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let banks = pcr_get_bank_list(device)?;
            let handles = [self.pcr_index.0];

            let auths = vec![self.auth.clone().unwrap_or_default()];

            let data_bytes = read_file_input(self.input_args.input.as_deref())?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
            let command = TpmPcrEventCommand {
                pcr_handle: handles[0].into(),
                event_data,
            };

            let (resp, _) = job.execute(device, &command, &handles, &auths)?;

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

            writeln!(job.key_cache.writer, "{}", clauses.join("+"))?;

            Ok(())
        })
    }
}
