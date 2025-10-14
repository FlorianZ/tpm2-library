// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{get_auth, SubCommand},
    context::ContextCache,
    convert::{from_input_to_bytes, from_str_to_handle},
    device::{self, Auth, Device, DeviceError},
    key::Tpm2shAlgId,
    pcr::pcr_get_bank_list,
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{Tpm2bEvent, TpmCc, TpmSe, TpmuHa},
    message::TpmPcrEventCommand,
    TpmHandle,
};

/// Extends a PCR with an event.
#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "pcr-event",
    note = "Extends a Platform Configuration Register (PCR) with data.

This command computes the digest of the provided data and uses it to
extend the state of the specified PCR. This is a one-way operation.

The output is a single, reusable policy expression that can be used
in other commands.

Example:
  # Extend PCR 16 with the SHA256 digest of the string \"my-event\"
  echo -n \"my-event\" | tpm2sh pcr-event 16"
)]
pub struct PcrEvent {
    /// PCR index
    #[argh(positional, arg_name = "pcr-index", from_str_fn(from_str_to_handle))]
    pub pcr_index: TpmHandle,

    /// data file to be hashed (reads from stdin if not provided)
    #[argh(positional)]
    pub input: Option<Uri>,

    /// auth for the PCR: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for PcrEvent {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth = match (self.auth.as_ref(), self.hmac_auth.as_ref()) {
            (Some(_), Some(_)) => {
                return Err(CommandError::InvalidInput(
                    "Cannot use --auth and --hmac-auth at the same time".to_string(),
                ));
            }
            (Some(auth_str), None) => get_auth(
                Some(auth_str),
                "TPM2SH_AUTH",
                &context.session_map,
                &[TpmSe::Policy],
            )?,
            (None, Some(hmac_auth_str)) => get_auth(
                Some(hmac_auth_str),
                "TPM2SH_HMAC_AUTH",
                &context.session_map,
                &[TpmSe::Hmac],
            )?,
            (None, None) => {
                let auth = get_auth(None, "TPM2SH_AUTH", &context.session_map, &[TpmSe::Policy])?;
                if matches!(&auth, Auth::Password(p) if p.is_empty()) {
                    get_auth(
                        None,
                        "TPM2SH_HMAC_AUTH",
                        &context.session_map,
                        &[TpmSe::Hmac],
                    )?
                } else {
                    auth
                }
            }
        };
        device::with_device(device, |device| {
            let banks = pcr_get_bank_list(device)?;
            let handles = [self.pcr_index.0];
            let auths = &[auth];

            let data_bytes = from_input_to_bytes(self.input.as_ref())?;

            let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
            let command = TpmPcrEventCommand {
                pcr_handle: handles[0].into(),
                event_data,
            };

            let (resp, _) = context.execute(device, &command, &handles, auths)?;

            let pcr_resp = resp
                .PcrEvent()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::PcrEvent))?;

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

            writeln!(context.writer, "{}", clauses.join("+"))?;

            Ok(())
        })
    }
}
