// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{CommandError, OutputEncoding},
    convert::{from_input_to_bytes, from_str_to_keyedhash_alg, from_tpm_key_to_output},
    device::with_device,
    job::Job,
    key::{Alg, TpmKey, TpmKeyTemplate, OID_SEALED_DATA},
    uri::Uri,
};
use argh::FromArgs;
use tpm2_protocol::data::Tpm2bSensitiveData;

/// Creates a sealed data object.
#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand, name = "seal", note = "Creates a sealed data object.")]
pub struct Seal {
    /// parent: 'tpm:<handle>', or 'key:<name grip>'
    #[argh(positional)]
    pub parent: Uri,

    /// name algorithm
    #[argh(positional, from_str_fn(from_str_to_keyedhash_alg))]
    pub algorithm: Alg,

    /// output: TPMKey file
    #[argh(option, short = 'o')]
    pub output: Option<Uri>,

    /// input: data file
    #[argh(option, short = 'i')]
    pub input: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "parent-auth", short = 'p')]
    pub parent_auth: Option<Auth>,

    /// key auth: 'password:<hex>' or 'policy:<hex>'
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<Auth>,
}

impl SubCommand for Seal {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let parent_handle = job.key_cache.load_parent(device, &self.parent)?;

            let parent_auth =
                job.resolve_auth_session(device, self.parent_auth.clone(), parent_handle)?;
            let auth = self.auth.clone().unwrap_or(Auth::Password(Vec::new()));

            let input_bytes = from_input_to_bytes(self.input.as_ref())?;

            if input_bytes.is_empty() {
                return Err(CommandError::InvalidInput(
                    "Cannot seal empty data; please provide data via stdin or an input file."
                        .to_string(),
                ));
            }

            let data_to_seal = Tpm2bSensitiveData::try_from(input_bytes.as_slice())?;

            let template = TpmKeyTemplate {
                alg_desc: &self.algorithm,
                sensitive_data: data_to_seal,
                key_type_oid: OID_SEALED_DATA,
            };

            let tpm_key =
                TpmKey::new(job, device, &[parent_auth], &auth, parent_handle, &template)?;

            from_tpm_key_to_output(
                &mut job.key_cache,
                &tpm_key,
                self.output.as_ref(),
                OutputEncoding::Pem,
            )
        })
    }
}
