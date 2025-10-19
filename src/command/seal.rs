// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{AuthArgs, CommandError, CreationArgs, InputArgs, OutputArgs, OutputEncoding},
    convert::{from_input_to_bytes, from_str_to_keyedhash_alg, from_tpm_key_to_output},
    device::with_device,
    job::Job,
    key::{Alg, TpmKey, TpmKeyTemplate, OID_SEALED_DATA},
};
use clap::Args;
use tpm2_protocol::data::Tpm2bSensitiveData;

/// Creates a sealed data object.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a sealed data object.")]
pub struct Seal {
    #[clap(flatten)]
    pub parent_args: AuthArgs,

    /// Name algorithm
    #[arg(value_parser = from_str_to_keyedhash_alg)]
    pub algorithm: Alg,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl SubCommand for Seal {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let parent_handle = job
                .key_cache
                .load_parent(device, &self.parent_args.parent)?;

            let mut auths: Vec<Auth> = self.parent_args.auth.clone().into_iter().collect();
            let (object_attributes, user_auth, auth_policy) =
                self.creation_args.parse(&self.algorithm)?;
            let input_bytes = from_input_to_bytes(self.input_args.input.as_ref())?;

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

            let tpm_key = TpmKey::new(
                job,
                device,
                &mut auths,
                user_auth,
                auth_policy,
                object_attributes,
                parent_handle,
                &template,
            )?;

            from_tpm_key_to_output(
                &mut job.key_cache,
                &tpm_key,
                self.output_args.output.as_ref(),
                OutputEncoding::Pem,
            )
        })
    }
}
