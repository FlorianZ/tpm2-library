// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys.

use crate::{
    cli::SubCommand,
    command::{deny_keyedhash, AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncoding},
    convert::from_tpm_key_to_output,
    device::{with_device, Device},
    job::Job,
    key::{Alg, TpmKey, TpmKeyTemplate, OID_LOADABLE_KEY},
};
use clap::Args;
use tpm2_protocol::data::Tpm2bSensitiveData;

/// Creates secondary keys.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key.")]
pub struct Create {
    #[clap(flatten)]
    pub parent_args: AuthArgs,

    /// Key algorithm
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl SubCommand for Create {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            deny_keyedhash(&self.algorithm)?;
            self.create_secondary_key(job, device)
        })
    }
}

impl Create {
    fn create_secondary_key(&self, job: &mut Job, device: &mut Device) -> Result<(), CommandError> {
        let parent_handle = job
            .key_cache
            .load_parent(device, &self.parent_args.parent)?;
        let mut auths = vec![self.parent_args.auth.clone().unwrap_or_default()];
        let (object_attributes, user_auth, auth_policy) =
            self.creation_args.parse(&self.algorithm)?;
        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data: Tpm2bSensitiveData::default(),
            key_type_oid: OID_LOADABLE_KEY,
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
    }
}
