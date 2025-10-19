// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::SubCommand,
    command::{CommandError, CreationArgs, OutputArgs, OutputEncodingArgs, ParentAuthArgs},
    convert::from_tpm_key_to_output,
    device::{with_device, Device},
    job::Job,
    key::{Alg, AlgInfo, TpmKey, TpmKeyTemplate, OID_LOADABLE_KEY, OID_SEALED_DATA},
};
use clap::Args;
use tpm2_protocol::data::Tpm2bSensitiveData;

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    #[clap(flatten)]
    pub parent_args: ParentAuthArgs,

    /// Object algorithm: (e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256')
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    /// With data to be encrypted with keyedhash.
    #[arg(long = "sensitive-data")]
    pub sensitive_data: Option<String>,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl SubCommand for Create {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| self.create_object(job, device))
    }
}

impl Create {
    fn create_object(&self, job: &mut Job, device: &mut Device) -> Result<(), CommandError> {
        let parent_handle = job
            .key_cache
            .load_parent(device, &self.parent_args.parent)?;
        let mut auths = vec![self.parent_args.auth.clone().unwrap_or_default()];
        let (object_attributes, user_auth, auth_policy) =
            self.creation_args.parse(&self.algorithm)?;

        let (sensitive_data, key_type_oid) = match (&self.sensitive_data, &self.algorithm.params) {
            (Some(hex_data), AlgInfo::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    return Err(CommandError::InvalidInput(
                        "Cannot seal empty data provided via --sensitive-data.".to_string(),
                    ));
                }
                (
                    Tpm2bSensitiveData::try_from(bytes.as_slice())?,
                    OID_SEALED_DATA,
                )
            }
            (None, AlgInfo::Rsa { .. } | AlgInfo::Ecc { .. }) => {
                (Tpm2bSensitiveData::default(), OID_LOADABLE_KEY)
            }
            (Some(_), _) => {
                return Err(CommandError::InvalidInput(format!(
                    "--sensitive-data is only valid with 'keyedhash' algorithms, not '{}'",
                    self.algorithm
                )))
            }
            (None, AlgInfo::KeyedHash) => {
                return Err(CommandError::InvalidInput(
                    "Missing --sensitive-data for 'keyedhash' algorithm.".to_string(),
                ))
            }
        };

        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data,
            key_type_oid,
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
            self.output_encoding_args.output_encoding,
        )
    }
}
