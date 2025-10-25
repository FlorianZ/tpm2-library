// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::SubCommand,
    command::{CommandError, CreationArgs, OutputArgs, OutputEncodingArgs, ParenBindArgs},
    device::{with_device, Device},
    io::write_key_data,
    job::Job,
    key::{Alg, AlgInfo, KeyError, TpmKey, TpmKeyTemplate, OID_LOADABLE_KEY, OID_SEALED_DATA},
};
use clap::Args;
use tpm2_protocol::data::Tpm2bSensitiveData;

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    #[clap(flatten)]
    pub parent_args: ParenBindArgs,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256'.
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    /// Sensitive data: hex string
    #[arg(long = "data")]
    pub data: Option<String>,

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
        let auths = &self.parent_args.auth;
        let parent_handle = job.load_context(device, &self.parent_args.parent, auths)?;

        let (object_attributes, user_auth, auth_policy) =
            self.creation_args.parse(&self.algorithm)?;

        let (sensitive_data, key_type_oid) = match (&self.data, &self.algorithm.params) {
            (Some(hex_data), AlgInfo::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    Err(CommandError::SensitiveDataMissing)
                } else {
                    Ok((
                        Tpm2bSensitiveData::try_from(bytes.as_slice())?,
                        OID_SEALED_DATA,
                    ))
                }
            }
            (None, AlgInfo::Rsa { .. } | AlgInfo::Ecc { .. }) => {
                Ok((Tpm2bSensitiveData::default(), OID_LOADABLE_KEY))
            }
            (Some(_), _) | (None, AlgInfo::KeyedHash) => Err(CommandError::SensitiveDataDenied),
        }?;

        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data,
            key_type_oid,
        };

        let tpm_key = TpmKey::new(
            job,
            device,
            auths,
            user_auth,
            auth_policy,
            object_attributes,
            parent_handle,
            &template,
        )
        .map_err(|e| {
            if let KeyError::InvalidParent(phandle) = e {
                if let Ok(key) = job.cache.find_by_phandle(device, phandle) {
                    return CommandError::InvalidParent("vtpm:", key.context.saved_handle.0);
                }
                return CommandError::InvalidParent("tpm:", phandle);
            }
            CommandError::Key(e)
        })?;

        write_key_data(
            &mut job.writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}
