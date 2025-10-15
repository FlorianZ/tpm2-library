// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{get_auth, SubCommand},
    context::ContextCache,
    convert::{from_input_to_bytes, from_str_to_keyedhash_alg, from_tpm_key_to_output},
    device::{with_device, Device},
    key::{Alg, TpmKey, TpmKeyTemplate, OID_SEALED_DATA},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::data::{Tpm2bSensitiveData, TpmSe};

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

    /// policy digest
    #[argh(option)]
    pub policy: Option<String>,

    /// output: TPMKey file
    #[argh(option, short = 'o')]
    pub output: Option<Uri>,

    /// input: data file
    #[argh(option, short = 'i')]
    pub input: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_PARENT_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<String>,

    /// auth for the sealed object: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Seal {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let parent_auth = get_auth(
            self.parent_auth.as_ref(),
            "TPM2SH_PARENT_AUTH",
            &context.session_map,
            &[TpmSe::Policy],
        )?;
        let auth = get_auth(self.auth.as_ref(), "TPM2SH_AUTH", &context.session_map, &[])?;
        with_device(device, |device| {
            let parent_handle = context.load_parent(device, &self.parent)?;

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
                policy: self.policy.as_ref(),
                sensitive_data: data_to_seal,
                key_type_oid: OID_SEALED_DATA,
            };

            let tpm_key = TpmKey::new(
                device,
                context,
                &[parent_auth],
                &auth,
                parent_handle,
                &template,
            )?;

            from_tpm_key_to_output(context, &tpm_key, self.output.as_ref())
        })
    }
}
