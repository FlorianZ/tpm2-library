// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys.

use super::{deny_keyedhash, CommandError};
use crate::{
    cli::SubCommand,
    context::ContextCache,
    convert::{from_env_to_auth, from_tpm_key_to_output},
    device::{with_device, Auth, Device},
    key::{Alg, TpmKey, TpmKeyTemplate, OID_LOADABLE_KEY},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::data::{Tpm2bSensitiveData, TpmSe};

/// Creates secondary keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "create", note = "Creates a secondary key.")]
pub struct Create {
    /// parent: 'tpm:<handle>', or 'key:<name grip>'
    #[argh(positional)]
    pub parent: Uri,

    /// key algorithm
    #[argh(positional)]
    pub algorithm: Alg,

    /// policy digest
    #[argh(option)]
    pub policy: Option<String>,

    /// output: TPMKey file
    #[argh(option, short = 'o')]
    pub output: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_PARENT_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<String>,

    /// auth for the new key: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Create {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let parent_auth = from_env_to_auth(
            self.parent_auth.as_ref(),
            "TPM2SH_PARENT_AUTH",
            &context.session_map,
            Some(TpmSe::Policy),
        )?;
        let auth = from_env_to_auth(
            self.auth.as_ref(),
            "TPM2SH_AUTH",
            &context.session_map,
            None,
        )?;
        with_device(device, |device| {
            deny_keyedhash(&self.algorithm)?;
            self.create_secondary_key(device, context, &[parent_auth], &auth)
        })
    }
}

impl Create {
    fn create_secondary_key(
        &self,
        device: &mut Device,
        context: &mut ContextCache,
        auth_list: &[Auth],
        auth: &Auth,
    ) -> Result<(), CommandError> {
        let parent_handle = context.load_parent(device, &self.parent)?;

        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            policy: self.policy.as_ref(),
            sensitive_data: Tpm2bSensitiveData::default(),
            key_type_oid: OID_LOADABLE_KEY,
        };

        let tpm_key = TpmKey::new(device, context, auth_list, auth, parent_handle, &template)?;

        from_tpm_key_to_output(context, &tpm_key, self.output.as_ref())
    }
}
