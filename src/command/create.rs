// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys.

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{deny_keyedhash, CommandError, OutputEncoding},
    convert::from_tpm_key_to_output,
    device::{with_device, Device},
    job::Job,
    key::{Alg, TpmKey, TpmKeyTemplate, OID_LOADABLE_KEY},
    uri::Uri,
};
use argh::FromArgs;
use tpm2_protocol::data::Tpm2bSensitiveData;

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

    /// output: TPMKey file
    #[argh(option, short = 'o')]
    pub output: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "parent-auth", short = 'p')]
    pub parent_auth: Option<Auth>,

    /// key auth: 'password:<hex>' or 'policy:<hex>'
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<Auth>,
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
        let parent_handle = job.key_cache.load_parent(device, &self.parent)?;
        let parent_auth =
            job.resolve_auth_session(device, self.parent_auth.clone(), parent_handle)?;
        let auth = self.auth.clone().unwrap_or(Auth::Password(Vec::new()));
        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data: Tpm2bSensitiveData::default(),
            key_type_oid: OID_LOADABLE_KEY,
        };
        let tpm_key = TpmKey::new(job, device, &[parent_auth], &auth, parent_handle, &template)?;
        from_tpm_key_to_output(
            &mut job.key_cache,
            &tpm_key,
            self.output.as_ref(),
            OutputEncoding::Pem,
        )
    }
}
