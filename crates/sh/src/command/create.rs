// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::Task,
    command::common::{
        build_policy_command_list, parse_creation_attributes, parse_password,
        resolve_public_template,
    },
    io::write_key_data,
    response::parse_response,
    task::TaskState,
};
use anyhow::{Result, anyhow};

use argh::FromArgs;
use std::path::PathBuf;
use tpm2_crypto::TpmPublicTemplate;
use tpm2_device::{TpmDevice, with_device};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmlPcrSelection,
        TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommandValue as TpmCommand, TpmCreateCommand, TpmCreateResponse},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyType};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates secondary keys or sealed data objects.
#[derive(FromArgs, Debug, Clone)]
#[argh(
    subcommand,
    name = "create",
    description = "Creates a secondary key or a sealed data object.",
    help_triggers("-h", "--help", "help")
)]
pub struct Create {
    /// parent's TPM handle as an eight characters hex string
    #[argh(positional)]
    pub parent: crate::handle::Handle,

    /// object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash-hmac:sha256'
    #[argh(positional)]
    pub algorithm: TpmPublicTemplate,

    /// description
    #[argh(option, short = 'd')]
    pub description: Option<String>,

    /// output file path (defaults to stdout as PEM)
    #[argh(option, short = 'O')]
    pub output: Option<PathBuf>,

    /// authentication value: '<hex string>'
    #[argh(option)]
    pub password: Option<String>,

    /// policy expression: e.g., 'pcr(sha256:7)'
    #[argh(option, long = "policy")]
    pub policy_expression: Option<String>,

    /// enable dictionary attack protection
    #[argh(switch)]
    pub lock: bool,
}

impl Task for Create {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        let parent = self
            .parent
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.parent))?;

        with_device(task_state.device.clone().as_ref(), |device| {
            self.create_object(task_state, writer, device, parent)
        })
    }
}

impl Create {
    /// Builds the TPM2_Create command by parsing arguments and resolving policies.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing arguments, handling sensitive data, or resolving the policy fails.
    fn build_create_command(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
    ) -> Result<(TpmCreateCommand, PolicyCommands, bool)> {
        let user_auth = parse_password(self.password.as_deref())?;
        let object_attributes = parse_creation_attributes(
            self.password.as_deref(),
            self.policy_expression.as_deref(),
            self.lock,
            &self.algorithm,
        )?;

        let (auth_policy_digest, policy_commands) = build_policy_command_list(
            self.policy_expression.as_deref(),
            task_state,
            device,
            self.algorithm.name_alg(),
        )?;

        let public_area =
            resolve_public_template(&self.algorithm, object_attributes, auth_policy_digest)?;

        let create_cmd = TpmCreateCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth,
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic { inner: public_area },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
            handles: [parent_handle],
        };

        Ok((create_cmd, policy_commands, user_auth.is_empty()))
    }

    fn create_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
        parent: u32,
    ) -> Result<()> {
        let (parent_phys_handle, _, auth) =
            task_state.resolve_auth(device, TpmUint32::new(parent))?;

        let (create_cmd, policy_commands, empty_auth) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let resp = task_state.execute(device, &create_cmd, &[auth])?;
        let resp = parse_response::<TpmCreateResponse>(resp)?;

        let policy = task_state.save_key_policy(device, policy_commands)?;

        let tpm_key = TpmKeyFile::new()
            .with_kind(TpmKeyType::Loadable)
            .with_empty_auth(empty_auth)
            .with_public(resp.out_public)
            .with_private(resp.out_private)
            .with_parent(parent_phys_handle)
            .with_description(self.description.clone().unwrap_or_default())
            .with_policy(&policy);

        write_key_data(writer, &tpm_key, self.output.as_deref())
    }
}
