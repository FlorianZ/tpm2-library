// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, resolve_sensitive_data},
        AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncodingArgs,
    },
    io::write_key_data,
    task::TaskState,
};

use clap::Args;
use std::path::PathBuf;
use tpm2_crypto::TpmPublicTemplate;
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, TpmCc, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    /// Parent's TPM handle as an eight characters hex string.
    pub parent: crate::handle::Handle,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256'.
    #[arg(value_parser = clap::value_parser!(TpmPublicTemplate))]
    pub algorithm: TpmPublicTemplate,

    /// Sensitive data: hex string
    #[arg(long = "data", conflicts_with = "input")]
    pub data: Option<String>,

    /// Sensitive data: input file (read as binary)
    #[arg(short = 'I', long, conflicts_with = "data")]
    pub input: Option<PathBuf>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Task for Create {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        self.parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(task_state.device.clone(), |device| {
            self.create_object(task_state, writer, device)
        })
    }
}

impl Create {
    /// Builds the TPM2_Create command by parsing arguments and resolving policies.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] if parsing arguments, handling sensitive data,
    /// or resolving the policy fails.
    fn build_create_command(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
    ) -> Result<(TpmCreateCommand, Option<PolicyCommands>, bool), CommandError> {
        let user_auth = self.creation_args.parse_password()?;
        let object_attributes = self.creation_args.parse_attributes(&self.algorithm)?;
        let sensitive_data = resolve_sensitive_data(
            self.data.as_deref(),
            self.input.as_deref(),
            self.algorithm.object_type,
        )?;

        let (auth_policy_digest, policy_commands) = build_policy_command_list(
            &self.creation_args,
            task_state,
            device,
            self.algorithm.name_alg,
        )?;

        let public_template = self
            .algorithm
            .to_public(auth_policy_digest, object_attributes);

        let create_cmd = TpmCreateCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth,
                    data: sensitive_data,
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
            handles: [parent_handle.0.into()],
        };

        Ok((create_cmd, policy_commands, user_auth.is_empty()))
    }

    fn create_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let Some(parent) = self.parent.value() else {
            return Err(CommandError::ParentMissing);
        };

        let (parent_phys_handle, _, auth) =
            task_state.resolve_auth(device, TpmUint32(parent), &self.auth_args.build_auth_map())?;

        let (create_cmd, policy_commands, empty_auth) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let (resp, _) = task_state.execute(device, &create_cmd, &[auth])?;
        let resp = resp
            .Create()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

        let tpm_key = task_state.build_tpm_key_file(
            device,
            resp.out_public,
            resp.out_private,
            parent_phys_handle,
            empty_auth,
            policy_commands,
        )?;

        write_key_data(
            writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.encoding,
        )
    }
}
