// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, resolve_public_template},
        AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncodingArgs,
    },
    io::write_key_data,
    task::TaskState,
};

use clap::Args;
use tpm2_crypto::TpmPublicTemplate;
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmCc,
        TpmaObject, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyType};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    /// Parent's TPM handle as an eight characters hex string.
    pub parent: crate::handle::Handle,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash-hmac:sha256'.
    #[arg(value_parser = clap::value_parser!(TpmPublicTemplate))]
    pub algorithm: TpmPublicTemplate,

    /// Description
    #[arg(short = 'd', long)]
    pub description: Option<String>,

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
    ) -> Result<(TpmCreateCommand, PolicyCommands, bool), CommandError> {
        let user_auth = self.creation_args.parse_password()?;
        let mut object_attributes = self.creation_args.parse_attributes(&self.algorithm)?;

        object_attributes |= TpmaObject::SENSITIVE_DATA_ORIGIN;

        if self.algorithm.object_type() == TpmAlgId::KeyedHash {
            object_attributes |= TpmaObject::SIGN_ENCRYPT;
        }

        let (auth_policy_digest, policy_commands) = build_policy_command_list(
            &self.creation_args,
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

        let (parent_phys_handle, _, auth) = task_state.resolve_auth(
            device,
            TpmUint32(parent),
            &self.auth_args.build_auth_map()?,
        )?;

        let (create_cmd, policy_commands, empty_auth) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let (resp, _) = task_state.execute(device, &create_cmd, &[auth])?;
        let resp = resp
            .Create()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

        let policy = task_state.save_key_policy(device, policy_commands)?;

        let tpm_key = TpmKeyFile::new()
            .with_kind(TpmKeyType::Loadable)
            .with_empty_auth(empty_auth)
            .with_public(resp.out_public)
            .with_private(resp.out_private)
            .with_parent(parent_phys_handle)
            .with_description(self.description.clone().unwrap_or_default())
            .with_policy(TpmKeyPolicy::new(None, policy));

        write_key_data(
            writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.encoding,
        )
    }
}
