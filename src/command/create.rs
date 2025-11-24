// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::Task,
    command::{
        common::build_policy_command_list, AuthArgs, CommandError, CreationArgs, OutputArgs,
        OutputEncodingArgs,
    },
    io::write_key_data,
    task::{TaskAuth, TaskError, TaskState},
};

use clap::Args;
use tpm2_crypto::{TpmPublicTemplate, TpmPublicTemplateType};
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmlPcrSelection,
        TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
    TpmHandle,
};
use tpm2_vtpm::VtpmHandle;

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    /// Parent handle: 'tpm:<handle>' or 'vtpm:<handle>'
    pub parent: VtpmHandle,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256'.
    #[arg(value_parser = clap::value_parser!(TpmPublicTemplate))]
    pub algorithm: TpmPublicTemplate,

    /// Sensitive data: hex string
    #[arg(long = "data")]
    pub data: Option<String>,

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
    fn get_sensitive_data(&self) -> Result<Tpm2bSensitiveData, CommandError> {
        match (&self.data, &self.algorithm.kind) {
            (Some(hex_data), TpmPublicTemplateType::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    Err(CommandError::SensitiveDataMissing)
                } else {
                    Ok(Tpm2bSensitiveData::try_from(bytes.as_slice())
                        .map_err(|_| CommandError::CapacityExceeded)?)
                }
            }
            (None, TpmPublicTemplateType::Rsa { .. } | TpmPublicTemplateType::Ecc { .. }) => {
                Ok(Tpm2bSensitiveData::default())
            }
            (Some(_), _) => Err(CommandError::SensitiveDataDenied),
            (None, TpmPublicTemplateType::KeyedHash) => Err(CommandError::SensitiveDataMissing),
        }
    }

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
    ) -> Result<(TpmCreateCommand, Option<PolicyCommands>), CommandError> {
        let (object_attributes, user_auth) = self.creation_args.parse(&self.algorithm)?;
        let sensitive_data = self.get_sensitive_data()?;

        let (auth_policy_digest, policy_commands) = build_policy_command_list(
            &self.creation_args,
            task_state,
            device,
            self.algorithm.hash,
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

        Ok((create_cmd, policy_commands))
    }

    fn create_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let (parent_phys_handle, _, auths, policy_session_auth) =
            task_state.build_auth(device, &self.parent, &self.auth_args)?;

        let (create_cmd, policy_commands) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let execution_result = task_state.execute(device, &create_cmd, &auths);

        if let Some(TaskAuth::Session(vhandle)) = policy_session_auth {
            if let Err(e) = task_state.remove_session(device, TpmHandle(vhandle)) {
                log::error!("vtpm:{vhandle:08x}: {e}");
            }
        }

        let (resp, _) = execution_result.map_err(|err| {
            if let TaskError::Device(device_err) = err {
                return CommandError::from(device_err);
            }
            err.into()
        })?;

        let create_resp = resp
            .Create()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

        let tpm_key = task_state.build_tpm_key_file(
            device,
            create_resp.out_public,
            create_resp.out_private,
            parent_phys_handle,
            policy_commands,
        )?;

        write_key_data(
            writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}
