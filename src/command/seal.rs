// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, CreationArgs, InputArgs, OutputArgs},
        CommandError,
    },
    io::{read_file_input, write_key_data},
    task::TaskState,
};
use clap::Args;
use tpm2_crypto::{TpmHash, TpmPublicTemplate};
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint16, TpmUint32},
    data::{
        Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId,
        TpmCc, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtKeyedhashScheme, TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms,
        TpmuSymKeyBits, TpmuSymMode,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyType};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates a sealed data object (passive KeyedHash).
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a sealed data object.")]
pub struct Seal {
    /// Parent's TPM handle as an eight characters hex string.
    pub parent: crate::handle::Handle,

    /// Hash algorithm
    pub hash_algorithm: TpmHash,

    /// Data to seal (hex string)
    #[arg(long = "data", conflicts_with = "input")]
    pub data: Option<String>,

    #[clap(flatten)]
    pub input_args: InputArgs,

    /// Description
    #[arg(short = 'd', long)]
    pub description: Option<String>,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Task for Seal {
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
            self.create_sealed_object(task_state, writer, device)
        })
    }
}

impl Seal {
    /// Resolves the sensitive data to be sealed.
    fn resolve_data(&self) -> Result<Tpm2bSensitiveData, CommandError> {
        let bytes = if let Some(hex_str) = &self.data {
            hex::decode(hex_str).map_err(|_| CommandError::InvalidSensitiveData)?
        } else {
            read_file_input(self.input_args.input.as_deref())?
        };

        if bytes.is_empty() {
            return Err(CommandError::SensitiveDataMissing);
        }

        Tpm2bSensitiveData::try_from(bytes.as_slice()).map_err(|_| CommandError::CapacityExceeded)
    }

    fn build_create_command(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
    ) -> Result<(TpmCreateCommand, PolicyCommands, bool), CommandError> {
        let user_auth = self.creation_args.parse_password()?;
        let sensitive_data = self.resolve_data()?;

        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if !self.creation_args.lock {
            object_attributes |= TpmaObject::NO_DA;
        }
        if self.creation_args.password.is_some() || self.creation_args.policy_expression.is_none() {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if self.creation_args.policy_expression.is_some() {
            object_attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        let name_alg = TpmAlgId::from(self.hash_algorithm);

        let (auth_policy_digest, policy_commands) =
            build_policy_command_list(&self.creation_args, task_state, device, name_alg)?;

        let symmetric = TpmtSymDefObject {
            algorithm: TpmAlgId::Aes,
            key_bits: TpmuSymKeyBits::Aes(TpmUint16::from(128)),
            mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
        };

        let unique = TpmuPublicId::KeyedHash(Tpm2bDigest::default());
        let parms = TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
            scheme: TpmtKeyedhashScheme {
                scheme: TpmAlgId::Null,
                details: TpmuKeyedhashScheme::Null,
            },
        });

        let template = TpmPublicTemplate::new()
            .with_public(unique, parms)?
            .with_name_alg(name_alg)
            .with_object_attributes(object_attributes)
            .with_auth_policy(auth_policy_digest)
            .with_symmetric(symmetric);

        let create_cmd = TpmCreateCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth,
                    data: sensitive_data,
                },
            },
            in_public: Tpm2bPublic {
                inner: template.try_into()?,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
            handles: [parent_handle.0.into()],
        };

        Ok((create_cmd, policy_commands, user_auth.is_empty()))
    }

    fn create_sealed_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let Some(parent) = self.parent.value() else {
            return Err(CommandError::ParentMissing);
        };

        let (parent_phys_handle, _, auth) = task_state.resolve_auth(device, TpmUint32(parent))?;

        let (create_cmd, policy_commands, empty_auth) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let (resp, _) = task_state.execute(device, &create_cmd, &[auth])?;
        let resp = resp
            .Create()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

        let policy = task_state.save_key_policy(device, policy_commands)?;

        let tpm_key = TpmKeyFile::new()
            .with_kind(TpmKeyType::SealedData)
            .with_empty_auth(empty_auth)
            .with_public(resp.out_public)
            .with_private(resp.out_private)
            .with_parent(parent_phys_handle)
            .with_policy(TpmKeyPolicy::new(None, policy))
            .with_description(self.description.clone().unwrap_or_default());

        write_key_data(writer, &tpm_key, self.output_args.output.as_deref())
    }
}
