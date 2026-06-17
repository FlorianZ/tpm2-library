// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::common::{build_policy_command_list, default_symmetric, parse_password},
    io::{read_file_input, write_key_data},
    response::parse_response,
    task::TaskState,
};
use anyhow::{Result, anyhow};
use argh::FromArgs;
use std::path::PathBuf;
use tpm2_crypto::{TpmHash, TpmPublicTemplate};
use tpm2_device::{TpmDevice, with_device};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId,
        TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate, TpmtKeyedhashScheme,
        TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms,
    },
    frame::{TpmAuthCommands, TpmCommandValue as TpmCommand, TpmCreateCommand, TpmCreateResponse},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyType};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// Creates a sealed data object (passive KeyedHash).
#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand, name = "seal", help_triggers("-h", "--help", "help"))]
pub struct Seal {
    /// parent's TPM handle as an eight characters hex string
    #[argh(positional)]
    pub parent: crate::handle::Handle,

    /// hash algorithm
    #[argh(positional)]
    pub hash_algorithm: TpmHash,

    /// data to seal as a hex string
    #[argh(option)]
    pub data: Option<String>,

    /// input file path (defaults to stdin as PEM)
    #[argh(option, short = 'I')]
    pub input: Option<PathBuf>,

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

impl Task for Seal {
    fn validate(&self) -> Result<()> {
        if self.data.is_some() && self.input.is_some() {
            return Err(anyhow!(
                "invalid input: --data and --input are mutually exclusive"
            ));
        }

        Ok(())
    }

    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        self.validate()?;
        self.parent
            .value()
            .ok_or_else(|| anyhow!("handle pattern not allowed: {}", self.parent))?;

        with_device(task_state.device.clone(), |device| {
            self.create_sealed_object(task_state, writer, device)
        })
    }
}

impl Seal {
    /// Resolves the sensitive data to be sealed.
    fn resolve_data(&self) -> Result<Tpm2bSensitiveData> {
        let bytes = if let Some(hex_str) = &self.data {
            hex::decode(hex_str).map_err(|_| anyhow!("sensitive data is not a valid hex string"))?
        } else {
            read_file_input(self.input.as_deref())?
        };

        if bytes.is_empty() {
            return Err(anyhow!("sensitive data missing"));
        }

        Tpm2bSensitiveData::try_from(bytes.as_slice()).map_err(|_| anyhow!("capacity exceeded"))
    }

    fn build_create_command(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
    ) -> Result<(TpmCreateCommand, PolicyCommands, bool)> {
        let user_auth = parse_password(self.password.as_deref())?;
        let sensitive_data = self.resolve_data()?;

        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if !self.lock {
            object_attributes |= TpmaObject::NO_DA;
        }
        if self.password.is_some() || self.policy_expression.is_none() {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if self.policy_expression.is_some() {
            object_attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        let name_alg = TpmAlgId::from(self.hash_algorithm);

        let (auth_policy_digest, policy_commands) = build_policy_command_list(
            self.policy_expression.as_deref(),
            task_state,
            device,
            name_alg,
        )?;

        let symmetric = default_symmetric();

        let unique = TpmuPublicId::KeyedHash(Tpm2bDigest::default());
        let parms = TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
            scheme: TpmtKeyedhashScheme {
                scheme: TpmAlgId::Null,
                details: TpmuKeyedhashScheme::Null,
            },
        });

        let template = TpmPublicTemplate::new()
            .with_public(unique, parms)?
            .with_name_alg(TpmHash::try_from(name_alg)?)
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
            handles: [parent_handle],
        };

        Ok((create_cmd, policy_commands, user_auth.is_empty()))
    }

    fn create_sealed_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<()> {
        let Some(parent) = self.parent.value() else {
            return Err(anyhow!("parent missing"));
        };

        let (parent_phys_handle, _, auth) =
            task_state.resolve_auth(device, TpmUint32::new(parent))?;

        let (create_cmd, policy_commands, empty_auth) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let resp = task_state.execute(device, &create_cmd, &[auth])?;
        let resp = parse_response::<TpmCreateResponse>(resp)?;

        let policy = task_state.save_key_policy(device, policy_commands)?;

        let tpm_key = TpmKeyFile::new()
            .with_kind(TpmKeyType::SealedData)
            .with_empty_auth(empty_auth)
            .with_public(resp.out_public)
            .with_private(resp.out_private)
            .with_parent(parent_phys_handle)
            .with_policy(&policy)
            .with_description(self.description.clone().unwrap_or_default());

        write_key_data(writer, &tpm_key, self.output.as_deref())
    }
}
