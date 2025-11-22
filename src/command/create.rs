// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    alg::{TpmPublicKind, TpmPublicTemplate},
    cli::Task,
    command::{
        common::resolve_policy, AuthArgs, CommandError, CreationArgs, OutputArgs,
        OutputEncodingArgs,
    },
    io::write_key_data,
    task::{is_empty_auth, TaskAuth, TaskError, TaskState},
    template,
};

use clap::Args;
use tpm2_crypto::tpm_make_name;
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bName, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand, TpmCreateResponse},
    TpmHandle,
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyPolicyCommand, TpmKeyType};
use tpm2_vtpm::{vtpm_policy_command_from, VtpmHandle, VtpmPolicyCommand};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// A template for creating a new TPM key object.
pub struct TpmKeyTemplate<'a> {
    pub alg_desc: &'a TpmPublicTemplate,
    pub sensitive_data: Tpm2bSensitiveData,
}

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
            (Some(hex_data), TpmPublicKind::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    Err(CommandError::SensitiveDataMissing)
                } else {
                    Ok(Tpm2bSensitiveData::try_from(bytes.as_slice())
                        .map_err(|_| CommandError::CapacityExceeded)?)
                }
            }
            (None, TpmPublicKind::Rsa { .. } | TpmPublicKind::Ecc { .. }) => {
                Ok(Tpm2bSensitiveData::default())
            }
            (Some(_), _) => Err(CommandError::SensitiveDataDenied),
            (None, TpmPublicKind::KeyedHash) => Err(CommandError::SensitiveDataMissing),
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

        let (auth_policy_digest, policy_commands) =
            resolve_policy(&self.creation_args, task_state, device, self.algorithm.hash)?;

        let public_template =
            template::build_public(&self.algorithm, auth_policy_digest, object_attributes);

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

    fn construct_tpm_key(
        &self,
        task_state: &TaskState,
        device: &mut TpmDevice,
        create_resp: TpmCreateResponse,
        parent_phys_handle: TpmHandle,
        policy_commands: Option<&PolicyCommands>,
    ) -> Result<TpmKeyFile, CommandError> {
        let (parent_public_data, _) = device.read_public(parent_phys_handle)?;
        let parent_public_2b = Tpm2bPublic {
            inner: parent_public_data,
        };

        let empty_auth = is_empty_auth(&create_resp.out_public.inner);

        let tpm_key_policy = if let Some(commands) = policy_commands {
            let mut vtpm_policy: Vec<Box<dyn VtpmPolicyCommand>> = Vec::new();
            for (cmd, _) in commands {
                let object_name = if let TpmCommand::PolicySecret(inner) = cmd {
                    if let Ok(key) = task_state.cache.find_by_virtual_handle(inner.handles[0]) {
                        tpm_make_name(&key.public)?
                    } else {
                        let (_, name) = device.read_public(inner.handles[0])?;
                        name
                    }
                } else {
                    Tpm2bName::default()
                };
                vtpm_policy.push(vtpm_policy_command_from(cmd, &object_name)?);
            }

            let mut policy: Vec<TpmKeyPolicyCommand> = Vec::new();
            for cmd in vtpm_policy {
                policy.push(TpmKeyPolicyCommand {
                    cc: cmd.cc(),
                    body: cmd.body(),
                });
            }

            Some(TpmKeyPolicy { name: None, policy })
        } else {
            None
        };

        let kind = if matches!(self.algorithm.kind, TpmPublicKind::KeyedHash) {
            TpmKeyType::SealedData
        } else {
            TpmKeyType::Loadable
        };

        Ok(TpmKeyFile {
            public: create_resp.out_public,
            private: create_resp.out_private,
            parent_handle: parent_phys_handle,
            parent_public: Some(parent_public_2b),
            empty_auth: if empty_auth { Some(true) } else { None },
            policy: tpm_key_policy,
            auth_policy: None,
            secret: None,
            description: None,
            kind,
        })
    }

    fn create_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let (parent_phys_handle, policy_blob, name_alg, parent_empty_auth) =
            task_state.resolve_policy(device, &self.parent)?;

        let (auths, policy_session_auth) = task_state.build_auth(
            device,
            &policy_blob,
            name_alg,
            parent_empty_auth,
            &self.auth_args,
        )?;

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

        let tpm_key = self.construct_tpm_key(
            task_state,
            device,
            create_resp,
            parent_phys_handle,
            policy_commands.as_ref(),
        )?;

        write_key_data(
            writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}
