//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    alg::{Alg, AlgInfo},
    cli::Task,
    command::{AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncodingArgs},
    io::write_key_data,
    pcr::{pcr_get_bank_list, resolve_pcr_digests},
    task::{is_empty_auth, TaskAuth, TaskError, TaskState},
    template,
};

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use clap::Args;
use tpm2_device::{with_device, TpmDevice};
use tpm2_policy_language::TpmPolicyExpression;
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmCc, TpmHt, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
    TpmHandle,
};
use tpm2_tpmkey::{
    tpm_key_command_from_command, TpmKey as TpmKeyFile, TpmKeyCommand, TpmPolicy, OID_LOADABLE_KEY,
    OID_SEALED_DATA,
};
use tpm2_vtpm::{VtpmHandle, VtpmHandleClass};

type PolicyCommands = Vec<(TpmCommand, TpmAuthCommands)>;

/// A template for creating a new TPM key object.
pub struct TpmKeyTemplate<'a> {
    pub alg_desc: &'a Alg,
    pub sensitive_data: Tpm2bSensitiveData,
}

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    /// Parent handle: 'tpm:<handle>' or 'vtpm:<handle>'
    pub parent: VtpmHandle,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256'.
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

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
        match (&self.data, &self.algorithm.params) {
            (Some(hex_data), AlgInfo::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    Err(CommandError::SensitiveDataMissing)
                } else {
                    Ok(Tpm2bSensitiveData::try_from(bytes.as_slice())
                        .map_err(|_| CommandError::CapacityExceeded)?)
                }
            }
            (None, AlgInfo::Rsa { .. } | AlgInfo::Ecc { .. }) => Ok(Tpm2bSensitiveData::default()),
            (Some(_), _) => Err(CommandError::SensitiveDataDenied),
            (None, AlgInfo::KeyedHash) => Err(CommandError::SensitiveDataMissing),
        }
    }

    #[allow(clippy::type_complexity)]
    fn resolve_policy(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
    ) -> Result<(Tpm2bDigest, Option<PolicyCommands>), CommandError> {
        if let Some(expression) = &self.creation_args.policy_expression {
            let banks = pcr_get_bank_list(device)?;
            let pcr_count = banks.iter().map(|b| b.count).max().unwrap_or(0);

            let static_pcr_banks: Vec<TpmAlgId> = banks.iter().map(|b| b.alg).collect();

            let tmp_policy_context = tpm2_policy_language::TpmPolicyState {
                pcr_count,
                pcr_banks: static_pcr_banks.clone(),
                names: HashMap::new(),
            };

            let tmp_ast = TpmPolicyExpression::new(expression, &tmp_policy_context)?;
            let mut handles = HashSet::new();
            visit_secret_handles(&tmp_ast, &mut handles)?;

            let mut names = HashMap::new();
            for &handle in &handles {
                let (_, name) = device.read_public(handle.into())?;
                names.insert(handle, name);
            }

            let policy_context = tpm2_policy_language::TpmPolicyState {
                pcr_count,
                pcr_banks: static_pcr_banks,
                names,
            };

            let mut ast = TpmPolicyExpression::new(expression, &policy_context)?;
            let session_hash_alg = self.algorithm.name_alg;

            resolve_pcr_digests(task_state, device, &mut ast, session_hash_alg, &banks)?;

            let (commands, final_digest) =
                ast.to_command_list(session_hash_alg, &policy_context)?;

            Ok((final_digest, Some(commands)))
        } else {
            Ok((Tpm2bDigest::default(), None))
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

        let (auth_policy_digest, policy_commands) = self.resolve_policy(task_state, device)?;

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

    fn create_object(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let parent_phys_handle = task_state.load_context(device, &self.parent)?;

        let (policy_blob, name_alg, parent_empty_auth) =
            task_state.resolve_policy(device, &self.parent, parent_phys_handle)?;

        let (auths, policy_session_auth) = task_state.build_auth(
            device,
            &policy_blob,
            name_alg,
            parent_empty_auth,
            &self.auth_args,
        )?;

        let (create_cmd, policy_commands) =
            self.build_create_command(task_state, device, parent_phys_handle)?;

        let handles = [parent_phys_handle.0];
        let execution_result = task_state.execute(device, &create_cmd, &handles, &auths);

        if let Some(TaskAuth::Session(vhandle)) = policy_session_auth {
            if let Err(e) = task_state.remove_session(device, vhandle) {
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

        let (parent_public_data, _) = device.read_public(parent_phys_handle)?;
        let parent_public_2b = Tpm2bPublic {
            inner: parent_public_data,
        };

        let empty_auth = is_empty_auth(&create_resp.out_public.inner);

        let tpm_key_policy = if let Some(commands) = &policy_commands {
            let mut policy: Vec<Box<dyn TpmKeyCommand>> = Vec::new();
            for (cmd, _) in commands {
                let object_name = if let TpmCommand::PolicySecret(inner) = cmd {
                    let (_, name) = device.read_public(inner.handles[0])?;
                    name
                } else {
                    Tpm2bName::default()
                };
                policy.push(tpm_key_command_from_command(cmd, &object_name)?);
            }

            Some(TpmPolicy { name: None, policy })
        } else {
            None
        };

        let oid = if matches!(self.algorithm.params, AlgInfo::KeyedHash) {
            OID_SEALED_DATA
        } else {
            OID_LOADABLE_KEY
        };

        let tpm_key = TpmKeyFile {
            public: create_resp.out_public,
            private: create_resp.out_private,
            parent_handle: parent_phys_handle,
            parent_public: Some(parent_public_2b),
            empty_auth: if empty_auth { Some(true) } else { None },
            policy: tpm_key_policy,
            auth_policy: None,
            secret: None,
            description: None,
            oid,
        };

        write_key_data(
            writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}

fn visit_secret_handles<S: BuildHasher>(
    ast: &TpmPolicyExpression,
    handles: &mut HashSet<u32, S>,
) -> Result<(), CommandError> {
    match ast {
        TpmPolicyExpression::Pcr { .. } | TpmPolicyExpression::Handle(_) => {}
        TpmPolicyExpression::And(branches) | TpmPolicyExpression::Or(branches) => {
            for branch in branches {
                visit_secret_handles(branch, handles)?;
            }
        }
        TpmPolicyExpression::Secret { auth_handle, .. } => {
            if let TpmPolicyExpression::Handle(handle) = &**auth_handle {
                let Some(val) = handle.value() else {
                    return Err(CommandError::PatternNotAllowed(auth_handle.to_string()));
                };

                if handle.class() != VtpmHandleClass::Tpm
                    || (val >> 24) as u8 != TpmHt::Persistent as u8
                {
                    return Err(CommandError::InvalidHandle);
                }
                handles.insert(val);
            } else {
                return Err(CommandError::InvalidPolicyExpression(
                    "secret() first argument must be a handle".to_string(),
                ));
            }
        }
    }
    Ok(())
}
