//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    alg::{Alg, AlgInfo},
    cli::Job,
    command::{AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncodingArgs},
    device::{with_device, Device, DeviceError},
    io::write_key_data,
    pcr::{pcr_get_bank_list, resolve_pcr_digests},
    policy::visit_secret_handles,
    session::{Session, SessionError},
    template,
};
use clap::Args;
use std::collections::{HashMap, HashSet};
use tpm2_policy_language::{Expression, Handle};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId,
        TpmCc, TpmRcBase, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmCreateCommand},
};
use tpm2_tpmkey::TpmKey;

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
    pub parent: Handle,

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

impl Job for Create {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        self.parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(job.device.clone(), |device| self.create_object(job, device))
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
        job: &mut Session,
        device: &mut Device,
    ) -> Result<(Tpm2bDigest, Option<Vec<(TpmCommand, TpmAuthCommands)>>), CommandError> {
        if let Some(expression) = &self.creation_args.policy_expression {
            let banks = pcr_get_bank_list(device)?;
            let pcr_count = banks.iter().map(|b| b.count).max().unwrap_or(0);

            let static_pcr_banks: Vec<TpmAlgId> = banks.iter().map(|b| b.alg).collect();

            let tmp_policy_context = tpm2_policy_language::PolicyState {
                pcr_count,
                pcr_banks: static_pcr_banks.clone(),
                names: HashMap::new(),
            };

            let tmp_ast = Expression::new(expression, &tmp_policy_context)?;
            let mut handles = HashSet::new();
            visit_secret_handles(&tmp_ast, &mut handles)?;

            let mut names = HashMap::new();
            for &handle in &handles {
                let (_, name) = device.read_public(handle.into())?;
                names.insert(handle, name);
            }

            let policy_context = tpm2_policy_language::PolicyState {
                pcr_count,
                pcr_banks: static_pcr_banks,
                names,
            };

            let mut ast = Expression::new(expression, &policy_context)?;
            let session_hash_alg = self.algorithm.name_alg;

            resolve_pcr_digests(job, device, &mut ast, session_hash_alg, &banks)?;

            let (commands, final_digest) =
                ast.to_command_list(session_hash_alg, &policy_context)?;

            Ok((final_digest, Some(commands)))
        } else {
            Ok((Tpm2bDigest::default(), None))
        }
    }

    fn create_object(&self, job: &mut Session, device: &mut Device) -> Result<(), CommandError> {
        let parent_handle = job.load_context(device, &self.parent)?;

        let (object_attributes, user_auth) = self.creation_args.parse(&self.algorithm)?;
        let sensitive_data = self.get_sensitive_data()?;

        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data,
        };

        let (auth_policy_digest, policy_commands) = self.resolve_policy(job, device)?;

        let tpm_key = {
            let public_template =
                template::build_public(template.alg_desc, auth_policy_digest, object_attributes);

            let create_cmd = TpmCreateCommand {
                parent_handle: parent_handle.0.into(),
                in_sensitive: Tpm2bSensitiveCreate {
                    inner: TpmsSensitiveCreate {
                        user_auth,
                        data: template.sensitive_data,
                    },
                },
                in_public: Tpm2bPublic {
                    inner: public_template,
                },
                outside_info: Tpm2bData::default(),
                creation_pcr: TpmlPcrSelection::default(),
            };

            let handles = [parent_handle.0];
            let (resp, _) = job
                .execute(device, &create_cmd, &handles, &self.auth_args.auths())
                .map_err(|e| {
                    if let SessionError::Device(DeviceError::TpmRc(rc)) = &e {
                        if rc.base() == TpmRcBase::Type {
                            if let Ok(key) = job.cache.find_by_phandle(device, parent_handle.0) {
                                return CommandError::InvalidParentHandle(
                                    "vtpm:",
                                    key.context.saved_handle.0,
                                );
                            }
                            return CommandError::InvalidParentHandle("tpm:", parent_handle.0);
                        }
                    }
                    e.into()
                })?;

            let create_resp = resp
                .Create()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

            let (parent_public_data, _) = device.read_public(parent_handle)?;
            let parent_public_2b = Tpm2bPublic {
                inner: parent_public_data,
            };

            let empty_auth_flag = user_auth.is_empty();

            TpmKey {
                public: create_resp.out_public,
                private: create_resp.out_private,
                parent_handle,
                parent_public: Some(parent_public_2b),
                key_type: template.alg_desc.object_type,
                empty_auth: empty_auth_flag.then_some(true),
                policy: policy_commands,
            }
        };

        write_key_data(
            &mut job.writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}
