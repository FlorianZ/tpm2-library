// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, resolve_sensitive_data},
        AuthArgs, CommandError, CreationArgs, HierarchyArgs,
    },
    task::TaskState,
};
use clap::Args;
use std::path::PathBuf;
use tpm2_crypto::{tpm_make_name, TpmPublicTemplate};
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::{TpmUint16, TpmUint32},
    data::{
        Tpm2bData, Tpm2bName, Tpm2bPublic, Tpm2bSensitiveCreate, TpmAlgId, TpmCc, TpmRh,
        TpmlPcrSelection, TpmsSensitiveCreate, TpmtSymDefObject, TpmuSymKeyBits, TpmuSymMode,
    },
    frame::{TpmCommand, TpmCreatePrimaryCommand},
};
use tpm2_vtpm::{vtpm_policy_command_from, VtpmPolicyCommand};

/// Creates a new primary key in a specified hierarchy.
#[derive(Args, Debug, Clone)]
pub struct CreatePrimary {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyArgs,

    /// Key algorithm
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
    pub creation_args: CreationArgs,
}

impl Task for CreatePrimary {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let primary_handle: TpmRh = self.hierarchy_args.hierarchy.into();

            let user_auth = self.creation_args.parse_password()?;
            let object_attributes = self.creation_args.parse_attributes(&self.algorithm)?;
            let sensitive_data = resolve_sensitive_data(
                self.data.as_deref(),
                self.input.as_deref(),
                self.algorithm.object_type(),
            )?;

            let (auth_policy_digest, policy_commands) = build_policy_command_list(
                &self.creation_args,
                task_state,
                device,
                self.algorithm.name_alg(),
            )?;

            let symmetric = TpmtSymDefObject {
                algorithm: TpmAlgId::Aes,
                key_bits: TpmuSymKeyBits::Aes(TpmUint16::from(128)),
                mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
            };

            let template = self
                .algorithm
                .clone()
                .with_object_attributes(object_attributes)
                .with_auth_policy(auth_policy_digest)
                .with_symmetric(symmetric);

            let cmd = TpmCreatePrimaryCommand {
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
                handles: [(primary_handle as u32).into()],
            };

            let auth_map = self.auth_args.build_auth_map();
            let auth = auth_map
                .get(&TpmUint32(primary_handle as u32))
                .cloned()
                .unwrap_or_default();

            let (resp, _) = task_state.execute(device, &cmd, &[auth])?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.handles[0];
            task_state.track(device, object_handle)?;
            let object_context = device.save_context(object_handle)?;

            let policy_blob = if let Some(cmds) = policy_commands {
                let mut blob: Vec<Box<dyn VtpmPolicyCommand>> = Vec::new();
                for (cmd, _) in cmds {
                    let name = if let TpmCommand::PolicySecret(inner) = &cmd {
                        if let Some(key) = task_state.cache.find_by_handle(inner.handles[0]) {
                            tpm_make_name(key.public())?
                        } else {
                            let (_, name) = device.read_public(inner.handles[0])?;
                            name
                        }
                    } else {
                        Tpm2bName::default()
                    };
                    blob.push(vtpm_policy_command_from(&cmd, &name)?);
                }
                Some(blob)
            } else {
                None
            };

            let vhandle = task_state.cache.save_transient(
                object_context,
                &resp.out_public.inner,
                &Tpm2bPublic::default().inner,
                &policy_blob,
            )?;
            writeln!(writer, "{vhandle:08x}")?;
            Ok(())
        })
    }
}
