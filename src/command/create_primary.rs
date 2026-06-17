// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Hierarchy, Task},
    command::common::{
        build_policy_command_list, parse_creation_attributes, parse_password,
        resolve_public_template,
    },
    error::device_err,
    response::parse_response,
    task::TaskState,
};
use anyhow::Result;
use argh::FromArgs;
use tpm2_crypto::TpmPublicTemplate;
use tpm2_device::{TpmDevice, with_device};
use tpm2_protocol::{
    basic::TpmUint32,
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmRh, TpmlPcrSelection,
        TpmsSensitiveCreate,
    },
    frame::{
        TpmAuthCommands, TpmCommandValue as TpmCommand, TpmCreatePrimaryCommand,
        TpmCreatePrimaryResponse,
    },
};

/// Creates a new primary key in a specified hierarchy.
#[derive(FromArgs, Debug, Clone)]
#[argh(
    subcommand,
    name = "create-primary",
    description = "Creates a new primary key in a specified hierarchy.",
    help_triggers("-h", "--help", "help")
)]
pub struct CreatePrimary {
    /// hierarchy for the primary key
    #[argh(option, short = 'H', default = "Hierarchy::Owner")]
    pub hierarchy: Hierarchy,

    /// key algorithm
    #[argh(positional)]
    pub algorithm: TpmPublicTemplate,

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

impl Task for CreatePrimary {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        with_device(task_state.device.clone(), |device| {
            self.execute_command(task_state, writer, device)
        })
    }
}

impl CreatePrimary {
    /// Builds the TPM2_CreatePrimary command.
    ///
    /// # Errors
    ///
    /// Returns an error if argument parsing or policy resolution fails.
    fn build_command(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
    ) -> Result<(TpmCreatePrimaryCommand, Vec<(TpmCommand, TpmAuthCommands)>)> {
        let primary_handle: TpmRh = self.hierarchy.into();

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

        let cmd = TpmCreatePrimaryCommand {
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth,
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic { inner: public_area },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
            handles: [(primary_handle as u32).into()],
        };

        Ok((cmd, policy_commands))
    }

    fn execute_command(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        device: &mut TpmDevice,
    ) -> Result<()> {
        let (cmd, policy_commands) = self.build_command(task_state, device)?;
        let primary_handle: TpmRh = self.hierarchy.into();

        let auth = task_state.auth_for(TpmUint32::new(primary_handle as u32));

        let resp = task_state.execute(device, &cmd, &[auth])?;
        let resp = parse_response::<TpmCreatePrimaryResponse>(resp)?;

        let object_handle = resp.handles[0];
        task_state.track(device, object_handle)?;
        let object_context = device.save_context(object_handle).map_err(device_err)?;

        let policy_blob = task_state.save_vtpm_policy(device, policy_commands)?;

        let vhandle = task_state.cache.save_transient(
            object_context,
            &resp.out_public.inner,
            &Tpm2bPublic::default().inner,
            &Some(policy_blob),
        )?;
        writeln!(writer, "{vhandle:08x}")?;
        Ok(())
    }
}
