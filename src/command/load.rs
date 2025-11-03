//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError, InputArgs},
    device::{with_device, Device},
    io::read_file_input,
    key::KeyError,
    pcr::pcr_get_bank_list,
    policy::visit_secret_handles,
    session::Session,
};
use clap::Args;
use std::collections::{HashMap, HashSet};
use tpm2_policy_language::{Auth, Expression, Handle, HandleClass, PolicyState};
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPublic, TpmCc},
    frame::TpmLoadCommand,
    TpmHandle,
};
use tpm2_tpmkey::{TpmKey, TpmKeyAsn1, TpmPolicyCommand};

/// Loads a PEM or DER TPMKey file to cache.
#[derive(Args, Debug)]
#[command(verbatim_doc_comment)]
pub struct Load {
    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,
}

impl Job for Load {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| -> Result<(), CommandError> {
            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            if input_bytes.is_empty() {
                return Ok(());
            }

            let banks = pcr_get_bank_list(device)?;
            let pcr_count = banks.iter().map(|b| b.count).max().unwrap_or(0);
            let pcr_banks: Vec<tpm2_protocol::data::TpmAlgId> =
                banks.iter().map(|b| b.alg).collect();

            let pcr_policy_state = PolicyState {
                pcr_count,
                pcr_banks,
                names: HashMap::new(),
            };

            let asn1_key = Self::parse_key_asn1(&input_bytes)?;

            let names_map = Self::build_names_map(&asn1_key, device)?;

            let complete_policy_state = PolicyState {
                names: names_map,
                ..pcr_policy_state
            };

            let tpm_key = TpmKey::from_pem(&input_bytes, &complete_policy_state).or_else(|_| {
                TpmKey::from_der(&input_bytes, &complete_policy_state).map_err(KeyError::from)
            })?;

            let parent_public = tpm_key
                .parent_public()
                .cloned()
                .ok_or(CommandError::InvalidInput("parent missing".to_string()))?;

            let parent_handle = Self::fetch_parent(job, device, &parent_public)?;

            let (object_handle, _, loaded_public) = Self::run_load(
                job,
                device,
                parent_handle,
                tpm_key.private(),
                tpm_key.public(),
                self.auth_args.auths().as_ref(),
            )?;

            let vhandle = job.cache.save_context(
                device,
                object_handle,
                &loaded_public,
                &parent_public,
                &tpm_key.policy,
            )?;
            writeln!(job.writer, "vtpm:{vhandle:08x}")?;
            Ok(())
        })
    }
}

impl Load {
    /// Parses the raw bytes (PEM or DER) into the ASN.1 struct without
    /// full policy validation.
    fn parse_key_asn1(bytes: &[u8]) -> Result<TpmKeyAsn1, KeyError> {
        TpmKeyAsn1::from_pem(bytes).or_else(|_| TpmKeyAsn1::from_der(bytes).map_err(Into::into))
    }

    /// Reconstructs the policy AST from the ASN.1 struct and extracts all
    /// handle names required by `secret()` commands.
    fn build_names_map(
        asn1_key: &TpmKeyAsn1,
        device: &mut Device,
    ) -> Result<HashMap<u32, Tpm2bName>, CommandError> {
        let temp_expr = match (asn1_key.auth_policy.as_ref(), asn1_key.policy.as_ref()) {
            (Some(auth_policies), _) if !auth_policies.is_empty() => {
                let branches: Result<Vec<_>, _> = auth_policies
                    .iter()
                    .map(|p| TpmPolicyCommand::to_expression(p.policy.clone()))
                    .collect();
                Some(Expression::Or(branches.map_err(KeyError::from)?))
            }
            (_, Some(policy_commands)) => Some(
                TpmPolicyCommand::to_expression(policy_commands.clone()).map_err(KeyError::from)?,
            ),
            _ => None,
        };

        let mut names = HashMap::new();
        if let Some(ast) = temp_expr {
            let mut handles = HashSet::new();
            visit_secret_handles(&ast, &mut handles)?;
            for &handle in &handles {
                let (_, name) = device.read_public(handle.into())?;
                names.insert(handle, name);
            }
        }
        Ok(names)
    }

    fn fetch_parent(
        job: &mut Session,
        device: &mut Device,
        parent_public: &Tpm2bPublic,
    ) -> Result<TpmHandle, CommandError> {
        if let Some((phandle, _)) = device.find_persistent(&parent_public.inner)? {
            return Ok(phandle);
        }

        let vhandle_opt = job
            .cache
            .key_iter()
            .find(|(_, key)| key.public == *parent_public)
            .map(|(vhandle, _)| *vhandle);

        if let Some(vhandle) = vhandle_opt {
            return Ok(job.load_context(device, &Handle::new(HandleClass::Vtpm, vhandle))?);
        }

        Err(CommandError::UnknownParent)
    }

    fn run_load(
        job: &mut Session,
        device: &mut Device,
        parent_handle: TpmHandle,
        in_private: &tpm2_protocol::data::Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        auths: &[Auth],
    ) -> Result<(TpmHandle, Tpm2bName, Tpm2bPublic), CommandError> {
        let cmd = TpmLoadCommand {
            parent_handle,
            in_private: *in_private,
            in_public: in_public.clone(),
        };
        let handles = [parent_handle.0];

        let (resp, _) = job.execute(device, &cmd, &handles, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Load))?;

        job.cache.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, in_public.clone()))
    }
}
