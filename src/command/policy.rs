// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::CommandError,
    device::with_device,
    job::Job,
    pcr::{pcr_composite_digest, pcr_get_bank_list, pcr_read},
    policy::{
        execute_policy, parse, Expression, PolicyError, SoftwarePolicySession, TpmPolicySession,
    },
    vtpm::VtpmSession,
};
use clap::Args;
use std::collections::HashSet;
use strum::{Display, EnumString};
use tpm2_protocol::{
    data::{TpmAlgId, TpmRh, TpmSe},
    TpmHandle,
};

/// The execution mode for a policy command.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum PolicyMode {
    #[default]
    Resolve,
    Software,
    Tpm,
    Session,
}

/// Builds an authorization policy.
#[derive(Args, Debug, Default)]
#[command()]
pub struct Policy {
    /// Execution mode: 'resolve' (default), 'software', 'tpm', or 'session'.
    #[arg(short = 'm', long = "mode", default_value_t = PolicyMode::default(), value_parser = clap::value_parser!(PolicyMode))]
    pub mode: PolicyMode,

    /// Policy expression
    pub expression: String,
}

/// Populates the AST with PCR digests by reading current values from the TPM.
fn resolve_pcr_digests(
    device: &mut crate::device::Device,
    ast: &mut Expression,
    session_hash_alg: TpmAlgId,
) -> Result<(), CommandError> {
    let mut required_selections = HashSet::new();
    try_visit_pcr_expressions_mut(ast, &mut |expr| {
        if let Expression::Pcr {
            selections,
            digest: None,
            ..
        } = expr
        {
            for s in selections {
                required_selections.insert(s.clone());
            }
        }
        Ok(())
    })?;

    if !required_selections.is_empty() {
        let banks = pcr_get_bank_list(device)?;
        let selections: Vec<_> = required_selections.into_iter().collect();
        let tpml_selection = crate::pcr::pcr_selection_vec_to_tpml(&selections, &banks)?;
        let (pcr_values, _) = pcr_read(device, &tpml_selection)?;

        let mut populator = |expr: &mut Expression| -> Result<(), CommandError> {
            if let Expression::Pcr {
                selections, digest, ..
            } = expr
            {
                if digest.is_none() {
                    let pcr_subset: Vec<crate::pcr::Pcr> = pcr_values
                        .iter()
                        .filter(|pcr| {
                            selections
                                .iter()
                                .any(|sel| sel.alg == pcr.bank && sel.indices.contains(&pcr.index))
                        })
                        .cloned()
                        .collect();

                    let composite_digest = pcr_composite_digest(&pcr_subset, session_hash_alg)?;
                    *digest = Some(hex::encode(composite_digest));
                }
            }
            Ok(())
        };
        try_visit_pcr_expressions_mut(ast, &mut populator)?;
    }
    Ok(())
}

/// Traverses the AST, applying a fallible visitor closure to each `Pcr` expression.
fn try_visit_pcr_expressions_mut<F>(
    ast: &mut Expression,
    visitor: &mut F,
) -> Result<(), CommandError>
where
    F: FnMut(&mut Expression) -> Result<(), CommandError>,
{
    match ast {
        Expression::Pcr { .. } => visitor(ast)?,
        Expression::And(branches) | Expression::Or(branches) => {
            for branch in branches.iter_mut() {
                try_visit_pcr_expressions_mut(branch, visitor)?;
            }
        }
        Expression::Secret { auth_handle, .. } => {
            try_visit_pcr_expressions_mut(auth_handle, visitor)?;
        }
        Expression::Auth(_) | Expression::Handle(_) | Expression::Path(_) => {}
    }
    Ok(())
}

impl SubCommand for Policy {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let mut ast = parse(&self.expression)?;
            match ast {
                Expression::Auth(_) | Expression::Handle(_) | Expression::Path(_) => {
                    return Err(CommandError::InvalidInput(
                        "not a valid policy expression".to_string(),
                    ));
                }
                _ => {}
            }
            let session_hash_alg = TpmAlgId::Sha256;

            resolve_pcr_digests(device, &mut ast, session_hash_alg)?;

            match self.mode {
                PolicyMode::Resolve => {
                    writeln!(job.writer, "{ast}")?;
                }
                PolicyMode::Software => {
                    let mut session = SoftwarePolicySession::new(session_hash_alg, device)?;
                    let final_digest = execute_policy(&ast, &mut session)?;
                    writeln!(job.writer, "{}", hex::encode(&*final_digest))?;
                }
                PolicyMode::Tpm => {
                    let session_handle =
                        start_trial_session(device, TpmSe::Trial, session_hash_alg)?;
                    let final_digest = {
                        let mut session =
                            TpmPolicySession::new(device, session_handle, session_hash_alg);
                        execute_policy(&ast, &mut session)?
                    };
                    device.flush_context(session_handle)?;
                    writeln!(job.writer, "{}", hex::encode(&*final_digest))?;
                }
                PolicyMode::Session => {
                    let (resp, nonce_caller) = device.start_session(
                        TpmSe::Policy,
                        session_hash_alg,
                        (TpmRh::Null as u32).into(),
                    )?;
                    let mut tpm_policy_session =
                        TpmPolicySession::new(device, resp.session_handle, session_hash_alg);
                    execute_policy(&ast, &mut tpm_policy_session)?;
                    let mut session_data =
                        VtpmSession::new(session_hash_alg, nonce_caller, &resp, &[])?;
                    session_data.context = device.save_context(resp.session_handle.0)?;
                    let vhandle = job.cache.add_session(session_data);
                    job.cache.save()?;
                    writeln!(job.writer, "vtpm:{vhandle:08x}")?;
                }
            }
            Ok(())
        })
    }
}

/// Starts a trial session.
///
/// # Errors
///
/// Returns `PolicyError` on failure.
pub fn start_trial_session(
    device: &mut crate::device::Device,
    session_type: tpm2_protocol::data::TpmSe,
    hash_alg: TpmAlgId,
) -> Result<TpmHandle, PolicyError> {
    let (resp, _) = device.start_session(session_type, hash_alg, (TpmRh::Null as u32).into())?;
    Ok(resp.session_handle)
}
