// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::CommandError,
    device::{with_device, Device},
    job::Job,
    pcr::{
        pcr_composite_digest, pcr_get_bank_list, pcr_read, pcr_selection_vec_from_str,
        pcr_selection_vec_to_tpml, Pcr,
    },
    policy::{
        execute_policy, parse, Expression, PolicyError, SoftwarePolicySession, TpmPolicySession,
    },
    session::Session,
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
    device: &mut Device,
    ast: &mut Expression,
    session_hash_alg: TpmAlgId,
) -> Result<(), CommandError> {
    let mut required_selections = HashSet::new();
    try_visit_pcr_expressions_mut(ast, &mut |expr| {
        if let Expression::Pcr {
            selection,
            digest: None,
            ..
        } = expr
        {
            required_selections.insert(selection.clone());
        }
        Ok(())
    })?;

    if !required_selections.is_empty() {
        let banks = pcr_get_bank_list(device)?;
        let selections_str = required_selections
            .into_iter()
            .collect::<Vec<_>>()
            .join("+");
        let selections = pcr_selection_vec_from_str(&selections_str)?;
        let tpml_selection = pcr_selection_vec_to_tpml(&selections, &banks)?;
        let (pcr_values, _) = pcr_read(device, &tpml_selection)?;

        let mut populator = |expr: &mut Expression| -> Result<(), CommandError> {
            if let Expression::Pcr {
                selection, digest, ..
            } = expr
            {
                if digest.is_none() {
                    let selections_for_node = pcr_selection_vec_from_str(selection)?;
                    let pcr_subset: Vec<Pcr> = pcr_values
                        .iter()
                        .filter(|pcr| {
                            selections_for_node
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
        Expression::Pcr {
            selection: _,
            digest: _,
            count: _,
        } => visitor(ast)?,
        Expression::Or(branches) => {
            for branch in branches.iter_mut() {
                try_visit_pcr_expressions_mut(branch, visitor)?;
            }
        }
        Expression::Secret { auth_handle, .. } => {
            try_visit_pcr_expressions_mut(auth_handle, visitor)?;
        }
        Expression::Auth(_) | Expression::Uri(_) => {}
    }
    Ok(())
}

impl SubCommand for Policy {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let mut ast = parse(&self.expression)?;
            match ast {
                Expression::Auth(_) | Expression::Uri(_) => {
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
                    writeln!(job.key_cache.writer, "{ast}")?;
                }
                PolicyMode::Software => {
                    let mut session = SoftwarePolicySession::new(session_hash_alg, device)?;
                    let final_digest = execute_policy(&ast, &mut session)?;
                    writeln!(job.key_cache.writer, "{}", hex::encode(&*final_digest))?;
                }
                PolicyMode::Tpm => {
                    let session_handle =
                        start_trial_session(device, TpmSe::Trial, session_hash_alg)?;
                    let final_digest = {
                        let mut session =
                            TpmPolicySession::new(device, session_handle, session_hash_alg);
                        execute_policy(&ast, &mut session)?
                    };
                    device.flush_context(session_handle.0)?;
                    writeln!(job.key_cache.writer, "{}", hex::encode(&*final_digest))?;
                }
                PolicyMode::Session => {
                    let (resp, nonce_caller) = device.start_session(
                        TpmSe::Policy,
                        session_hash_alg,
                        (TpmRh::Null as u32).into(),
                    )?;
                    let live_handle = resp.session_handle;

                    let mut tpm_policy_session =
                        TpmPolicySession::new(device, live_handle, session_hash_alg);
                    execute_policy(&ast, &mut tpm_policy_session)?;

                    let mut session_data =
                        Session::new(TpmSe::Policy, session_hash_alg, nonce_caller, &resp, &[])?;
                    session_data.context = device.save_context(live_handle.0)?;
                    session_data.handle = tpm2_protocol::TpmHandle(0);

                    let vhandle = job.session_cache.add(session_data);
                    job.session_cache.save()?;

                    writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
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
    device: &mut Device,
    session_type: tpm2_protocol::data::TpmSe,
    hash_alg: TpmAlgId,
) -> Result<TpmHandle, PolicyError> {
    let (resp, _) = device.start_session(session_type, hash_alg, (TpmRh::Null as u32).into())?;
    Ok(resp.session_handle)
}
