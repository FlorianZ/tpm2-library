// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
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
    uri::Uri,
};
use argh::FromArgs;
use std::{collections::HashSet, str::FromStr};
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
    Trial,
    Session,
}

/// Builds an authorization policy.
#[derive(FromArgs, Debug, Default)]
#[argh(
    subcommand,
    name = "policy",
    note = "A policy expression for the digest is defined with an expression language
e.g, 'sha256:0,...' or 'secret(\"tpm:...\")'."
)]
pub struct Policy {
    /// execution mode: 'resolve' (default), 'software', 'trial', or 'session'.
    #[argh(option, long = "mode", default = "Default::default()")]
    pub mode: PolicyMode,

    /// session to be updated with policy commands
    #[argh(option)]
    pub auth: Option<String>,

    /// policy expression
    #[argh(positional)]
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
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let mut ast = parse(&self.expression)?;
            let session_hash_alg = TpmAlgId::Sha256;

            resolve_pcr_digests(device, &mut ast, session_hash_alg)?;

            if let Some(session_uri_str) = &self.auth {
                let session_uri = Uri::from_str(session_uri_str)?;

                let Uri::Session(session_handle) = session_uri else {
                    return Err(CommandError::InvalidInput(
                        "Session must be a session: URI".to_string(),
                    ));
                };

                job.session_cache
                    .prepare_sessions(device, &[Auth::Session(session_handle)])?;

                let live_handle = job
                    .session_cache
                    .get(&Uri::Session(session_handle).to_string())?
                    .handle;

                let mut session = TpmPolicySession::new(device, live_handle, session_hash_alg);
                execute_policy(&ast, &mut session)?;

                let new_context = device.save_context(live_handle.0)?;
                let update_session = job.session_cache.get_mut(session_uri_str)?;
                update_session.context = new_context;
                update_session.handle = tpm2_protocol::TpmHandle(0);
            } else {
                match self.mode {
                    PolicyMode::Resolve => {
                        writeln!(job.context_cache.writer, "{ast}")?;
                    }
                    PolicyMode::Software => {
                        let mut session = SoftwarePolicySession::new(session_hash_alg, device)?;
                        let final_digest = execute_policy(&ast, &mut session)?;
                        writeln!(job.context_cache.writer, "{}", hex::encode(&*final_digest))?;
                    }
                    PolicyMode::Trial => {
                        let session_handle =
                            start_trial_session(device, TpmSe::Trial, session_hash_alg)?;
                        let final_digest = {
                            let mut session =
                                TpmPolicySession::new(device, session_handle, session_hash_alg);
                            execute_policy(&ast, &mut session)?
                        };
                        device.flush_context(session_handle.0)?;
                        writeln!(job.context_cache.writer, "{}", hex::encode(&*final_digest))?;
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

                        let mut session_data = Session::new(
                            TpmSe::Policy,
                            session_hash_alg,
                            nonce_caller,
                            &resp,
                            &[],
                        )?;
                        session_data.context = device.save_context(live_handle.0)?;
                        session_data.handle = tpm2_protocol::TpmHandle(0);

                        let saved_uri = job.session_cache.add(session_data);
                        job.session_cache.save()?;

                        writeln!(job.context_cache.writer, "{saved_uri}")?;
                    }
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
