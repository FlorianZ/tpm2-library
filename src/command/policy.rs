// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::CommandError,
    context::ContextCache,
    device::{self, Auth, Device},
    pcr::{
        pcr_composite_digest, pcr_get_bank_list, pcr_read, pcr_selection_vec_from_str,
        pcr_selection_vec_to_tpml, Pcr,
    },
    policy::{
        execute_policy, parse, Expression, PolicyError, SoftwarePolicySession, TpmPolicySession,
    },
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, collections::HashSet, rc::Rc, str::FromStr};
use strum::{Display, EnumString};
use tpm2_protocol::{data::TpmAlgId, TpmHandle};

/// The execution mode for a policy command.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum PolicyMode {
    #[default]
    Resolve,
    Software,
    Tpm,
}

/// Builds an authorization policy.
#[derive(FromArgs, Debug, Default)]
#[argh(
    subcommand,
    name = "policy",
    note = "A policy expression for the digest is defined with an expression language
e.g, 'sha256:0,...' or 'secret(\"tpm://...\")'."
)]
pub struct Policy {
    /// execution mode: 'resolve' (default), 'software', or 'tpm'.
    #[argh(option, long = "mode", default = "Default::default()")]
    pub mode: PolicyMode,

    /// session to be updated with policy commands
    #[argh(option)]
    pub auth: Option<String>,

    /// policy expression
    #[argh(positional)]
    pub expression: String,
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
        Expression::Secret {
            auth_handle_uri, ..
        } => {
            try_visit_pcr_expressions_mut(auth_handle_uri, visitor)?;
        }
        Expression::Uri(_) => {}
    }
    Ok(())
}

impl SubCommand for Policy {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        device::with_device(device, |device| {
            let mut ast = parse(&self.expression)?;
            let session_hash_alg = TpmAlgId::Sha256;

            let mut required_selections = HashSet::new();
            try_visit_pcr_expressions_mut(&mut ast, &mut |expr| {
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
                                    selections_for_node.iter().any(|sel| {
                                        sel.alg == pcr.bank && sel.indices.contains(&pcr.index)
                                    })
                                })
                                .cloned()
                                .collect();

                            let composite_digest =
                                pcr_composite_digest(&pcr_subset, session_hash_alg)?;
                            *digest = Some(hex::encode(composite_digest));
                        }
                    }
                    Ok(())
                };
                try_visit_pcr_expressions_mut(&mut ast, &mut populator)?;
            }

            if let Some(session_uri_str) = &self.auth {
                let session_uri = Uri::from_str(session_uri_str)?;

                let Uri::Session(session_handle) = session_uri else {
                    return Err(CommandError::InvalidInput(
                        "Session must be a session:// URI".to_string(),
                    ));
                };

                context
                    .session_map
                    .prepare_sessions(device, &[Auth::Tracked(session_handle)])?;

                let live_handle = context
                    .session_map
                    .get(&Uri::Session(session_handle).to_string())?
                    .handle;

                let mut session = TpmPolicySession::new(device, live_handle, session_hash_alg);
                execute_policy(&ast, &mut session)?;

                let new_context = device.save_context(live_handle.0)?;
                let session_to_update = context.session_map.get_mut(session_uri_str)?;
                session_to_update.context = new_context;
                session_to_update.handle = tpm2_protocol::TpmHandle(0);
            } else {
                match self.mode {
                    PolicyMode::Resolve => {
                        writeln!(context.writer, "{ast}")?;
                    }
                    PolicyMode::Software => {
                        let mut session = SoftwarePolicySession::new(session_hash_alg, device)?;
                        let final_digest = execute_policy(&ast, &mut session)?;
                        writeln!(context.writer, "{}", hex::encode(&*final_digest))?;
                    }
                    PolicyMode::Tpm => {
                        let session_handle = start_trial_session(
                            device,
                            tpm2_protocol::data::TpmSe::Trial,
                            session_hash_alg,
                        )?;
                        let final_digest = {
                            let mut session =
                                TpmPolicySession::new(device, session_handle, session_hash_alg);
                            execute_policy(&ast, &mut session)?
                        };
                        device.flush_context(session_handle.0)?;
                        writeln!(context.writer, "{}", hex::encode(&*final_digest))?;
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
    let (resp, _) = device.start_session(session_type, hash_alg)?;
    Ok(resp.session_handle)
}
