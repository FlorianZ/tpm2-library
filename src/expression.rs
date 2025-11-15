// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    build_and_branch, Auth, Error, Handle, HandleClass, HandleError, LanguageError,
    TpmPolicySession, TpmPolicyState,
};
use std::borrow::Cow;
use std::fmt;
use tpm2_crypto::Hash;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmHt, TpmRh, TpmaSession,
        TpmlDigest, TpmlPcrSelection, TpmsAuthCommand,
    },
    frame::{
        TpmAuthCommands, TpmCommand, TpmFrame, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
};

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, Eq, Clone)]
pub enum TpmPolicyExpression {
    Auth(Auth),
    Pcr {
        selections: TpmlPcrSelection,
        digest: Option<Tpm2bDigest>,
    },
    Secret {
        auth_handle: Box<TpmPolicyExpression>,
        password: Option<Box<TpmPolicyExpression>>,
    },
    And(Vec<TpmPolicyExpression>),
    Or(Vec<TpmPolicyExpression>),
    Handle(Handle),
}

/// Compares two password expressions semantically, treating `None` as equal to
/// an empty password.
fn compare_passwords(
    left: Option<&TpmPolicyExpression>,
    right: Option<&TpmPolicyExpression>,
) -> bool {
    /// Maps an expression to a comparable password slice.
    ///
    /// - `None` (no arg) is treated as `Some(&[])` (empty password).
    /// - `Some(Password(p))` is treated as `Some(p)`.
    /// - Anything else is `None` (not a comparable password).
    fn get_pw_slice(expr_opt: Option<&TpmPolicyExpression>) -> Option<&[u8]> {
        match expr_opt {
            None => Some(&[] as &[u8]),
            Some(expr) => match expr {
                TpmPolicyExpression::Auth(Auth::Password(p)) => Some(p.as_slice()),
                _ => None,
            },
        }
    }

    match (get_pw_slice(left), get_pw_slice(right)) {
        (Some(l_bytes), Some(r_bytes)) => l_bytes == r_bytes,
        _ => false,
    }
}

impl PartialEq for TpmPolicyExpression {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Secret {
                    auth_handle: l_ah,
                    password: l_pw,
                },
                Self::Secret {
                    auth_handle: r_ah,
                    password: r_pw,
                },
            ) => {
                l_ah == r_ah
                    && compare_passwords(l_pw.as_ref().map(|b| &**b), r_pw.as_ref().map(|b| &**b))
            }
            (Self::Auth(l), Self::Auth(r)) => l == r,
            (
                Self::Pcr {
                    selections: l_s,
                    digest: l_d,
                },
                Self::Pcr {
                    selections: r_s,
                    digest: r_d,
                },
            ) => l_s == r_s && l_d == r_d,
            (Self::And(l), Self::And(r)) | (Self::Or(l), Self::Or(r)) => l == r,
            (Self::Handle(l), Self::Handle(r)) => l == r,
            _ => false,
        }
    }
}

impl fmt::Display for TpmPolicyExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmPolicyExpression::Auth(auth) => write!(f, "{auth}"),
            TpmPolicyExpression::Pcr { selections, digest } => {
                let selection_strings: Vec<String> = selections
                    .iter()
                    .map(|tpms| {
                        let alg_str = Hash::from(tpms.hash).to_string();
                        let mut indices = Vec::new();
                        for (byte_index, &byte) in tpms.pcr_select.iter().enumerate() {
                            for bit_index in 0..8 {
                                if (byte & (1 << bit_index)) != 0 {
                                    #[allow(clippy::cast_possible_truncation)]
                                    let pcr_index = (byte_index * 8 + bit_index) as u32;
                                    indices.push(pcr_index.to_string());
                                }
                            }
                        }
                        format!("{}:{}", alg_str, indices.join(","))
                    })
                    .collect();

                write!(f, "pcr({})", selection_strings.join("+"))?;

                if let Some(d) = digest {
                    write!(f, ":{}", hex::encode(d.as_ref()))?;
                }
                write!(f, ")")
            }
            TpmPolicyExpression::Secret {
                auth_handle,
                password,
            } => {
                write!(f, "secret({auth_handle}")?;
                if let Some(p) = password {
                    if !matches!(&**p, TpmPolicyExpression::Auth(Auth::Password(pw)) if pw.is_empty())
                    {
                        write!(f, ", {p}")?;
                    }
                }
                write!(f, ")")
            }
            TpmPolicyExpression::And(expressions) => {
                let s: Vec<String> = expressions.iter().map(ToString::to_string).collect();
                write!(f, "({})", s.join(" and "))
            }
            TpmPolicyExpression::Or(expressions) => {
                let s: Vec<String> = expressions.iter().map(ToString::to_string).collect();
                write!(f, "({})", s.join(" or "))
            }
            TpmPolicyExpression::Handle(handle) => write!(f, "{handle}"),
        }
    }
}

impl TpmPolicyExpression {
    /// Parses a policy expression string into an
    /// [`Expression`](crate::Expression) AST.
    ///
    /// # Errors
    ///
    /// Returns a [`Error`] variant if parsing fails due to syntactic errors,
    /// malformed literals (handles, auth strings, PCR selections), or other
    /// structural problems in the input string.
    pub fn new(input: &str, context: &TpmPolicyState) -> Result<TpmPolicyExpression, Error> {
        let tokens = crate::tokenize(input);
        let mut iter = tokens.iter().peekable();
        let expr = crate::parse_expression(&mut iter, context)?;

        if iter.peek().is_none() {
            Ok(expr)
        } else {
            Err(LanguageError::TrailingData.into())
        }
    }

    /// Reconstructs a policy AST from a list of serialized TPM policy
    /// commands.
    ///
    /// This function performs the inverse of [`to_command_list`]. It parses a
    /// sequence of command blobs and rebuilds the logical `Expression` tree
    /// that represents the policy.
    ///
    /// This is useful for analyzing or replaying policy command streams
    /// generated by other tools.
    ///
    /// # Errors
    ///
    /// Returns a [`Error`] variant if any command blob is malformed, an
    /// unexpected command is found, or if the sequence of commands is
    /// logically inconsistent (e.g., mismatched policy branches).
    pub fn from_command_list(
        command_list: &[(TpmCommand, TpmAuthCommands)],
    ) -> Result<TpmPolicyExpression, Error> {
        let mut stack: Vec<Vec<TpmPolicyExpression>> = vec![vec![]];

        for (command_body, auth_sessions) in command_list {
            let current_branch = stack.last_mut().ok_or(LanguageError::OperationFailed)?;

            match command_body {
                TpmCommand::PolicyRestart(_) => {
                    stack.push(vec![]);
                }
                TpmCommand::PolicyPcr(cmd) => {
                    let selections = cmd.pcrs;
                    let digest = Some(cmd.pcr_digest);
                    let expr = TpmPolicyExpression::Pcr { selections, digest };
                    current_branch.push(expr);
                }
                TpmCommand::PolicySecret(cmd) => {
                    let auth_handle = Box::new(TpmPolicyExpression::Handle(Handle::new(
                        HandleClass::Tpm,
                        cmd.auth_handle.into(),
                    )));

                    let password = auth_sessions.iter().find_map(|auth| {
                        if auth.session_handle.0 == TpmRh::Pw as u32 {
                            Some(Box::new(TpmPolicyExpression::Auth(Auth::Password(
                                auth.hmac.as_ref().to_vec(),
                            ))))
                        } else {
                            None
                        }
                    });

                    let expr = TpmPolicyExpression::Secret {
                        auth_handle,
                        password,
                    };
                    current_branch.push(expr);
                }
                TpmCommand::PolicyOr(cmd) => {
                    let num_branches = cmd.p_hash_list.iter().len();
                    if stack.len() < num_branches {
                        return Err(LanguageError::OperationFailed.into());
                    }

                    let mut branches = Vec::with_capacity(num_branches);
                    for _ in 0..num_branches {
                        if let Some(branch_vec) = stack.pop() {
                            branches.push(build_and_branch(branch_vec));
                        } else {
                            return Err(LanguageError::OperationFailed.into());
                        }
                    }

                    branches.reverse();
                    let expr = TpmPolicyExpression::Or(branches);

                    if let Some(branch_to_push_to) = stack.last_mut() {
                        branch_to_push_to.push(expr);
                    } else {
                        return Err(LanguageError::OperationFailed.into());
                    }
                }
                _ => return Err(LanguageError::InvalidCc(command_body.cc()).into()),
            }
        }

        if stack.len() != 1 {
            return Err(LanguageError::OperationFailed.into());
        }

        if let Some(final_branch) = stack.pop() {
            Ok(build_and_branch(final_branch))
        } else {
            Err(LanguageError::OperationFailed.into())
        }
    }

    /// Converts a parsed policy AST into a list of serialized TPM policy
    /// commands.
    ///
    /// This function performs an iterative, stack-based traversal of the
    /// `Expression` tree and generates a `Vec<Vec<u8>>`. Each inner `Vec<u8>`
    /// is a complete, serialized TPM command, including the header, tag, body,
    /// and auth area.
    ///
    /// Commands that require authorization, like `PolicySecret`, have their
    /// authorization (e.g., password) serialized directly into the auth area
    /// of the command blob.
    ///
    /// # Errors
    ///
    /// Returns a [`Error`] variant if the expression tree is invalid for
    /// command generation (e.g., containing a standalone `Auth` node), if
    /// required context from `PolicyState` is missing (e.g., a handle name),
    /// or if any part of the TPM command construction fails.
    pub fn to_command_list(
        &self,
        session_hash_alg: TpmAlgId,
        context: &TpmPolicyState,
    ) -> Result<(Vec<(TpmCommand, TpmAuthCommands)>, Tpm2bDigest), Error> {
        let mut command_list: Vec<(TpmCommand, TpmAuthCommands)> = Vec::new();
        let mut software_session = TpmPolicySession::new(session_hash_alg)?;

        let final_digest =
            self.to_command_list_walk(&mut command_list, &mut software_session, context)?;
        Ok((command_list, final_digest))
    }

    fn to_command_list_walk<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommand, TpmAuthCommands)>,
        software_session: &mut TpmPolicySession,
        context: &'a TpmPolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        match self {
            TpmPolicyExpression::And(branches) => {
                for branch in branches {
                    branch.to_command_list_walk(command_list, software_session, context)?;
                }
                Ok(software_session.get_digest())
            }
            expr @ TpmPolicyExpression::Or { .. } => {
                expr.to_command_list_walk_or(command_list, software_session, context)
            }
            expr @ TpmPolicyExpression::Pcr { .. } => {
                expr.to_command_list_walk_pcr(command_list, software_session)
            }
            expr @ TpmPolicyExpression::Secret { .. } => {
                expr.to_command_list_walk_secret(command_list, software_session, context)
            }
            expr @ (TpmPolicyExpression::Auth { .. } | TpmPolicyExpression::Handle { .. }) => {
                Err(LanguageError::InvalidExpression(Box::new(expr.clone())).into())
            }
        }
    }

    fn to_command_list_walk_pcr(
        &self,
        command_list: &mut Vec<(TpmCommand, TpmAuthCommands)>,
        software_session: &mut TpmPolicySession,
    ) -> Result<Tpm2bDigest, Error> {
        let (selections, digest) = match self {
            TpmPolicyExpression::Pcr { selections, digest } => (selections, digest),
            expr => return Err(LanguageError::InvalidExpression(Box::new(expr.clone())).into()),
        };

        let pcr_digest = digest.ok_or(LanguageError::PcrDigestMissing)?;

        if pcr_digest.as_ref().len() != software_session.digest_size {
            return Err(LanguageError::InvalidPcrDigest.into());
        }

        let cmd = TpmPolicyPcrCommand {
            policy_session: 0.into(),
            pcr_digest,
            pcrs: *selections,
        };

        command_list.push((TpmCommand::PolicyPcr(cmd), TpmAuthCommands::new()));
        software_session.policy_pcr(&cmd)?;

        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_secret<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommand, TpmAuthCommands)>,
        software_session: &mut TpmPolicySession,
        context: &'a TpmPolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        let (auth_handle, password) = match self {
            TpmPolicyExpression::Secret {
                auth_handle,
                password,
            } => (auth_handle, password),
            expr => return Err(LanguageError::InvalidExpression(Box::new(expr.clone())).into()),
        };

        let h_val = if let TpmPolicyExpression::Handle(handle) = &**auth_handle {
            handle.value().ok_or(HandleError::PatternDenied)?
        } else {
            return Err(LanguageError::InvalidExpression(Box::new((**auth_handle).clone())).into());
        };

        let ht_byte = (h_val >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| HandleError::InvalidType(ht_byte))?;

        let name = match ht {
            TpmHt::Persistent => Cow::Borrowed(
                context
                    .names
                    .get(&h_val)
                    .ok_or_else(|| LanguageError::InvalidExpression(Box::new(self.clone())))?,
            ),
            TpmHt::Permanent => {
                let rh = TpmRh::try_from(h_val).map_err(|_| HandleError::InvalidType(ht_byte))?;
                match rh {
                    TpmRh::Owner | TpmRh::Endorsement | TpmRh::Platform | TpmRh::Lockout => {
                        let handle_bytes = (rh as u32).to_be_bytes();
                        let name = Tpm2bName::try_from(handle_bytes.as_slice())
                            .map_err(|_| HandleError::InvalidType(ht_byte))?;
                        Cow::Owned(name)
                    }
                    _ => return Err(HandleError::InvalidType(ht_byte).into()),
                }
            }
            _ => return Err(HandleError::InvalidType(ht_byte).into()),
        };

        let cmd = TpmPolicySecretCommand {
            auth_handle: h_val.into(),
            policy_session: 0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };

        let password_bytes = if let Some(p) = password {
            match &**p {
                TpmPolicyExpression::Auth(Auth::Password(value)) => value.clone(),
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let auth_session = TpmsAuthCommand {
            session_handle: (TpmRh::Pw as u32).into(),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::empty(),
            hmac: Tpm2bAuth::try_from(password_bytes.as_slice())
                .map_err(|_| LanguageError::OperationFailed)?,
        };
        let mut auth_commands = TpmAuthCommands::new();
        auth_commands
            .push(auth_session)
            .map_err(|_| LanguageError::AuthListTooLong)?;

        command_list.push((TpmCommand::PolicySecret(cmd), auth_commands));
        software_session.policy_secret(name.as_ref())?;
        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_or<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommand, TpmAuthCommands)>,
        software_session: &mut TpmPolicySession,
        context: &'a TpmPolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        let branches = match self {
            TpmPolicyExpression::Or(branches) => branches,
            expr => return Err(LanguageError::InvalidExpression(Box::new(expr.clone())).into()),
        };

        let mut digest_list = TpmlDigest::new();
        for branch in branches {
            let restart_cmd = TpmPolicyRestartCommand {
                session_handle: 0.into(),
            };
            command_list.push((
                TpmCommand::PolicyRestart(restart_cmd),
                TpmAuthCommands::new(),
            ));
            software_session.policy_restart()?;

            let digest = branch.to_command_list_walk(command_list, software_session, context)?;

            digest_list
                .push(digest)
                .map_err(|_| LanguageError::TooManyBranches(Box::new(self.clone())))?;
        }

        let or_cmd = TpmPolicyOrCommand {
            policy_session: 0.into(),
            p_hash_list: digest_list,
        };
        command_list.push((TpmCommand::PolicyOr(or_cmd), TpmAuthCommands::new()));
        software_session.policy_or(&or_cmd)?;

        Ok(software_session.get_digest())
    }
}
