//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    build_and_branch, Auth, AuthError, CommandError, Error, ExpressionError, Handle, HandleClass,
    HandleError, PcrError, PolicyAlgId, PolicyState, SecretError, SoftwarePolicySession,
};
use std::fmt;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmAlgId, TpmHt, TpmRh, TpmaSession, TpmlDigest,
        TpmlPcrSelection, TpmsAuthCommand,
    },
    frame::{
        TpmAuthCommands, TpmCommandBody, TpmFrame, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmSized,
};

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, Eq, Clone)]
pub enum Expression {
    Auth(Auth),
    Pcr {
        selections: TpmlPcrSelection,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle: Box<Expression>,
        password: Option<Box<Expression>>,
        cp_hash: Option<String>,
    },
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Handle(Handle),
}

/// Compares two password expressions semantically, treating `None` as equal to
/// an empty password.
fn compare_passwords(left: Option<&Expression>, right: Option<&Expression>) -> bool {
    /// Maps an expression to a comparable password slice.
    ///
    /// - `None` (no arg) is treated as `Some(&[])` (empty password).
    /// - `Some(Password(p))` is treated as `Some(p)`.
    /// - Anything else is `None` (not a comparable password).
    fn get_pw_slice(expr_opt: Option<&Expression>) -> Option<&[u8]> {
        match expr_opt {
            None => Some(&[] as &[u8]),
            Some(expr) => match expr {
                Expression::Auth(Auth::Password(p)) => Some(p.as_slice()),
                _ => None,
            },
        }
    }

    match (get_pw_slice(left), get_pw_slice(right)) {
        (Some(l_bytes), Some(r_bytes)) => l_bytes == r_bytes,
        _ => false,
    }
}

impl PartialEq for Expression {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Secret {
                    auth_handle: l_ah,
                    password: l_pw,
                    cp_hash: l_cph,
                },
                Self::Secret {
                    auth_handle: r_ah,
                    password: r_pw,
                    cp_hash: r_cph,
                },
            ) => {
                l_ah == r_ah
                    && l_cph == r_cph
                    && compare_passwords(l_pw.as_ref().map(|b| &**b), r_pw.as_ref().map(|b| &**b))
            }
            (Self::Auth(l), Self::Auth(r)) => l == r,
            (
                Self::Pcr {
                    selections: l_s,
                    digest: l_d,
                    count: l_c,
                },
                Self::Pcr {
                    selections: r_s,
                    digest: r_d,
                    count: r_c,
                },
            ) => l_s == r_s && l_d == r_d && l_c == r_c,
            (Self::And(l), Self::And(r)) | (Self::Or(l), Self::Or(r)) => l == r,
            (Self::Handle(l), Self::Handle(r)) => l == r,
            _ => false,
        }
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Auth(auth) => write!(f, "{auth}"),
            Expression::Pcr {
                selections,
                digest,
                count,
            } => {
                let selection_strings: Vec<String> = selections
                    .iter()
                    .map(|tpms| {
                        let alg_str = PolicyAlgId(tpms.hash).to_string();
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
                    write!(f, ":{d}")?;
                }
                if let Some(c) = count {
                    write!(f, ", count={c}")?;
                }
                write!(f, ")")
            }
            Expression::Secret {
                auth_handle,
                password,
                cp_hash,
            } => {
                write!(f, "secret({auth_handle}")?;
                if let Some(p) = password {
                    if !matches!(&**p, Expression::Auth(Auth::Password(pw)) if pw.is_empty()) {
                        write!(f, ", {p}")?;
                    }
                }
                if let Some(c) = cp_hash {
                    write!(f, ", {c}")?;
                }
                write!(f, ")")
            }
            Expression::And(expressions) => {
                let s: Vec<String> = expressions.iter().map(ToString::to_string).collect();
                write!(f, "({})", s.join(" and "))
            }
            Expression::Or(expressions) => {
                let s: Vec<String> = expressions.iter().map(ToString::to_string).collect();
                write!(f, "({})", s.join(" or "))
            }
            Expression::Handle(handle) => write!(f, "{handle}"),
        }
    }
}

impl Expression {
    /// Parses a policy expression string into an
    /// [`Expression`](crate::Expression) AST.
    ///
    /// # Errors
    ///
    /// Returns a [`Error`] variant if parsing fails due to syntactic errors,
    /// malformed literals (handles, auth strings, PCR selections), or other
    /// structural problems in the input string.
    pub fn new(input: &str, context: &PolicyState) -> Result<Expression, Error> {
        let tokens = crate::tokenize(input);
        let mut iter = tokens.iter().peekable();
        let expr = crate::parse_expression(&mut iter, context)?;

        if iter.peek().is_none() {
            Ok(expr)
        } else {
            Err(ExpressionError::TrailingData.into())
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
        command_list: &[(TpmCommandBody, TpmAuthCommands)],
    ) -> Result<Expression, Error> {
        let mut stack: Vec<Vec<Expression>> = vec![vec![]];

        for (command_body, auth_sessions) in command_list {
            let current_branch = stack.last_mut().ok_or(ExpressionError::MalformedState)?;

            match command_body.clone() {
                TpmCommandBody::PolicyRestart(_) => {
                    stack.push(vec![]);
                }
                TpmCommandBody::PolicyPcr(cmd) => {
                    let selections = cmd.pcrs;
                    let digest = Some(hex::encode(cmd.pcr_digest.as_ref()));
                    let expr = Expression::Pcr {
                        selections,
                        digest,
                        count: None,
                    };
                    current_branch.push(expr);
                }
                TpmCommandBody::PolicySecret(cmd) => {
                    let auth_handle = Box::new(Expression::Handle(Handle::new(
                        HandleClass::Tpm,
                        cmd.auth_handle.into(),
                    )));

                    let cp_hash_bytes = cmd.cp_hash_a.as_ref();
                    let cp_hash = if cp_hash_bytes.is_empty() {
                        None
                    } else {
                        Some(hex::encode(cp_hash_bytes))
                    };

                    let password = auth_sessions.iter().find_map(|auth| {
                        if auth.session_handle.0 == TpmRh::Pw as u32 {
                            Some(Box::new(Expression::Auth(Auth::Password(
                                auth.hmac.as_ref().to_vec(),
                            ))))
                        } else {
                            None
                        }
                    });

                    let expr = Expression::Secret {
                        auth_handle,
                        password,
                        cp_hash,
                    };
                    current_branch.push(expr);
                }
                TpmCommandBody::PolicyOr(cmd) => {
                    let num_branches = cmd.p_hash_list.iter().len();
                    if stack.len() < num_branches {
                        return Err(ExpressionError::MalformedState.into());
                    }

                    let mut branches = Vec::with_capacity(num_branches);
                    for _ in 0..num_branches {
                        if let Some(branch_vec) = stack.pop() {
                            branches.push(build_and_branch(branch_vec));
                        } else {
                            return Err(ExpressionError::MalformedState.into());
                        }
                    }

                    branches.reverse();
                    let expr = Expression::Or(branches);

                    if let Some(branch_to_push_to) = stack.last_mut() {
                        branch_to_push_to.push(expr);
                    } else {
                        return Err(ExpressionError::MalformedState.into());
                    }
                }
                _ => return Err(CommandError::UnexpectedCommand(command_body.cc()).into()),
            }
        }

        if stack.len() != 1 {
            return Err(ExpressionError::MalformedState.into());
        }

        if let Some(final_branch) = stack.pop() {
            Ok(build_and_branch(final_branch))
        } else {
            Err(ExpressionError::MalformedState.into())
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
        context: &PolicyState,
    ) -> Result<(Vec<(TpmCommandBody, TpmAuthCommands)>, Tpm2bDigest), Error> {
        let mut command_list: Vec<(TpmCommandBody, TpmAuthCommands)> = Vec::new();
        let mut software_session = SoftwarePolicySession::new(session_hash_alg)?;

        let final_digest =
            self.to_command_list_walk(&mut command_list, &mut software_session, context)?;
        Ok((command_list, final_digest))
    }

    fn to_command_list_walk<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommandBody, TpmAuthCommands)>,
        software_session: &mut SoftwarePolicySession,
        context: &'a PolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        match self {
            Expression::And(branches) => {
                for branch in branches {
                    branch.to_command_list_walk(command_list, software_session, context)?;
                }
                Ok(software_session.get_digest())
            }
            expr @ Expression::Or { .. } => {
                expr.to_command_list_walk_or(command_list, software_session, context)
            }
            expr @ Expression::Pcr { .. } => {
                expr.to_command_list_walk_pcr(command_list, software_session)
            }
            expr @ Expression::Secret { .. } => {
                expr.to_command_list_walk_secret(command_list, software_session, context)
            }
            expr @ (Expression::Auth { .. } | Expression::Handle { .. }) => {
                Err(ExpressionError::InvalidNode(expr.to_string()).into())
            }
        }
    }

    fn to_command_list_walk_pcr(
        &self,
        command_list: &mut Vec<(TpmCommandBody, TpmAuthCommands)>,
        software_session: &mut SoftwarePolicySession,
    ) -> Result<Tpm2bDigest, Error> {
        let (selections, digest) = match self {
            Expression::Pcr {
                selections, digest, ..
            } => (selections, digest),
            expr => return Err(ExpressionError::InvalidNode(expr.to_string()).into()),
        };

        let digest_bytes = hex::decode(digest.as_ref().ok_or(PcrError::MissingPcrDigest)?)
            .map_err(|_| PcrError::InvalidDigestString(digest.as_ref().unwrap().to_string()))?;

        if digest_bytes.len() != software_session.digest_size {
            return Err(PcrError::TooLargeDigest(digest_bytes.len()).into());
        }

        let pcr_digest = Tpm2bDigest::try_from(digest_bytes.as_slice())
            .map_err(|_| PcrError::TooLargeDigest(digest_bytes.len()))?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: 0.into(),
            pcr_digest,
            pcrs: *selections,
        };

        command_list.push((
            TpmCommandBody::PolicyPcr(cmd.clone()),
            TpmAuthCommands::new(),
        ));
        software_session.policy_pcr(&cmd)?;

        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_secret<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommandBody, TpmAuthCommands)>,
        software_session: &mut SoftwarePolicySession,
        context: &'a PolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        let (auth_handle, password, cp_hash) = match self {
            Expression::Secret {
                auth_handle,
                password,
                cp_hash,
            } => (auth_handle, password, cp_hash),
            expr => return Err(ExpressionError::InvalidNode(expr.to_string()).into()),
        };

        let h_val = if let Expression::Handle(handle) = &**auth_handle {
            handle.value().ok_or(HandleError::PatternNotAllowed)?
        } else {
            return Err(ExpressionError::InvalidNode(auth_handle.to_string()).into());
        };

        let ht = h_val >> 24;
        if (h_val >> 24) as u8 != TpmHt::Persistent as u8 {
            return Err(HandleError::InvalidType(ht as u8).into());
        }

        let name = context
            .names
            .get(&h_val)
            .ok_or(SecretError::HandleNameMissing(h_val))?;

        let cp_hash_bytes = match cp_hash.as_ref().map(String::as_str) {
            None | Some("") => Ok::<_, SecretError>(Tpm2bDigest::default()),
            Some(cp_hash_str) => {
                let bytes = hex::decode(cp_hash_str)
                    .map_err(|_| SecretError::InvalidDigestString(cp_hash_str.to_string()))?;
                Tpm2bDigest::try_from(bytes.as_slice())
                    .map_err(|_| SecretError::InvalidDigestSize(bytes.len()))
            }
        }?;

        let cmd = TpmPolicySecretCommand {
            auth_handle: h_val.into(),
            policy_session: 0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: cp_hash_bytes,
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };

        let password_bytes = if let Some(p) = password {
            match &**p {
                Expression::Auth(Auth::Password(value)) => value.clone(),
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
                .map_err(|_| AuthError::TooLargeDigest(password_bytes.len()))?,
        };
        let mut auth_commands = TpmAuthCommands::new();
        auth_commands
            .push(auth_session)
            .map_err(|_| AuthError::TooLargeAuth(1))?;

        command_list.push((TpmCommandBody::PolicySecret(cmd), auth_commands));
        software_session.policy_secret(name)?;
        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_or<'a>(
        &'a self,
        command_list: &mut Vec<(TpmCommandBody, TpmAuthCommands)>,
        software_session: &mut SoftwarePolicySession,
        context: &'a PolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        let branches = match self {
            Expression::Or(branches) => branches,
            expr => return Err(ExpressionError::InvalidNode(expr.to_string()).into()),
        };

        let mut digest_list = TpmlDigest::new();
        for branch in branches {
            let restart_cmd = TpmPolicyRestartCommand {
                session_handle: 0.into(),
            };
            command_list.push((
                TpmCommandBody::PolicyRestart(restart_cmd),
                TpmAuthCommands::new(),
            ));
            software_session.policy_restart()?;

            let digest = branch.to_command_list_walk(command_list, software_session, context)?;

            digest_list
                .push(digest)
                .map_err(|_| CommandError::TooManyOrBranches(digest_list.len()))?;
        }

        let or_cmd = TpmPolicyOrCommand {
            policy_session: 0.into(),
            p_hash_list: digest_list,
        };
        command_list.push((
            TpmCommandBody::PolicyOr(or_cmd.clone()),
            TpmAuthCommands::new(),
        ));
        software_session.policy_or(&or_cmd)?;

        Ok(software_session.get_digest())
    }
}
