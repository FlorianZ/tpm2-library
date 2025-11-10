//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the executor for the unified policy language.

use tpm2_policy_language::{Error as PolicyLanguageError, Expression, HandleClass};

use crate::{
    device::DeviceError,
    pcr::{self, PcrError},
    vtpm::VtpmError,
};
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::num::ParseIntError;
use thiserror::Error;
use tpm2_crypto::Error as CryptoError;
use tpm2_protocol::{
    data::{Tpm2bDigest, Tpm2bName, TpmAlgId, TpmHt, TpmlDigest, TpmlPcrSelection},
    TpmProtocolError,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("cache: {0}")]
    Vtpm(#[from] VtpmError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] ParseIntError),
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid expression: {0}")]
    InvalidExpression(String),
    #[error("invalid secret: {0}")]
    InvalidSecret(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("no valid branch found for OR policy")]
    NoValidPolicyOrBranch,
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("pcr index too large: {0}")]
    PcrIndexTooLarge(usize),
    #[error("PCR value for selection '{0}' not provided")]
    PcrValueMissing(String),
    #[error("policy language: {0}")]
    PolicyLanguage(#[from] PolicyLanguageError),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
}

/// Pre-resolved data needed for policy execution.
pub struct PolicyState {
    /// List of available PCR banks.
    pub banks: Vec<pcr::PcrBank>,
    /// Map of persistent handle values to their TPM names.
    pub names: HashMap<u32, Tpm2bName>,
}

/// An abstract interface for a session that can have a policy applied to it.
pub trait PolicySession {
    /// Applies a `TPM2_PolicyPCR` action to the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy action fails.
    fn policy_pcr(
        &mut self,
        pcr_digest: &Tpm2bDigest,
        pcrs: TpmlPcrSelection,
    ) -> Result<(), PolicyError>;

    /// Applies a `TPM2_PolicyOR` action to the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy action fails.
    fn policy_or(&mut self, p_hash_list: &TpmlDigest) -> Result<(), PolicyError>;

    /// Applies a `TPM2_PolicySecret` action to the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy action fails.
    fn policy_secret(
        &mut self,
        auth_handle: u32,
        auth_handle_name: &tpm2_protocol::data::Tpm2bName,
        password: Option<&[u8]>,
        cp_hash: Option<Tpm2bDigest>,
    ) -> Result<(), PolicyError>;

    /// Applies a `TPM2_PolicyRestart` action to the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy action fails.
    fn policy_restart(&mut self) -> Result<(), PolicyError>;

    /// Retrieves the final policy digest from the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest cannot be retrieved.
    fn get_digest(&mut self) -> Result<Tpm2bDigest, PolicyError>;

    /// Returns the session's hash algorithm.
    fn hash_alg(&self) -> TpmAlgId;
}

/// Resolves a password expression into bytes.
///
/// # Errors
///
/// Returns a `PolicyError` if the expression is not a file path or the file
/// cannot be read.
pub fn expression_to_bytes(expression: &Expression) -> Result<Vec<u8>, PolicyError> {
    match expression {
        Expression::Auth(tpm2_policy_language::Auth::Password(value)) => Ok(value.clone()),
        _ => Err(PolicyError::InvalidSecret(format!(
            "{expression:?}: expected 'password:<hex>'"
        ))),
    }
}

/// Traverses a policy AST and applies the commands to a session object.
///
/// # Errors
///
/// Returns an error if any policy command fails.
pub fn execute_policy(
    ast: &Expression,
    session: &mut impl PolicySession,
    context: &PolicyState,
) -> Result<Tpm2bDigest, PolicyError> {
    match ast {
        Expression::Auth(auth) => Err(PolicyError::InvalidExpression(auth.to_string())),
        Expression::Pcr {
            selections,
            digest,
            count: _,
        } => {
            let digest_bytes =
                hex::decode(digest.as_ref().ok_or(PolicyError::InvalidExpression(
                    "expected a hex string for optional digest in pcr()".to_string(),
                ))?)?;
            let pcr_digest = Tpm2bDigest::try_from(digest_bytes.as_slice())
                .map_err(|_| PolicyError::CapacityExceeded)?;
            session.policy_pcr(&pcr_digest, *selections)?;
            session.get_digest()
        }
        Expression::Secret {
            auth_handle,
            password,
        } => {
            let h_val = if let Expression::Handle(handle) = &**auth_handle {
                let val = handle.value().ok_or(PolicyError::InvalidExpression(
                    "secret() handle cannot be a pattern".to_string(),
                ))?;

                if handle.class() != HandleClass::Tpm
                    || (val >> 24) as u8 != TpmHt::Persistent as u8
                {
                    return Err(PolicyError::InvalidExpression(
                        "secret() handle must be a persistent TPM handle ('tpm:81xxxxxx')"
                            .to_string(),
                    ));
                }
                val
            } else {
                return Err(PolicyError::InvalidExpression(
                    "secret() first argument must be a handle".to_string(),
                ));
            };

            let name = context.names.get(&h_val).ok_or_else(|| {
                PolicyError::InvalidExpression(format!("Handle tpm:{h_val:08x} name not found"))
            })?;

            let password_bytes = password
                .as_ref()
                .map(|expr| expression_to_bytes(expr))
                .transpose()?;
            let cp_hash_digest = None;

            session.policy_secret(h_val, name, password_bytes.as_deref(), cp_hash_digest)?;

            session.get_digest()
        }
        Expression::And(expressions) => {
            let (last_expr, other_exprs) = expressions.split_last().ok_or_else(|| {
                PolicyError::InvalidExpression("'and'-expression must be non-empty".to_string())
            })?;

            for expr in other_exprs {
                execute_policy(expr, session, context)?;
            }
            execute_policy(last_expr, session, context)
        }
        Expression::Or(branch_list) => {
            let mut digest_list = TpmlDigest::new();
            for branch in branch_list {
                session.policy_restart()?;
                let digest = execute_policy(branch, session, context)?;
                digest_list
                    .push(digest)
                    .map_err(|_| PolicyError::InvalidExpression(ast.to_string()))?;
            }
            session.policy_or(&digest_list)?;
            session.get_digest()
        }
        Expression::Handle(handle) => Err(PolicyError::InvalidExpression(handle.to_string())),
    }
}

/// Recursively traverses a policy AST and populates any missing PCR digests
/// from a provided map.
///
/// # Errors
///
/// Returns a `PolicyError` if a PCR selection is malformed or if its value is
/// not in the map.
pub fn populate_pcr_digests<S: BuildHasher>(
    ast: &mut Expression,
    pcr_map: &HashMap<String, Vec<u8>, S>,
) -> Result<(), PolicyError> {
    match ast {
        Expression::Pcr {
            selections, digest, ..
        } => {
            if digest.is_none() {
                let selection_strings: Vec<String> = selections
                    .iter()
                    .map(|tpms| {
                        let alg_str = tpm2_crypto::Hash::from(tpms.hash).to_string();
                        let mut indices = Vec::new();
                        for (byte_index, &byte) in tpms.pcr_select.iter().enumerate() {
                            for bit_index in 0..8 {
                                if (byte & (1 << bit_index)) != 0 {
                                    let pcr_index_usize = byte_index * 8 + bit_index;
                                    let pcr_index =
                                        u32::try_from(pcr_index_usize).map_err(|_| {
                                            PolicyError::PcrIndexTooLarge(pcr_index_usize)
                                        })?;
                                    indices.push(pcr_index.to_string());
                                }
                            }
                        }
                        Ok(format!("{}:{}", alg_str, indices.join(",")))
                    })
                    .collect::<Result<Vec<String>, PolicyError>>()?;
                let selection_str = selection_strings.join("+");

                let digest_bytes = pcr_map
                    .get(&selection_str)
                    .ok_or(PolicyError::PcrValueMissing(selection_str))?;
                *digest = Some(hex::encode(digest_bytes));
            }
        }
        Expression::And(expressions) | Expression::Or(expressions) => {
            for expr in expressions.iter_mut() {
                populate_pcr_digests(expr, pcr_map)?;
            }
        }
        Expression::Secret {
            auth_handle,
            password,
        } => {
            populate_pcr_digests(auth_handle, pcr_map)?;
            if let Some(pwd_expr) = password {
                populate_pcr_digests(pwd_expr, pcr_map)?;
            }
        }
        Expression::Auth(_) | Expression::Handle(_) => {}
    }
    Ok(())
}

/// Traverses the AST, applying a fallible visitor closure to each `Pcr` expression.
///
/// # Errors
///
/// Returns a `PolicyError` if the provided visitor closure returns an error.
pub fn visit_pcr_expressions_mut<F>(
    ast: &mut Expression,
    visitor: &mut F,
) -> Result<(), PolicyError>
where
    F: FnMut(&mut Expression) -> Result<(), PolicyError>,
{
    match ast {
        Expression::Pcr { .. } => visitor(ast)?,
        Expression::And(branches) | Expression::Or(branches) => {
            for branch in branches.iter_mut() {
                visit_pcr_expressions_mut(branch, visitor)?;
            }
        }
        Expression::Secret { auth_handle, .. } => {
            visit_pcr_expressions_mut(auth_handle, visitor)?;
        }
        Expression::Auth(_) | Expression::Handle(_) => {}
    }
    Ok(())
}

/// Traverses the AST, collecting all persistent handles used in `secret()`
/// commands.
///
/// # Errors
///
/// Returns [`InvalidExpression`](crate::policy::PolicyError::InvalidExpression)
/// if a secret is not pointing to a persistent handle.
pub fn visit_secret_handles<S: BuildHasher>(
    ast: &Expression,
    handles: &mut HashSet<u32, S>,
) -> Result<(), PolicyError> {
    match ast {
        Expression::Pcr { .. } | Expression::Auth(_) | Expression::Handle(_) => {}
        Expression::And(branches) | Expression::Or(branches) => {
            for branch in branches {
                visit_secret_handles(branch, handles)?;
            }
        }
        Expression::Secret { auth_handle, .. } => {
            if let Expression::Handle(handle) = &**auth_handle {
                let val = handle.value().ok_or(PolicyError::InvalidExpression(
                    "secret() handle cannot be a pattern".to_string(),
                ))?;
                if handle.class() != HandleClass::Tpm
                    || (val >> 24) as u8 != TpmHt::Persistent as u8
                {
                    return Err(PolicyError::InvalidExpression(
                        "secret() handle must be a persistent TPM handle ('tpm:81xxxxxx')"
                            .to_string(),
                    ));
                }
                handles.insert(val);
            } else {
                return Err(PolicyError::InvalidExpression(
                    "secret() first argument must be a handle".to_string(),
                ));
            }
        }
    }
    Ok(())
}
