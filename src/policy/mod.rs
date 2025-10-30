// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the executor for the unified policy language.

mod software;
mod tpm;

pub use software::*;
pub use tpm::*;
use tpm2_policy_language::{Auth, Expression, HandleClass, ParseError as PolicyParseError};

use crate::{
    device::{Device, DeviceError},
    pcr::{self, PcrError},
    vtpm::VtpmError,
};
use std::{collections::HashMap, num::ParseIntError};
use thiserror::Error;
use tpm2_crypto::CryptoError;
use tpm2_protocol::{
    data::{Tpm2bDigest, TpmAlgId, TpmHt, TpmlDigest, TpmlPcrSelection},
    TpmError, TpmHandle,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid expression: {0}")]
    InvalidExpression(String),
    #[error("invalid secret: {0}")]
    InvalidSecret(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("no valid branch found for OR policy")]
    NoValidPolicyOrBranch,
    #[error("PCR value for selection '{0}' not provided")]
    PcrValueMissing(String),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("cache: {0}")]
    Cache(#[from] VtpmError),
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] ParseIntError),
    #[error("protocol: {0}")]
    TpmProtocol(TpmError),
    #[error("parse: {0}")]
    Parse(#[from] PolicyParseError),
}

impl From<TpmError> for PolicyError {
    fn from(err: TpmError) -> Self {
        Self::TpmProtocol(err)
    }
}

/// An abstract interface for a session that can have a policy applied to it.
pub trait PolicySession {
    /// Returns the device associated with the session.
    fn device(&mut self) -> &mut Device;

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
        Expression::Auth(Auth::Password(value)) => Ok(value.clone()),
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
            let pcr_digest = Tpm2bDigest::try_from(digest_bytes.as_slice())?;
            let banks = pcr::pcr_get_bank_list(session.device())?;
            let pcrs = pcr::pcr_selection_vec_to_tpml(selections, &banks)?;
            session.policy_pcr(&pcr_digest, pcrs)?;
            session.get_digest()
        }
        Expression::Secret {
            auth_handle,
            password,
            cp_hash,
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
            let handle = TpmHandle(h_val);

            let (_, name) = session.device().read_public(handle)?;

            let password_bytes = password
                .as_ref()
                .map(|p| expression_to_bytes(p))
                .transpose()?;
            let cp_hash_digest = cp_hash
                .as_ref()
                .map(|hex_str| -> Result<Tpm2bDigest, PolicyError> {
                    let bytes = hex::decode(hex_str)?;
                    Ok(Tpm2bDigest::try_from(bytes.as_slice())?)
                })
                .transpose()?;

            session.policy_secret(h_val, &name, password_bytes.as_deref(), cp_hash_digest)?;

            session.get_digest()
        }
        Expression::And(expressions) => {
            let (last_expr, other_exprs) = expressions.split_last().ok_or_else(|| {
                PolicyError::InvalidExpression("'and'-expression must be non-empty".to_string())
            })?;

            for expr in other_exprs {
                execute_policy(expr, session)?;
            }
            execute_policy(last_expr, session)
        }
        Expression::Or(branches) => {
            let mut branch_digests = TpmlDigest::new();
            for branch in branches {
                let mut temp_session =
                    SoftwarePolicySession::new(session.hash_alg(), session.device())?;
                let branch_digest = execute_policy(branch, &mut temp_session)?;
                branch_digests
                    .try_push(branch_digest)
                    .map_err(|e| PolicyError::InvalidExpression(e.to_string()))?;
            }

            let mut last_error: Option<PolicyError> = None;
            let mut branch_succeeded = false;
            for branch in branches {
                session.policy_restart()?;
                match execute_policy(branch, session) {
                    Ok(_) => {
                        branch_succeeded = true;
                        break;
                    }
                    Err(e) => {
                        last_error = Some(e);
                    }
                }
            }

            if !branch_succeeded {
                return Err(last_error.unwrap_or(PolicyError::NoValidPolicyOrBranch));
            }

            session.policy_or(&branch_digests)?;
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
pub fn populate_pcr_digests<S: std::hash::BuildHasher>(
    ast: &mut Expression,
    pcr_map: &HashMap<String, Vec<u8>, S>,
) -> Result<(), PolicyError> {
    match ast {
        Expression::Pcr {
            selections, digest, ..
        } => {
            if digest.is_none() {
                let selection_str = selections
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("+");
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
            ..
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
