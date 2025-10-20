// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the parser and executor for the unified policy language.

pub mod software;
pub mod tpm;

pub use software::*;
pub use tpm::*;

use crate::{
    auth::Auth,
    crypto::CryptoError,
    device::{Device, DeviceError},
    key_cache::KeyCacheError,
    pcr::{self, PcrError},
    scheme::{Scheme, SchemeError},
    session::SessionError,
};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, hex_digit1, space0},
    combinator::{map, map_res, opt},
    error::ErrorKind,
    multi::separated_list1,
    sequence::{delimited, preceded, terminated, tuple},
    Err as NomErr, IResult,
};
use std::{collections::HashMap, fmt, str::FromStr};
use thiserror::Error;
use tpm2_protocol::{
    data::{Tpm2bDigest, TpmAlgId, TpmHt, TpmlDigest, TpmlPcrSelection},
    TpmErrorKind, TpmHandle,
};

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

    /// Retrieves the final policy digest from the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest cannot be retrieved.
    fn get_digest(&mut self) -> Result<Tpm2bDigest, PolicyError>;

    /// Returns the session's hash algorithm.
    fn hash_alg(&self) -> TpmAlgId;
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("context: {0}")]
    KeyCacheError(#[from] KeyCacheError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
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
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("PCR value for selection '{0}' not provided")]
    PcrValueMissing(String),
    #[error("session: {0}")]
    Session(#[from] SessionError),
    #[error("uri: {0}")]
    Uri(#[from] SchemeError),
}

impl From<hex::FromHexError> for PolicyError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}

impl From<base64::DecodeError> for PolicyError {
    fn from(err: base64::DecodeError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}

impl From<std::num::ParseIntError> for PolicyError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}

impl From<std::str::Utf8Error> for PolicyError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::InvalidValue(err.to_string())
    }
}

impl From<TpmErrorKind> for PolicyError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Device(err.into())
    }
}

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Auth(Auth),
    Pcr {
        selection: String,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle: Box<Expression>,
        password: Option<Box<Expression>>,
        cp_hash: Option<String>,
    },
    Or(Vec<Expression>),
    Uri(Scheme),
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expression::Auth(auth) => write!(f, "{auth}"),
            Expression::Pcr {
                selection,
                digest,
                count,
            } => {
                write!(f, "{selection}")?;
                if let Some(d) = digest {
                    write!(f, ":{d}")?;
                }
                if let Some(c) = count {
                    write!(f, ", count={c}")?;
                }
                Ok(())
            }
            Expression::Secret {
                auth_handle,
                password,
                cp_hash,
            } => {
                write!(f, "secret({auth_handle}")?;
                if let Some(p) = password {
                    write!(f, ", {p}")?;
                }
                if let Some(c) = cp_hash {
                    write!(f, ", {c}")?;
                }
                write!(f, ")")
            }
            Expression::Or(branches) => {
                let branches_str: Vec<String> = branches.iter().map(ToString::to_string).collect();
                write!(f, "or({})", branches_str.join(", "))
            }
            Expression::Uri(uri) => write!(f, "{uri}"),
        }
    }
}

impl Expression {
    /// Resolves a file path expression into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the expression is not a file path or the file
    /// cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        match self {
            Self::Auth(Auth(Scheme::Password(bytes))) => Ok(bytes.clone()),
            _ => Err(PolicyError::InvalidSecret(format!(
                "{self:?}: expected 'password:<hex>'"
            ))),
        }
    }

    /// Parses a TPM handle from a `tpm:` expression.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the expression is not a `Expression::Uri(Uri::Tpm)`.
    pub fn to_tpm_handle(&self) -> Result<u32, PolicyError> {
        match self {
            Self::Uri(Scheme::Tpm(handle)) => Ok(*handle),
            _ => Err(PolicyError::InvalidExpression(format!(
                "invalid expression: {self:?}: expected 'tpm:<handle>'"
            ))),
        }
    }
}

fn comma_sep<'a, F, O>(f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    preceded(terminated(char(','), space0), f)
}

fn secret_expression(input: &str) -> IResult<&str, Expression> {
    map(
        tuple((
            parse_expression,
            opt(comma_sep(parse_expression)),
            opt(comma_sep(map(hex_digit1, |s: &str| s.to_string()))),
        )),
        |(uri_expr, password_expr, cp_hash_str)| Expression::Secret {
            auth_handle: Box::new(uri_expr),
            password: password_expr.map(Box::new),
            cp_hash: cp_hash_str,
        },
    )(input)
}

fn or_expression(input: &str) -> IResult<&str, Expression> {
    map(
        separated_list1(
            preceded(space0, terminated(char(','), space0)),
            parse_expression,
        ),
        Expression::Or,
    )(input)
}

fn call<'a, F, O>(name: &'static str, f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(
        terminated(tag(name), char('(')),
        delimited(space0, f, space0),
        char(')'),
    )
}

fn auth_expression(input: &str) -> IResult<&str, Expression> {
    map_res(take_while1(|c: char| c != ',' && c != ')'), |s: &str| {
        Auth::from_str(s).map(Expression::Auth)
    })(input)
}

fn uri_expression(input: &str) -> IResult<&str, Expression> {
    map_res(take_while1(|c: char| c != ',' && c != ')'), |s: &str| {
        Scheme::from_str(s).map(Expression::Uri)
    })(input)
}

fn pcr_policy_expression(input: &str) -> IResult<&str, Expression> {
    let (remainder, pcr_substring) = take_while1(|c: char| !matches!(c, '(' | ')' | ','))(input)?;

    match pcr::parse_pcr_policy_string(pcr_substring) {
        Ok((selections, digest)) => {
            let selection_str = selections
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("+");
            let expr = Expression::Pcr {
                selection: selection_str,
                digest,
                count: None,
            };
            Ok((remainder, expr))
        }
        Err(_) => Err(NomErr::Error(nom::error::Error::new(
            input,
            ErrorKind::Verify,
        ))),
    }
}

/// Parses any valid expression.
fn parse_expression(input: &str) -> IResult<&str, Expression> {
    alt((
        call("secret", secret_expression),
        call("or", or_expression),
        pcr_policy_expression,
        auth_expression,
        uri_expression,
    ))(input)
}

/// Parses an expression string, ensuring the entire input is consumed.
///
/// # Errors
///
/// Returns a `PolicyError` if the input is not a valid expression or if there
/// is trailing input left after parsing.
pub fn parse(input: &str) -> Result<Expression, PolicyError> {
    let (remaining, expr) =
        parse_expression(input).map_err(|e| PolicyError::InvalidExpression(e.to_string()))?;

    if !remaining.is_empty() {
        return Err(PolicyError::InvalidExpression(format!(
            "unexpected trailing input: '{remaining}'"
        )));
    }
    Ok(expr)
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
            selection,
            digest,
            count: _,
        } => {
            let digest_bytes =
                hex::decode(digest.as_ref().ok_or(PolicyError::InvalidExpression(
                    "PCR policy requires a digest for execution".to_string(),
                ))?)?;
            let pcr_digest = Tpm2bDigest::try_from(digest_bytes.as_slice())?;
            let selections = pcr::pcr_selection_vec_from_str(selection)?;
            let banks = pcr::pcr_get_bank_list(session.device())?;
            let pcrs = pcr::pcr_selection_vec_to_tpml(&selections, &banks)?;
            session.policy_pcr(&pcr_digest, pcrs)?;
            session.get_digest()
        }
        Expression::Secret {
            auth_handle,
            password,
            cp_hash,
        } => {
            let handle_val = match &**auth_handle {
                Expression::Uri(Scheme::Tpm(h)) => {
                    if (*h >> 24) as u8 != TpmHt::Persistent as u8 {
                        return Err(PolicyError::InvalidExpression(
                            "secret() auth must be a persistent 'tpm:<handle>'".to_string(),
                        ));
                    }
                    *h
                }
                _ => {
                    return Err(PolicyError::InvalidExpression(
                        "secret() auth must be a persistent 'tpm:<handle>'".to_string(),
                    ))
                }
            };
            let handle = TpmHandle(handle_val);

            let (_, name) = session.device().read_public(handle)?;

            let password_bytes = password.as_ref().map(|p| p.to_bytes()).transpose()?;
            let cp_hash_digest = cp_hash
                .as_ref()
                .map(|hex_str| -> Result<Tpm2bDigest, PolicyError> {
                    let bytes = hex::decode(hex_str)?;
                    Ok(Tpm2bDigest::try_from(bytes.as_slice())?)
                })
                .transpose()?;

            session.policy_secret(handle_val, &name, password_bytes.as_deref(), cp_hash_digest)?;

            session.get_digest()
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
            session.policy_or(&branch_digests)?;
            session.get_digest()
        }
        Expression::Uri(uri) => Err(PolicyError::InvalidExpression(uri.to_string())),
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
            selection, digest, ..
        } => {
            if digest.is_none() {
                let digest_bytes = pcr_map
                    .get(selection)
                    .ok_or_else(|| PolicyError::PcrValueMissing(selection.clone()))?;
                *digest = Some(hex::encode(digest_bytes));
            }
        }
        Expression::Or(branches) => {
            for branch in branches.iter_mut() {
                populate_pcr_digests(branch, pcr_map)?;
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
        Expression::Auth(_) | Expression::Uri(_) => {}
    }
    Ok(())
}
