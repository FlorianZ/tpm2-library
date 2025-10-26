// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the parser and executor for the unified policy language.

pub mod software;
pub mod tpm;

pub use software::*;
pub use tpm::*;

use crate::{
    auth::{Auth, AuthClass},
    crypto::CryptoError,
    device::{Device, DeviceError},
    handle::{Handle, HandleClass, HandleError},
    pcr::{self, PcrError, PcrSelection},
    vtpm::VtpmError,
};
use std::{
    collections::HashMap, fmt, iter::Peekable, num::ParseIntError, slice::Iter, str::FromStr,
};
use thiserror::Error;
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
    #[error("unexpected end of expression")]
    UnexpectedEndOfExpression,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("unmatched parenthesis")]
    UnmatchedParenthesis,
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
    #[error("handle decode: {0}")]
    IntDecode(#[from] ParseIntError),
    #[error("protocol: {0}")]
    TpmProtocol(TpmError),
    #[error("handle: {0}")]
    Handle(#[from] HandleError),
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

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Auth(Auth),
    Pcr {
        selections: Vec<PcrSelection>,
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

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Auth(auth) => write!(f, "{auth}"),
            Expression::Pcr {
                selections,
                digest,
                count,
            } => {
                let selection_str = selections
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("+");
                write!(f, "pcr({selection_str}")?;
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
                    write!(f, ", {p}")?;
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
    /// Resolves a password expression into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the expression is not a file path or the file
    /// cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        match self {
            Self::Auth(auth_instance) if auth_instance.class() == AuthClass::Password => {
                Ok(auth_instance.value().to_vec())
            }
            _ => Err(PolicyError::InvalidSecret(format!(
                "{self:?}: expected 'password:<hex>'"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    And,
    Or,
    LParen,
    RParen,
    Comma,
    Ident(&'a str),
}

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::And => write!(f, "'and'"),
            Token::Or => write!(f, "'or'"),
            Token::LParen => write!(f, "'('"),
            Token::RParen => write!(f, "')'"),
            Token::Comma => write!(f, "','"),
            Token::Ident(s) => write!(f, "'{s}'"),
        }
    }
}

fn tokenize(input: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut current_index = 0;
    let bytes = input.as_bytes();

    while current_index < bytes.len() {
        let ch = bytes[current_index] as char;

        match ch {
            '(' => {
                tokens.push(Token::LParen);
                current_index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                current_index += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                current_index += 1;
            }
            c if c.is_whitespace() => {
                let char_len = input[current_index..].chars().next().unwrap().len_utf8();
                current_index += char_len;
            }
            _ => {
                let start_index = current_index;
                let mut end_index = start_index;
                while end_index < bytes.len() {
                    let current_char = input[end_index..].chars().next().unwrap();
                    if current_char.is_whitespace() || "(),".contains(current_char) {
                        break;
                    }
                    end_index += current_char.len_utf8();
                }

                let ident_slice = &input[start_index..end_index];

                match ident_slice {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    _ => tokens.push(Token::Ident(ident_slice)),
                }
                current_index = end_index;
            }
        }
    }
    tokens
}

struct Parser<'a, 'b> {
    tokens: &'a mut Peekable<Iter<'b, Token<'b>>>,
}

impl Parser<'_, '_> {
    fn parse_or(&mut self) -> Result<Expression, PolicyError> {
        let mut node = self.parse_and()?;
        while let Some(Token::Or) = self.tokens.peek() {
            self.tokens.next();
            let rhs = self.parse_and()?;
            node = match node {
                Expression::Or(mut terms) => {
                    terms.push(rhs);
                    Expression::Or(terms)
                }
                lhs => Expression::Or(vec![lhs, rhs]),
            };
        }
        Ok(node)
    }

    fn parse_and(&mut self) -> Result<Expression, PolicyError> {
        let mut node = self.parse_primary()?;
        while let Some(Token::And) = self.tokens.peek() {
            self.tokens.next();
            let rhs = self.parse_primary()?;
            node = match node {
                Expression::And(mut factors) => {
                    factors.push(rhs);
                    Expression::And(factors)
                }
                lhs => Expression::And(vec![lhs, rhs]),
            };
        }
        Ok(node)
    }

    fn parse_primary(&mut self) -> Result<Expression, PolicyError> {
        let token = self
            .tokens
            .next()
            .ok_or(PolicyError::UnexpectedEndOfExpression)?;

        match token {
            Token::LParen => {
                let expr = self.parse_or()?;
                if self.tokens.next() != Some(&Token::RParen) {
                    return Err(PolicyError::UnmatchedParenthesis);
                }
                Ok(expr)
            }
            Token::Ident(name) => match *name {
                "pcr" => self.parse_pcr_call(),
                "secret" => self.parse_secret_call(),
                _ => Self::parse_literal(name),
            },
            _ => Err(PolicyError::UnexpectedToken(token.to_string())),
        }
    }

    fn parse_literal(s: &str) -> Result<Expression, PolicyError> {
        if let Ok(auth) = Auth::from_str(s) {
            Ok(Expression::Auth(auth))
        } else if let Ok(handle) = Handle::from_str(s) {
            Ok(Expression::Handle(handle))
        } else {
            Err(PolicyError::InvalidExpression(format!(
                "unrecognized literal: {s}"
            )))
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expression>, PolicyError> {
        match self.tokens.peek() {
            Some(&&Token::LParen) => {
                self.tokens.next();
            }
            Some(actual_token) => {
                return Err(PolicyError::UnexpectedToken(format!(
                    "Expected '(' to start argument list, found {actual_token}"
                )));
            }
            None => {
                return Err(PolicyError::UnexpectedEndOfExpression);
            }
        }

        let mut args = Vec::new();
        if self.tokens.peek() == Some(&&Token::RParen) {
            self.tokens.next();
            return Ok(args);
        }

        loop {
            if let Some(Token::Ident(ident)) = self.tokens.peek() {
                if let Ok(selections) = pcr::pcr_selection_vec_from_str(ident) {
                    self.tokens.next();
                    args.push(Expression::Pcr {
                        selections,
                        digest: None,
                        count: None,
                    });
                } else {
                    args.push(self.parse_or()?);
                }
            } else {
                args.push(self.parse_or()?);
            }

            match self.tokens.peek() {
                Some(&&Token::RParen) => {
                    self.tokens.next();
                    break;
                }
                Some(&&Token::Comma) => {
                    self.tokens.next();
                }
                Some(actual_token) => {
                    return Err(PolicyError::UnexpectedToken(format!(
                        "Expected ',' or ')' in argument list, found {actual_token}"
                    )));
                }
                None => return Err(PolicyError::UnmatchedParenthesis),
            }
        }
        Ok(args)
    }

    fn parse_pcr_call(&mut self) -> Result<Expression, PolicyError> {
        let mut args = self.parse_call_args()?;
        if args.len() != 1 {
            return Err(PolicyError::InvalidExpression(
                "pcr() expects one argument ".to_string(),
            ));
        }

        let arg = args.remove(0);
        if let Expression::Pcr {
            selections,
            digest,
            count,
        } = arg
        {
            Ok(Expression::Pcr {
                selections,
                digest,
                count,
            })
        } else if let Expression::Auth(_) | Expression::Handle(_) = arg {
            let pcr_content = arg.to_string();
            let (selection_part, digest_part) =
                if let Some((selection, digest)) = pcr_content.rsplit_once(':') {
                    if digest.chars().all(|c| c.is_ascii_hexdigit())
                        && digest.len()
                            >= crate::crypto::crypto_hash_size(TpmAlgId::Sha1).unwrap_or(20) * 2
                    {
                        (selection.to_string(), Some(digest.to_string()))
                    } else {
                        (pcr_content, None)
                    }
                } else {
                    (pcr_content, None)
                };

            let selections = pcr::pcr_selection_vec_from_str(&selection_part)?;
            Ok(Expression::Pcr {
                selections,
                digest: digest_part,
                count: None,
            })
        } else {
            Err(PolicyError::InvalidExpression(
                "pcr() argument is not a valid PCR selection ".to_string(),
            ))
        }
    }

    fn parse_secret_call(&mut self) -> Result<Expression, PolicyError> {
        let args = self.parse_call_args()?;
        if args.is_empty() || args.len() > 3 {
            return Err(PolicyError::InvalidExpression(
                "secret() expects 1 to 3 arguments ".to_string(),
            ));
        }

        let mut arg_iter = args.into_iter();
        let auth_handle = Box::new(arg_iter.next().unwrap());
        let password = arg_iter.next().map(Box::new);
        let cp_hash = arg_iter.next().map(|expr| expr.to_string());

        Ok(Expression::Secret {
            auth_handle,
            password,
            cp_hash,
        })
    }
}

/// Parses a policy expression string.
///
/// # Errors
///
/// Returns a `PolicyError::InvalidExpression` if expression parsing fails.
/// Returns a `PolicyError::UnexpectedToken` if there is trailing data after the
/// expression.
pub fn parse(input: &str) -> Result<Expression, PolicyError> {
    let tokens = tokenize(input);
    let mut iter = tokens.iter().peekable();
    let mut parser = Parser { tokens: &mut iter };
    let expr = parser.parse_or()?;

    if parser.tokens.peek().is_some() {
        return Err(PolicyError::UnexpectedToken(
            "Trailing data after expression ".to_string(),
        ));
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
            let handle_val =
                match &**auth_handle {
                    Expression::Handle(handle) if handle.class() == HandleClass::Tpm => {
                        let h_val = handle.value();
                        if (h_val >> 24) as u8 != TpmHt::Persistent as u8 {
                            return Err(PolicyError::InvalidExpression(
                                "secret() handle must be a persistent TPM handle ('tpm:81xxxxxx')"
                                    .to_string(),
                            ));
                        }
                        h_val
                    }
                    _ => return Err(PolicyError::InvalidExpression(
                        "secret() first argument must be a persistent TPM handle ('tpm:81xxxxxx')"
                            .to_string(),
                    )),
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
