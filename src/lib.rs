// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

//! A parser for the TPM 2.0 policy language.
//!
//! This crate provides the necessary components to parse a policy language
//! string into an Abstract Syntax Tree (AST), represented by the
//! [`Expression`] enum. The main entry point is the [`Expression::new()`]
//! function.
//!
//! It also provides the [`Expression::to_command_list()`] function to convert a
//! parsed AST into a sequence of serialized TPM command blobs, and the
//! [`Expression::from_command_list()`] function to perform the reverse
//! operation.

use std::{collections::HashMap, fmt, iter::Peekable, slice::Iter, str::FromStr};
use thiserror::Error;
use tpm2_crypto::{digest as crypto_digest, hash_size as crypto_hash_size};
use tpm2_protocol::{
    constant::{TPM_MAX_COMMAND_SIZE, TPM_PCR_SELECT_MAX},
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmHt, TpmRh, TpmSt,
        TpmaSession, TpmlDigest, TpmlPcrSelection, TpmsAuthCommand, TpmsPcrSelect,
        TpmsPcrSelection,
    },
    frame::{
        tpm_marshal_command, tpm_unmarshal_command, TpmCommandBody, TpmFrame, TpmPolicyOrCommand,
        TpmPolicyPcrCommand, TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmMarshal, TpmSized, TpmWriter,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid authorization string prefix (expected 'password:', 'policy:', or 'vtpm:')")]
    InvalidPrefix,
    #[error("authorization data size too large: {0}")]
    SizeTooLarge(usize),
    #[error("invalid hex string for password or policy")]
    InvalidHex,
    #[error("invalid handle string for session: {0}")]
    InvalidHandleString(String),
    #[error("invalid handle type for session: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("expected 'password:<hex>'")]
    ExpectedPassword,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandleError {
    #[error("handle has less than eight characters")]
    TooFewDigits,
    #[error("handle has more than one '*'")]
    TooManyAsterisks,
    #[error("handle has more than eight characters")]
    TooManyDigits,
    #[error("invalid handle string: {0}")]
    InvalidString(String),
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidType(u8),
    #[error("handle must be a persistent TPM handle ('tpm:81xxxxxx')")]
    MustBePersistent,
    #[error("handle is a pattern but a concrete value is required")]
    PatternNotAllowed,
    #[error("invalid handle value: {0:08x}")]
    InvalidValue(u32),
    #[error("invalid handle scheme (expected 'tpm:' or 'vtpm:')")]
    InvalidScheme,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcrError {
    #[error("PCR selection string is not valid: {0}")]
    InvalidSelectionString(String),
    #[error("PCR selection index overflow: {0}")]
    IndexOverflow(usize),
    #[error("PCR selection size too large: {0}")]
    SelectionTooLarge(usize),
    #[error("PCR value (digest) is missing")]
    ValueMissing,
    #[error("PCR bank not available: {0:?}")]
    BankMissing(TpmAlgId),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret() expects 1 to 3 arguments")]
    ArgumentCount,
    #[error("a handle name for {0:08x} was not provided in the policy state")]
    HandleNameMissing(u32),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpressionError {
    #[error("malformed policy command: {0}")]
    MalformedPolicyCommand(String),
    #[error("parser state is malformed")]
    MalformedState,
    #[error("unexpected end of expression")]
    UnexpectedEnd,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,
    #[error("trailing data")]
    TrailingData,
    #[error("invalid expression node: {0}")]
    InvalidNode(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("unexpected non-policy command: {0:?}")]
    UnexpectedCommand(TpmCc),
    #[error("failed to build command: {0}")]
    BuildFailed(String),
    #[error("failed to parse command: {0}")]
    ParseFailed(String),
}

/// The primary error type for this crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Expression(#[from] ExpressionError),
    #[error(transparent)]
    Handle(#[from] HandleError),
    #[error(transparent)]
    Pcr(#[from] PcrError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("invalid hex digest format")]
    InvalidDigestFormat,
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),
}

/// Represents the properties of a single PCR bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrBank {
    pub alg: TpmAlgId,
    pub count: usize,
}

/// Pre-resolved data needed for policy execution.
///
/// This structure must be populated by the caller and passed to
/// [`Expression::to_command_list()`].
#[derive(Debug, Clone)]
pub struct PolicyState {
    /// List of available PCR banks.
    pub banks: Vec<PcrBank>,
    /// Map of persistent handle values to their TPM names.
    pub names: HashMap<u32, Tpm2bName>,
}

/// Maximum size for password or policy authorization data.
const MAX_AUTH_SIZE: usize = 64;

/// Authorization data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Policy(Vec<u8>),
    Session(u32),
}

fn parse_auth_hex(s: &str) -> Result<Vec<u8>, AuthError> {
    let bytes = hex::decode(s).map_err(|_| AuthError::InvalidHex)?;
    if bytes.len() > MAX_AUTH_SIZE {
        return Err(AuthError::SizeTooLarge(bytes.len()));
    }
    Ok(bytes)
}

impl Default for Auth {
    /// Creates a default `Auth` instance with an empty password.
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(data) if data.is_empty() => write!(f, "empty"),
            Self::Password(_) => write!(f, "password:<sensitive>"),
            Self::Policy(data) => write!(f, "policy:{}", hex::encode(data)),
            Self::Session(handle) => write!(f, "vtpm:{handle:08x}"),
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        let (prefix, value) = auth_str.split_once(':').ok_or(AuthError::InvalidPrefix)?;

        match prefix {
            "password" => Ok(Self::Password(parse_auth_hex(value)?)),
            "policy" => Ok(Self::Policy(parse_auth_hex(value)?)),
            "vtpm" => {
                let handle_val = u32::from_str_radix(value, 16)
                    .map_err(|_| AuthError::InvalidHandleString(value.to_string()))?;
                let ht_byte = (handle_val >> 24) as u8;
                let ht =
                    TpmHt::try_from(ht_byte).map_err(|()| AuthError::InvalidHandleType(ht_byte))?;

                match ht {
                    TpmHt::PolicySession | TpmHt::HmacSession => Ok(Self::Session(handle_val)),
                    _ => Err(AuthError::InvalidPrefix),
                }
            }
            _ => Err(AuthError::InvalidPrefix),
        }
    }
}

/// Handle classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleClass {
    Tpm,
    Vtpm,
}

/// TPM and vTPM handles, with support for pattern matching.
///
/// A `Handle` can represent either a single, specific handle value (e.g.,
/// `tpm:81000001`) or a pattern for matching multiple handles (e.g., `tpm:81*`,
/// `vtpm:????????`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    class: HandleClass,
    mask: u32,
    value: u32,
}

impl Handle {
    /// Creates a new `Handle` that represents a single, specific handle value.
    #[must_use]
    pub fn new(class: HandleClass, value: u32) -> Self {
        Self {
            class,
            mask: 0xFFFF_FFFF,
            value,
        }
    }

    /// Returns the class of the handle (`Tpm` or `Vtpm`).
    #[must_use]
    pub fn class(&self) -> HandleClass {
        self.class
    }

    /// Returns the value of the handle if it represents a single handle.
    ///
    /// Returns `Some(value)` when the handle was created without wildcards.
    /// Returns `None` when the handle is a pattern.
    #[must_use]
    pub fn value(&self) -> Option<u32> {
        if self.mask == 0xFFFF_FFFF {
            Some(self.value)
        } else {
            None
        }
    }

    /// Checks if a given handle value matches the handle's pattern.
    #[must_use]
    pub fn matches(&self, handle: u32) -> bool {
        (handle & self.mask) == self.value
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = match self.class {
            HandleClass::Tpm => "tpm",
            HandleClass::Vtpm => "vtpm",
        };
        write!(f, "{scheme}:")?;
        if self.mask == 0 {
            write!(f, "*")
        } else if self.mask == 0xFFFF_FFFF {
            write!(f, "{:08x}", self.value)
        } else {
            let mut out = [b'?'; 8];
            for (pos, item) in out.iter_mut().enumerate() {
                let i = 7usize.saturating_sub(pos);
                let nibble_mask = (self.mask >> (i * 4)) & 0xF;
                if nibble_mask == 0xF {
                    let nibble_val = (self.value >> (i * 4)) & 0xF;
                    *item = b"0123456789abcdef"[nibble_val as usize];
                }
            }
            let s = std::str::from_utf8(&out).map_err(|_| fmt::Error)?;
            write!(f, "{s}")
        }
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme_str, value_str) = s
            .split_once(':')
            .ok_or_else(|| HandleError::InvalidString(s.to_string()))?;

        let class = match scheme_str {
            "tpm" => HandleClass::Tpm,
            "vtpm" => HandleClass::Vtpm,
            _ => return Err(HandleError::InvalidScheme),
        };

        if value_str == "*" {
            return Ok(Self {
                class,
                mask: 0,
                value: 0,
            });
        }

        let mut normalized_str = String::with_capacity(8);
        if let Some((prefix, suffix)) = value_str.split_once('*') {
            if suffix.contains('*') {
                return Err(HandleError::TooManyAsterisks);
            }
            if prefix.len() + suffix.len() > 8 {
                return Err(HandleError::TooManyDigits);
            }
            normalized_str.push_str(prefix);
            normalized_str.extend(
                std::iter::repeat('?').take(8_usize.saturating_sub(prefix.len() + suffix.len())),
            );
            normalized_str.push_str(suffix);
        } else {
            if value_str.len() < 8 {
                return Err(HandleError::TooFewDigits);
            }
            if value_str.len() > 8 {
                return Err(HandleError::TooManyDigits);
            }
            normalized_str.push_str(value_str);
        }

        let mut mask: u32 = 0;
        let mut value: u32 = 0;

        for (i, c) in normalized_str.chars().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let shift = ((7 - i) * 4) as u32;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => return Err(HandleError::InvalidString(value_str.to_string())),
            }
        }

        Ok(Self { class, mask, value })
    }
}

impl TryFrom<Handle> for TpmHt {
    type Error = HandleError;

    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        let raw_handle = handle.value().ok_or(HandleError::PatternNotAllowed)?;
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|()| HandleError::InvalidType(ht_byte))
    }
}

/// A selection of PCR indices for a specific bank.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcrSelection {
    pub alg: TpmAlgId,
    pub indices: Vec<u32>,
}

/// A list of PCR selections, used as a newtype for `TryFrom` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelectionList(pub Vec<PcrSelection>);

impl fmt::Display for PcrSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let indices_str = self
            .indices
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}:{}", PolicyAlgId(self.alg), indices_str)
    }
}

/// Provides a [`Display`](std::fmt::Display) implementation for
/// [`TpmAlgId`](tpm2_protocol::data::TpmAlgId).
#[derive(Debug, Clone, Copy)]
pub struct PolicyAlgId(pub TpmAlgId);

impl TryFrom<&str> for PolicyAlgId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let alg_id = match s {
            "sha1" => TpmAlgId::Sha1,
            "sha256" => TpmAlgId::Sha256,
            "sha384" => TpmAlgId::Sha384,
            "sha512" => TpmAlgId::Sha512,
            _ => return Err(Error::UnsupportedHashAlgorithm(s.to_string())),
        };
        Ok(Self(alg_id))
    }
}

impl std::fmt::Display for PolicyAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            TpmAlgId::Sha1 => "sha1",
            TpmAlgId::Sha256 => "sha256",
            TpmAlgId::Sha384 => "sha384",
            TpmAlgId::Sha512 => "sha512",
            _ => "unknown",
        };
        write!(f, "{s}")
    }
}

impl TryFrom<&str> for PcrSelectionList {
    type Error = Error;

    fn try_from(selection_str: &str) -> Result<Self, Self::Error> {
        let selections = selection_str
            .split('+')
            .map(|part| {
                let (alg_str, indices_str) = part
                    .split_once(':')
                    .ok_or_else(|| PcrError::InvalidSelectionString(part.to_string()))?;

                let alg = PolicyAlgId::try_from(alg_str)?.0;

                let indices: Vec<u32> = indices_str
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<_, _>>()
                    .map_err(|_| PcrError::InvalidSelectionString(part.to_string()))?;

                Ok(PcrSelection { alg, indices })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self(selections))
    }
}

impl From<&TpmlPcrSelection> for PcrSelectionList {
    fn from(tpml: &TpmlPcrSelection) -> Self {
        let selections = tpml
            .iter()
            .map(|tpms| {
                let mut indices = Vec::new();
                for (byte_index, &byte) in tpms.pcr_select.iter().enumerate() {
                    for bit_index in 0..8 {
                        if (byte & (1 << bit_index)) != 0 {
                            #[allow(clippy::cast_possible_truncation)]
                            let pcr_index = (byte_index * 8 + bit_index) as u32;
                            indices.push(pcr_index);
                        }
                    }
                }
                PcrSelection {
                    alg: tpms.hash,
                    indices,
                }
            })
            .collect();
        Self(selections)
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
    let mut chars = input.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        match c {
            '(' => tokens.push(Token::LParen),
            ')' => tokens.push(Token::RParen),
            ',' => tokens.push(Token::Comma),
            c if c.is_whitespace() => {}
            _ => {
                let start = i;
                let mut end = i + c.len_utf8();

                while let Some(&(_, next_char)) = chars.peek() {
                    if next_char.is_whitespace() || "(),".contains(next_char) {
                        break;
                    }
                    let (next_i, _) = chars.next().unwrap();
                    end = next_i + next_char.len_utf8();
                }

                let ident_slice = &input[start..end];
                match ident_slice {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    _ => tokens.push(Token::Ident(ident_slice)),
                }
            }
        }
    }
    tokens
}

fn parse_expression<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Expression, ExpressionError> {
    parse_or(tokens)
}

fn parse_binary_expression<'a, F, G>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    mut operand_parser: F,
    operator: &Token,
    mut expression_combiner: G,
) -> Result<Expression, ExpressionError>
where
    F: FnMut(&mut Peekable<Iter<'a, Token<'a>>>) -> Result<Expression, ExpressionError>,
    G: FnMut(Expression, Expression) -> Expression,
{
    let mut node = operand_parser(tokens)?;
    while tokens.peek() == Some(&operator) {
        tokens.next();
        let rhs = operand_parser(tokens)?;
        node = expression_combiner(node, rhs);
    }
    Ok(node)
}

fn parse_or<'a>(tokens: &mut Peekable<Iter<'a, Token<'a>>>) -> Result<Expression, ExpressionError> {
    parse_binary_expression(tokens, parse_and, &Token::Or, |lhs, rhs| match lhs {
        Expression::Or(mut terms) => {
            terms.push(rhs);
            Expression::Or(terms)
        }
        _ => Expression::Or(vec![lhs, rhs]),
    })
}

fn parse_and<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Expression, ExpressionError> {
    parse_binary_expression(tokens, parse_primary, &Token::And, |lhs, rhs| match lhs {
        Expression::And(mut factors) => {
            factors.push(rhs);
            Expression::And(factors)
        }
        _ => Expression::And(vec![lhs, rhs]),
    })
}

fn parse_primary<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Expression, ExpressionError> {
    let token = tokens.next().ok_or(ExpressionError::UnexpectedEnd)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(ExpressionError::ParenthesisMismatch);
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => parse_pcr_call(tokens),
            "secret" => parse_secret_call(tokens),
            _ => parse_literal(name),
        },
        _ => Err(ExpressionError::UnexpectedToken(token.to_string())),
    }
}

fn parse_literal(s: &str) -> Result<Expression, ExpressionError> {
    if let Ok(auth) = Auth::from_str(s) {
        Ok(Expression::Auth(auth))
    } else if let Ok(handle) = Handle::from_str(s) {
        Ok(Expression::Handle(handle))
    } else {
        Err(ExpressionError::UnexpectedToken(format!(
            "unrecognized literal '{s}'"
        )))
    }
}

fn parse_call_args<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Vec<Expression>, ExpressionError> {
    match tokens.peek() {
        Some(&&Token::LParen) => {
            tokens.next();
        }
        Some(actual_token) => {
            return Err(ExpressionError::UnexpectedToken(format!(
                "Expected '(' to start argument list, found {actual_token}"
            )));
        }
        None => {
            return Err(ExpressionError::UnexpectedEnd);
        }
    }

    let mut args = Vec::new();
    if tokens.peek() == Some(&&Token::RParen) {
        tokens.next();
        return Ok(args);
    }

    loop {
        args.push(parse_or(tokens)?);

        match tokens.peek() {
            Some(&&Token::RParen) => {
                tokens.next();
                break;
            }
            Some(&&Token::Comma) => {
                tokens.next();
            }
            Some(actual_token) => {
                return Err(ExpressionError::UnexpectedToken(format!(
                    "Expected ',' or ')' in argument list, found {actual_token}"
                )));
            }
            None => return Err(ExpressionError::ParenthesisMismatch),
        }
    }
    Ok(args)
}

fn parse_pcr_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Expression, ExpressionError> {
    if tokens.next() != Some(&Token::LParen) {
        return Err(ExpressionError::UnexpectedToken(
            "expected '(' after 'pcr'".to_string(),
        ));
    }

    let mut buf = String::new();
    loop {
        match tokens.next() {
            Some(Token::RParen) => break,
            Some(Token::Ident(s)) => buf.push_str(s),
            Some(Token::Comma) => buf.push(','),
            Some(Token::And | Token::Or | Token::LParen) => {
                return Err(ExpressionError::UnexpectedToken(
                    "unexpected token inside pcr()".to_string(),
                ))
            }
            None => return Err(ExpressionError::UnexpectedEnd),
        }
    }

    let (selection_part, digest_part): (&str, Option<String>) =
        if let Some((selection, digest)) = buf.rsplit_once(':') {
            if hex::decode(digest).is_ok() && digest.len() > 10 {
                (selection, Some(digest.to_string()))
            } else {
                (buf.as_str(), None)
            }
        } else {
            (buf.as_str(), None)
        };

    let selections = PcrSelectionList::try_from(selection_part)
        .map_err(|e| ExpressionError::UnexpectedToken(e.to_string()))?
        .0;
    Ok(Expression::Pcr {
        selections,
        digest: digest_part,
        count: None,
    })
}

fn parse_secret_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
) -> Result<Expression, ExpressionError> {
    let args = parse_call_args(tokens)?;
    if args.is_empty() || args.len() > 3 {
        return Err(ExpressionError::UnexpectedToken(
            SecretError::ArgumentCount.to_string(),
        ));
    }

    let mut arg_iter = args.into_iter();
    let auth_handle = if let Some(handle) = arg_iter.next() {
        Box::new(handle)
    } else {
        return Err(ExpressionError::UnexpectedToken(
            SecretError::ArgumentCount.to_string(),
        ));
    };
    let password = arg_iter.next().map(Box::new);
    let cp_hash = arg_iter.next().map(|expr| expr.to_string());

    Ok(Expression::Secret {
        auth_handle,
        password,
        cp_hash,
    })
}

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, PartialEq, Eq, Clone)]
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

/// A session that simulates TPM policy digest calculations in software.
struct SoftwarePolicySession {
    digest: Tpm2bDigest,
    hash_alg: TpmAlgId,
    digest_size: usize,
}

/// Updates a policy digest with a new command, mimicking the TPM's internal
/// hashing.
fn update_policy_digest(
    current_digest: &mut Tpm2bDigest,
    hash_alg: TpmAlgId,
    cc: TpmCc,
    params: &[&[u8]],
) -> Result<(), Error> {
    let cc_bytes = (cc as u32).to_be_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(2 + params.len());
    chunks.push(current_digest.as_ref());
    chunks.push(&cc_bytes);
    chunks.extend(params.iter());

    let new_digest_bytes = crypto_digest(hash_alg, &chunks)
        .map_err(|e| Error::UnsupportedHashAlgorithm(e.to_string()))?;
    *current_digest = Tpm2bDigest::try_from(new_digest_bytes.as_slice())
        .map_err(|_| Error::InvalidDigestSize(new_digest_bytes.len()))?;
    Ok(())
}

impl SoftwarePolicySession {
    /// Creates a new software policy session.
    fn new(hash_alg: TpmAlgId) -> Result<Self, Error> {
        let digest_size = crypto_hash_size(hash_alg)
            .map_err(|e| Error::UnsupportedHashAlgorithm(e.to_string()))?;
        let digest = Tpm2bDigest::try_from(vec![0; digest_size].as_slice())
            .map_err(|_| Error::InvalidDigestSize(digest_size))?;
        Ok(Self {
            digest,
            hash_alg,
            digest_size,
        })
    }

    /// Applies a `TPM2_PolicyPCR` action to the session.
    fn policy_pcr(&mut self, cmd: &TpmPolicyPcrCommand) -> Result<(), Error> {
        let mut pcrs_bytes = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let pcrs_bytes_len = {
            let mut writer = TpmWriter::new(&mut pcrs_bytes);
            cmd.pcrs
                .marshal(&mut writer)
                .map_err(|e| CommandError::BuildFailed(e.to_string()))?;
            writer.len()
        };
        pcrs_bytes.truncate(pcrs_bytes_len);

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyPcr,
            &[&pcrs_bytes, cmd.pcr_digest.as_ref()],
        )
    }

    /// Applies a `TPM2_PolicyOR` action to the session.
    fn policy_or(&mut self, cmd: &TpmPolicyOrCommand) -> Result<(), Error> {
        let mut digests_as_bytes = Vec::with_capacity(cmd.p_hash_list.len() * self.digest_size);
        for digest in cmd.p_hash_list.iter() {
            digests_as_bytes.extend_from_slice(digest.as_ref());
        }

        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(|_| Error::InvalidDigestSize(self.digest_size))?;

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyOR,
            &[&digests_as_bytes],
        )
    }

    /// Applies a `TPM2_PolicySecret` action to the session.
    fn policy_secret(
        &mut self,
        cmd: &TpmPolicySecretCommand,
        auth_handle_name: &Tpm2bName,
    ) -> Result<(), Error> {
        let expiration_bytes = cmd.expiration.to_be_bytes();

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicySecret,
            &[
                auth_handle_name.as_ref(),
                cmd.nonce_tpm.as_ref(),
                cmd.cp_hash_a.as_ref(),
                cmd.policy_ref.as_ref(),
                &expiration_bytes,
            ],
        )
    }

    /// Applies a `TPM2_PolicyRestart` action to the session.
    fn policy_restart(&mut self) -> Result<(), Error> {
        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(|_| Error::InvalidDigestSize(self.digest_size))?;
        update_policy_digest(&mut self.digest, self.hash_alg, TpmCc::PolicyRestart, &[])
    }

    /// Retrieves the final policy digest from the session.
    fn get_digest(&self) -> Tpm2bDigest {
        self.digest
    }
}

/// Creates a password authorization session command structure.
fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, Error> {
    Ok(TpmsAuthCommand {
        session_handle: (TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password)
            .map_err(|_| Error::InvalidDigestSize(password.len()))?,
    })
}

/// Builds a complete, serialized TPM command buffer.
fn build_full_command<C: TpmFrame>(
    command: &C,
    tag: TpmSt,
    sessions: &[TpmsAuthCommand],
) -> Result<Vec<u8>, Error> {
    let mut cmd_buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];

    let cmd_len = {
        let mut writer = TpmWriter::new(&mut cmd_buf);
        tpm_marshal_command(command, tag, sessions, &mut writer)
            .map_err(|e| CommandError::BuildFailed(e.to_string()))?;
        writer.len()
    };
    cmd_buf.truncate(cmd_len);

    Ok(cmd_buf)
}

/// Converts a policy expression into raw bytes for auth/secret.
fn expression_to_bytes(expression: &Expression) -> Result<Vec<u8>, AuthError> {
    match expression {
        Expression::Auth(Auth::Password(value)) => Ok(value.clone()),
        _ => Err(AuthError::ExpectedPassword),
    }
}

/// Converts a `PcrSelection` list to the TPM's `TpmlPcrSelection` struct.
fn pcr_selection_vec_to_tpml(
    selections: &[PcrSelection],
    banks: &[PcrBank],
) -> Result<TpmlPcrSelection, Error> {
    let mut list = TpmlPcrSelection::new();
    for selection in selections {
        let bank = banks
            .iter()
            .find(|b| b.alg == selection.alg)
            .ok_or(PcrError::BankMissing(selection.alg))?;
        let pcr_select_size = bank.count.div_ceil(8);
        if pcr_select_size > TPM_PCR_SELECT_MAX as usize {
            return Err(PcrError::SelectionTooLarge(pcr_select_size).into());
        }
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &selection.indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= bank.count {
                return Err(PcrError::IndexOverflow(pcr_index).into());
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: selection.alg,
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())
                .map_err(|_| Error::InvalidDigestSize(pcr_select_bytes.len()))?,
        })
        .map_err(|e| CommandError::BuildFailed(e.to_string()))?;
    }
    Ok(list)
}

/// Conditionally wraps a list of expressions in `Expression::And`.
/// If the list contains exactly one item, it is returned directly.
fn build_and_branch(mut branch: Vec<Expression>) -> Expression {
    if branch.len() == 1 {
        match branch.pop() {
            Some(expr) => expr,
            None => Expression::And(Vec::new()),
        }
    } else {
        Expression::And(branch)
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
    pub fn new(input: &str) -> Result<Expression, Error> {
        let tokens = tokenize(input);
        let mut iter = tokens.iter().peekable();
        let expr = parse_expression(&mut iter)?;

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
    pub fn from_command_list(command_list: &[Vec<u8>]) -> Result<Expression, Error> {
        let mut stack: Vec<Vec<Expression>> = vec![vec![]];

        for cmd_blob in command_list {
            let (_handles, command_body, auth_sessions) = tpm_unmarshal_command(cmd_blob)
                .map_err(|e| CommandError::ParseFailed(e.to_string()))?;

            let current_branch = stack.last_mut().ok_or(ExpressionError::MalformedState)?;

            match command_body {
                TpmCommandBody::PolicyRestart(_) => {
                    stack.push(vec![]);
                }
                TpmCommandBody::PolicyPcr(cmd) => {
                    let selections = PcrSelectionList::from(&cmd.pcrs).0;
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
    ) -> Result<(Vec<Vec<u8>>, Tpm2bDigest), Error> {
        let mut command_list = Vec::new();
        let mut software_session = SoftwarePolicySession::new(session_hash_alg)?;

        let final_digest =
            self.to_command_list_walk(&mut command_list, &mut software_session, context)?;
        Ok((command_list, final_digest))
    }

    fn to_command_list_walk<'a>(
        &'a self,
        command_list: &mut Vec<Vec<u8>>,
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
                expr.to_command_list_walk_pcr(command_list, software_session, context)
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
        command_list: &mut Vec<Vec<u8>>,
        software_session: &mut SoftwarePolicySession,
        context: &PolicyState,
    ) -> Result<Tpm2bDigest, Error> {
        let (selections, digest) = match self {
            Expression::Pcr {
                selections, digest, ..
            } => (selections, digest),
            expr => return Err(ExpressionError::InvalidNode(expr.to_string()).into()),
        };

        let digest_bytes = hex::decode(digest.as_ref().ok_or(PcrError::ValueMissing)?)
            .map_err(|_| Error::InvalidDigestFormat)?;

        if digest_bytes.len() != software_session.digest_size {
            return Err(Error::InvalidDigestSize(digest_bytes.len()));
        }

        let pcr_digest = Tpm2bDigest::try_from(digest_bytes.as_slice())
            .map_err(|_| Error::InvalidDigestSize(digest_bytes.len()))?;

        let pcrs = pcr_selection_vec_to_tpml(selections, &context.banks)?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: 0.into(),
            pcr_digest,
            pcrs,
        };

        let full_cmd = build_full_command(&cmd, TpmSt::NoSessions, &[])?;
        command_list.push(full_cmd);
        software_session.policy_pcr(&cmd)?;

        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_secret<'a>(
        &'a self,
        command_list: &mut Vec<Vec<u8>>,
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

        if (h_val >> 24) as u8 != TpmHt::Persistent as u8 {
            return Err(HandleError::MustBePersistent.into());
        }

        let name = context
            .names
            .get(&h_val)
            .ok_or(SecretError::HandleNameMissing(h_val))?;

        let cp_hash_digest = match cp_hash.as_ref().map(String::as_str) {
            None | Some("") => Ok(Tpm2bDigest::default()),
            Some(hex_str) => {
                let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidDigestFormat)?;
                Tpm2bDigest::try_from(bytes.as_slice())
                    .map_err(|_| Error::InvalidDigestSize(bytes.len()))
            }
        }?;

        let cmd = TpmPolicySecretCommand {
            auth_handle: h_val.into(),
            policy_session: 0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: cp_hash_digest,
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };

        let full_cmd = if let Some(p) = password {
            let password_bytes = expression_to_bytes(p)?;
            let sanitized_password = vec![0u8; password_bytes.len()];
            let auth_session = build_password_session(&sanitized_password)?;
            build_full_command(&cmd, TpmSt::Sessions, &[auth_session])?
        } else {
            build_full_command(&cmd, TpmSt::NoSessions, &[])?
        };

        command_list.push(full_cmd);
        software_session.policy_secret(&cmd, name)?;
        Ok(software_session.get_digest())
    }

    fn to_command_list_walk_or<'a>(
        &'a self,
        command_list: &mut Vec<Vec<u8>>,
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
            let full_cmd = build_full_command(&restart_cmd, TpmSt::NoSessions, &[])?;
            command_list.push(full_cmd);
            software_session.policy_restart()?;

            let digest = branch.to_command_list_walk(command_list, software_session, context)?;

            digest_list
                .try_push(digest)
                .map_err(|e| CommandError::BuildFailed(e.to_string()))?;
        }

        let or_cmd = TpmPolicyOrCommand {
            policy_session: 0.into(),
            p_hash_list: digest_list,
        };
        let full_cmd = build_full_command(&or_cmd, TpmSt::NoSessions, &[])?;
        command_list.push(full_cmd);
        software_session.policy_or(&or_cmd)?;

        Ok(software_session.get_digest())
    }
}
