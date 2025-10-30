// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

//! A parser for the TPM 2.0 policy language.
//!
//! This crate provides the necessary components to parse a policy language string
//! into an Abstract Syntax Tree (AST), represented by the [`Expression`] enum.
//! The main entry point is the [`Expression::new()`] function.

use std::{fmt, iter::Peekable, slice::Iter, str::FromStr};
use thiserror::Error;
use tpm2_protocol::data::{TpmAlgId, TpmHt};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid authorization string: '{0}'")]
    InvalidAuthString(String),
    #[error("invalid handle string: '{0}'")]
    InvalidHandleString(String),
    #[error("handle has less than eight characters")]
    HandleTooFewDigits,
    #[error("handle has more than one '*'")]
    HandleTooManyAsterisks,
    #[error("handle has more than eight characters")]
    HandleTooManyDigits,
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("invalid hex string: '{0}'")]
    InvalidHexString(String),
    #[error("invalid integer: '{0}'")]
    InvalidInteger(String),
    #[error("invalid PCR selection string: '{0}'")]
    InvalidPcrSelectionString(String),
    #[error("value too large")]
    ValueTooLarge,
    #[error("unexpected end of expression")]
    UnexpectedEnd,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("unmatched parenthesis")]
    UnmatchedParenthesis,
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

/// Decodes a hexadecimal string.
fn parse_auth_hex(s: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = hex::decode(s).map_err(|_| ParseError::InvalidHexString(s.to_string()))?;
    if bytes.len() > MAX_AUTH_SIZE {
        return Err(ParseError::ValueTooLarge);
    }
    Ok(bytes)
}

impl Default for Auth {
    /// Creates a default `Auth` instance representing an empty password.
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
    type Err = ParseError;

    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        let (prefix, value) = auth_str
            .split_once(':')
            .ok_or_else(|| ParseError::InvalidAuthString(auth_str.to_string()))?;

        match prefix {
            "password" => Ok(Self::Password(parse_auth_hex(value)?)),
            "policy" => Ok(Self::Policy(parse_auth_hex(value)?)),
            "vtpm" => {
                let handle_val = u32::from_str_radix(value, 16)
                    .map_err(|_| ParseError::InvalidHexString(value.to_string()))?;
                let ht_byte = (handle_val >> 24) as u8;
                let ht = TpmHt::try_from(ht_byte)
                    .map_err(|()| ParseError::InvalidHandleType(ht_byte))?;

                match ht {
                    TpmHt::PolicySession | TpmHt::HmacSession => Ok(Self::Session(handle_val)),
                    _ => Err(ParseError::InvalidAuthString(auth_str.to_string())),
                }
            }
            _ => Err(ParseError::InvalidAuthString(auth_str.to_string())),
        }
    }
}

/// Handle types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleClass {
    Tpm,
    Vtpm,
}

/// TPM and vTPM handles, with support for pattern matching.
///
/// A `Handle` can represent either a single, specific handle (e.g., `tpm:81000001`)
/// or a pattern for matching multiple handles (e.g., `tpm:81*`, `vtpm:????????`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    raw: String,
    class: HandleClass,
    mask: u32,
    value: u32,
}

impl Handle {
    /// Returns the class of the handle (`Tpm` or `Vtpm`).
    #[must_use]
    pub fn class(&self) -> HandleClass {
        self.class
    }

    /// Returns the value of the handle if it represents a single handle.
    ///
    /// Returns `Some(value)` if the handle was created without wildcards.
    /// Returns `None` if the handle is a pattern.
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
        write!(f, "{}", self.raw)
    }
}

impl FromStr for Handle {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme_str, value_str) = s
            .split_once(':')
            .ok_or_else(|| ParseError::InvalidHandleString(s.to_string()))?;

        let class = match scheme_str {
            "tpm" => HandleClass::Tpm,
            "vtpm" => HandleClass::Vtpm,
            _ => return Err(ParseError::InvalidHandleString(s.to_string())),
        };

        if value_str == "*" {
            return Ok(Self {
                raw: s.to_string(),
                class,
                mask: 0,
                value: 0,
            });
        }

        let mut mask: u32 = 0;
        let mut value: u32 = 0;

        let (prefix_str, suffix_str) = if let Some((p, suffix)) = value_str.split_once('*') {
            if suffix.contains('*') {
                return Err(ParseError::HandleTooManyAsterisks);
            }
            if p.len() + suffix.len() > 8 {
                return Err(ParseError::HandleTooManyDigits);
            }
            (p, suffix)
        } else {
            if value_str.len() < 8 {
                return Err(ParseError::HandleTooFewDigits);
            }
            if value_str.len() > 8 {
                return Err(ParseError::HandleTooManyDigits);
            }
            (value_str, "")
        };

        for (i, c) in prefix_str.chars().enumerate() {
            let shift = (7 - i) * 4;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => return Err(ParseError::InvalidHandleString(value_str.to_string())),
            }
        }

        for (i, c) in suffix_str.chars().rev().enumerate() {
            let shift = i * 4;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => return Err(ParseError::InvalidHandleString(value_str.to_string())),
            }
        }

        Ok(Self {
            raw: s.to_string(),
            class,
            mask,
            value,
        })
    }
}

impl TryFrom<Handle> for TpmHt {
    type Error = ParseError;

    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        let raw_handle = handle
            .value()
            .ok_or_else(|| ParseError::InvalidHandleString(handle.to_string()))?;
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|()| ParseError::InvalidHandleType(ht_byte))
    }
}

/// Represents a user's selection of PCR indices for a specific bank.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcrSelection {
    pub alg: TpmAlgId,
    pub indices: Vec<u32>,
}

impl fmt::Display for PcrSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let indices_str = self
            .indices
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}:{}", Tpm2shAlgId(self.alg), indices_str)
    }
}

/// A newtype wrapper to provide a project-specific `Display` implementation for `TpmAlgId`.
#[derive(Debug, Clone, Copy)]
pub struct Tpm2shAlgId(pub TpmAlgId);

impl TryFrom<&str> for Tpm2shAlgId {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let alg_id = match s {
            "sha1" => TpmAlgId::Sha1,
            "sha256" => TpmAlgId::Sha256,
            "sha384" => TpmAlgId::Sha384,
            "sha512" => TpmAlgId::Sha512,
            _ => {
                return Err(ParseError::InvalidPcrSelectionString(format!(
                    "unsupported algorithm '{s}'"
                )))
            }
        };
        Ok(Self(alg_id))
    }
}

impl std::fmt::Display for Tpm2shAlgId {
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

fn pcr_selection_vec_from_str(selection_str: &str) -> Result<Vec<PcrSelection>, ParseError> {
    selection_str
        .split('+')
        .map(|part| {
            let (alg_str, indices_str) = part
                .split_once(':')
                .ok_or_else(|| ParseError::InvalidPcrSelectionString(part.to_string()))?;

            let alg = Tpm2shAlgId::try_from(alg_str)?.0;

            let indices: Vec<u32> = indices_str
                .split(',')
                .map(|s| {
                    s.parse::<u32>()
                        .map_err(|_| ParseError::InvalidInteger(s.to_string()))
                })
                .collect::<Result<_, _>>()?;

            Ok(PcrSelection { alg, indices })
        })
        .collect()
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

fn parse_expression(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    parse_or(tokens)
}

fn parse_or(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    let mut node = parse_and(tokens)?;
    while let Some(Token::Or) = tokens.peek() {
        tokens.next();
        let rhs = parse_and(tokens)?;
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

fn parse_and(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    let mut node = parse_primary(tokens)?;
    while let Some(Token::And) = tokens.peek() {
        tokens.next();
        let rhs = parse_primary(tokens)?;
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

fn parse_primary(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    let token = tokens.next().ok_or(ParseError::UnexpectedEnd)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(ParseError::UnmatchedParenthesis);
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => parse_pcr_call(tokens),
            "secret" => parse_secret_call(tokens),
            _ => parse_literal(name),
        },
        _ => Err(ParseError::UnexpectedToken(token.to_string())),
    }
}

fn parse_literal(s: &str) -> Result<Expression, ParseError> {
    if let Ok(auth) = Auth::from_str(s) {
        Ok(Expression::Auth(auth))
    } else if let Ok(handle) = Handle::from_str(s) {
        Ok(Expression::Handle(handle))
    } else {
        Err(ParseError::UnexpectedToken(format!(
            "unrecognized literal '{s}'"
        )))
    }
}

fn parse_call_args(
    tokens: &mut Peekable<Iter<'_, Token<'_>>>,
) -> Result<Vec<Expression>, ParseError> {
    match tokens.peek() {
        Some(&&Token::LParen) => {
            tokens.next();
        }
        Some(actual_token) => {
            return Err(ParseError::UnexpectedToken(format!(
                "Expected '(' to start argument list, found {actual_token}"
            )));
        }
        None => {
            return Err(ParseError::UnexpectedEnd);
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
                return Err(ParseError::UnexpectedToken(format!(
                    "Expected ',' or ')' in argument list, found {actual_token}"
                )));
            }
            None => return Err(ParseError::UnmatchedParenthesis),
        }
    }
    Ok(args)
}

fn parse_pcr_call(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    if tokens.next() != Some(&Token::LParen) {
        return Err(ParseError::UnexpectedToken(
            "expected '(' after 'pcr'".to_string(),
        ));
    }

    let pcr_string = match tokens.next() {
        Some(Token::Ident(s)) => s,
        Some(other) => {
            return Err(ParseError::UnexpectedToken(format!(
                "expected PCR selection string, found {other}"
            )))
        }
        None => return Err(ParseError::UnexpectedEnd),
    };

    if tokens.next() != Some(&Token::RParen) {
        return Err(ParseError::UnmatchedParenthesis);
    }

    let (selection_part, digest_part): (&str, Option<String>) =
        if let Some((selection, digest)) = pcr_string.rsplit_once(':') {
            if hex::decode(digest).is_ok() && digest.len() > 10 {
                (selection, Some(digest.to_string()))
            } else {
                (pcr_string, None)
            }
        } else {
            (pcr_string, None)
        };

    let selections = pcr_selection_vec_from_str(selection_part)?;
    Ok(Expression::Pcr {
        selections,
        digest: digest_part,
        count: None,
    })
}

fn parse_secret_call(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, ParseError> {
    let args = parse_call_args(tokens)?;
    if args.is_empty() || args.len() > 3 {
        return Err(ParseError::UnexpectedToken(
            "secret() expects 1 to 3 arguments".to_string(),
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

impl Expression {
    /// Parses a policy expression string into an `Expression` AST.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidAuthString`] when an auth literal is malformed.
    /// Returns [`ParseError::InvalidHandleString`] when a handle literal is malformed.
    /// Returns [`ParseError::InvalidPcrSelectionString`] when a `pcr()` argument is malformed.
    /// Returns [`ParseError::UnexpectedEnd`] when the expression ends prematurely.
    /// Returns [`ParseError::UnexpectedToken`] when an unexpected token is found.
    /// Returns [`ParseError::UnmatchedParenthesis`] when parentheses are mismatched.
    pub fn new(input: &str) -> Result<Expression, ParseError> {
        let tokens = tokenize(input);
        let mut iter = tokens.iter().peekable();
        let expr = parse_expression(&mut iter)?;

        if iter.peek().is_some() {
            return Err(ParseError::UnexpectedToken(
                "trailing data after expression".to_string(),
            ));
        }

        Ok(expr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::data::TpmAlgId;

    #[test]
    fn test_complex_expression() {
        let input = "pcr(sha256:16) or (pcr(sha256:7)) and secret(tpm:81000001)";
        let ast = Expression::new(input).unwrap();

        let expected = Expression::Or(vec![
            Expression::Pcr {
                selections: vec![PcrSelection {
                    alg: TpmAlgId::Sha256,
                    indices: vec![16],
                }],
                digest: None,
                count: None,
            },
            Expression::And(vec![
                Expression::Pcr {
                    selections: vec![PcrSelection {
                        alg: TpmAlgId::Sha256,
                        indices: vec![7],
                    }],
                    digest: None,
                    count: None,
                },
                Expression::Secret {
                    auth_handle: Box::new(Expression::Handle(
                        "tpm:81000001".parse::<Handle>().unwrap(),
                    )),
                    password: None,
                    cp_hash: None,
                },
            ]),
        ]);

        assert_eq!(ast, expected);
    }

    #[test]
    fn test_simple_or() {
        let input = "pcr(sha256:7) or pcr(sha256:15)";
        let ast = Expression::new(input).unwrap();

        let expected = Expression::Or(vec![
            Expression::Pcr {
                selections: vec![PcrSelection {
                    alg: TpmAlgId::Sha256,
                    indices: vec![7],
                }],
                digest: None,
                count: None,
            },
            Expression::Pcr {
                selections: vec![PcrSelection {
                    alg: TpmAlgId::Sha256,
                    indices: vec![15],
                }],
                digest: None,
                count: None,
            },
        ]);

        assert_eq!(ast, expected);
    }

    #[test]
    fn test_pcr_with_digest() {
        let digest_str = "01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962";
        let input = format!("pcr(sha256:7:{digest_str})");
        let ast = Expression::new(&input).unwrap();

        let expected = Expression::Pcr {
            selections: vec![PcrSelection {
                alg: TpmAlgId::Sha256,
                indices: vec![7],
            }],
            digest: Some(digest_str.to_string()),
            count: None,
        };

        assert_eq!(ast, expected);
    }
}
