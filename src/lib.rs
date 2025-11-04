//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

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

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod auth;
pub mod error;
pub mod expression;
pub mod handle;

pub use self::error::*;
pub use auth::*;
pub use expression::*;
pub use handle::*;

use std::{collections::HashMap, fmt, iter::Peekable, slice::Iter};
use tpm2_crypto::{digest as crypto_digest, hash_size as crypto_hash_size};
use tpm2_protocol::{
    constant::TPM_PCR_SELECT_MAX,
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmlPcrSelection, TpmsPcrSelect,
        TpmsPcrSelection,
    },
    frame::{TpmPolicyOrCommand, TpmPolicyPcrCommand},
    TpmMarshal, TpmSized, TpmWriter,
};

/// Pre-resolved data needed for policy execution.
///
/// This structure must be populated by the caller and passed to
/// [`Expression::to_command_list()`].
#[derive(Debug, Clone, Default)]
pub struct PolicyState {
    /// Number of PCRs.
    pub pcr_count: usize,
    /// List of available PCR banks.
    pub pcr_banks: Vec<TpmAlgId>,
    /// Map of persistent handle values to their TPM names.
    pub names: HashMap<u32, Tpm2bName>,
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
            _ => return Err(CommandError::InvalidAlgorithm(s.to_string()).into()),
        };
        Ok(Self(alg_id))
    }
}

impl std::fmt::Display for PolicyAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

/// Parses a PCR selection string (e.g., "sha1:0,1+sha256:7") into a
/// `TpmlPcrSelection` using context from the `PolicyState`.
fn parse_tpml_pcr_selection_str(
    selection_str: &str,
    context: &PolicyState,
) -> Result<TpmlPcrSelection, Error> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = context.pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX as usize {
        return Err(PcrError::TooLargeSelection(pcr_select_size).into());
    }

    for part in selection_str.split('+') {
        let (alg_str, indices_str) = part
            .split_once(':')
            .ok_or_else(|| PcrError::InvalidSelectionString(part.to_string()))?;

        let alg = PolicyAlgId::try_from(alg_str)?.0;
        if !context.pcr_banks.contains(&alg) {
            return Err(PcrError::MissingBank(alg).into());
        }

        let indices: Vec<u32> = indices_str
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| PcrError::InvalidSelectionString(part.to_string()))?;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= context.pcr_count {
                return Err(PcrError::TooLargeIndex(pcr_index).into());
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.push(TpmsPcrSelection {
            hash: alg,
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())
                .map_err(|_| PcrError::TooLargeSelection(pcr_select_bytes.len()))?,
        })
        .map_err(|_| PcrError::TooLargeSelection(list.len()))?;
    }
    Ok(list)
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
    context: &PolicyState,
) -> Result<Expression, ExpressionError> {
    parse_or(tokens, context)
}

fn parse_binary_expression<'a, F, G>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    mut operand_parser: F,
    operator: &Token,
    mut expression_combiner: G,
    context: &PolicyState,
) -> Result<Expression, ExpressionError>
where
    F: FnMut(
        &mut Peekable<Iter<'a, Token<'a>>>,
        &PolicyState,
    ) -> Result<Expression, ExpressionError>,
    G: FnMut(Expression, Expression) -> Expression,
{
    let mut node = operand_parser(tokens, context)?;
    while tokens.peek() == Some(&operator) {
        tokens.next();
        let rhs = operand_parser(tokens, context)?;
        node = expression_combiner(node, rhs);
    }
    Ok(node)
}

fn parse_or<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, ExpressionError> {
    parse_binary_expression(
        tokens,
        parse_and,
        &Token::Or,
        |lhs, rhs| match lhs {
            Expression::Or(mut terms) => {
                terms.push(rhs);
                Expression::Or(terms)
            }
            _ => Expression::Or(vec![lhs, rhs]),
        },
        context,
    )
}

fn parse_and<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, ExpressionError> {
    parse_binary_expression(
        tokens,
        parse_primary,
        &Token::And,
        |lhs, rhs| match lhs {
            Expression::And(mut factors) => {
                factors.push(rhs);
                Expression::And(factors)
            }
            _ => Expression::And(vec![lhs, rhs]),
        },
        context,
    )
}

fn parse_primary<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, ExpressionError> {
    let token = tokens.next().ok_or(ExpressionError::UnexpectedEnd)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens, context)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(ExpressionError::ParenthesisMismatch);
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => parse_pcr_call(tokens, context),
            "secret" => parse_secret_call(tokens, context),
            _ => parse_literal(name),
        },
        _ => Err(ExpressionError::UnexpectedToken(token.to_string())),
    }
}

fn parse_literal(s: &str) -> Result<Expression, ExpressionError> {
    use std::str::FromStr;
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
    context: &PolicyState,
) -> Result<Vec<Expression>, ExpressionError> {
    match tokens.next() {
        Some(Token::LParen) => {}
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
        args.push(parse_or(tokens, context)?);

        match tokens.next() {
            Some(Token::RParen) => break,
            Some(Token::Comma) => {}
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
    context: &PolicyState,
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

    let mut selection_result = parse_tpml_pcr_selection_str(&buf, context);

    if let Ok(selections) = selection_result {
        return Ok(Expression::Pcr {
            selections,
            digest: None,
            count: None,
        });
    }

    if let Some((selection_part, digest_part)) = buf.rsplit_once(':') {
        let selection_with_digest_result = parse_tpml_pcr_selection_str(selection_part, context);

        if let Ok(selections) = selection_with_digest_result {
            hex::decode(digest_part)
                .map_err(|_| ExpressionError::InvalidDigestString(digest_part.to_string()))?;

            return Ok(Expression::Pcr {
                selections,
                digest: Some(digest_part.to_string()),
                count: None,
            });
        }
        selection_result = selection_with_digest_result;
    }

    Err(match selection_result.unwrap_err() {
        Error::Pcr(pcr_err) => pcr_err.into(),
        other => ExpressionError::UnexpectedToken(other.to_string()),
    })
}

fn parse_secret_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, ExpressionError> {
    let args = parse_call_args(tokens, context)?;
    if args.is_empty() || args.len() > 3 {
        return Err(SecretError::ArgumentCount.into());
    }

    let mut arg_iter = args.into_iter();
    let auth_handle = if let Some(handle) = arg_iter.next() {
        Box::new(handle)
    } else {
        return Err(SecretError::ArgumentCount.into());
    };
    let password = arg_iter.next().map(Box::new);
    let cp_hash = arg_iter.next().map(|expr| expr.to_string());

    Ok(Expression::Secret {
        auth_handle,
        password,
        cp_hash,
    })
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

    let new_digest_bytes = crypto_digest(hash_alg, &chunks).map_err(CommandError::from)?;
    *current_digest = Tpm2bDigest::try_from(new_digest_bytes.as_slice())
        .map_err(|_| CommandError::InvalidDigestSize(new_digest_bytes.len()))?;
    Ok(())
}

impl SoftwarePolicySession {
    /// Creates a new software policy session.
    fn new(hash_alg: TpmAlgId) -> Result<Self, Error> {
        let digest_size = crypto_hash_size(hash_alg).map_err(CommandError::from)?;
        let digest = Tpm2bDigest::try_from(vec![0; digest_size].as_slice())
            .map_err(|_| CommandError::InvalidDigestSize(digest_size))?;
        Ok(Self {
            digest,
            hash_alg,
            digest_size,
        })
    }

    /// Applies a `TPM2_PolicyPCR` action to the session.
    fn policy_pcr(&mut self, cmd: &TpmPolicyPcrCommand) -> Result<(), Error> {
        let mut pcrs_bytes = vec![0u8; TpmlPcrSelection::SIZE];
        let pcrs_bytes_len = {
            let mut writer = TpmWriter::new(&mut pcrs_bytes);
            cmd.pcrs.marshal(&mut writer).map_err(PcrError::from)?;
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
            .map_err(|_| CommandError::InvalidDigestSize(self.digest_size))?;

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyOR,
            &[&digests_as_bytes],
        )
    }

    /// Applies a `TPM2_PolicySecret` action to the session.
    fn policy_secret(&mut self, auth_handle_name: &Tpm2bName) -> Result<(), Error> {
        let policy_ref = Tpm2bNonce::default();
        let cc_bytes = (TpmCc::PolicySecret as u32).to_be_bytes();

        let intermediate_digest_bytes = crypto_digest(
            self.hash_alg,
            &[self.digest.as_ref(), &cc_bytes, auth_handle_name.as_ref()],
        )
        .map_err(CommandError::from)?;

        let final_digest_bytes = crypto_digest(
            self.hash_alg,
            &[&intermediate_digest_bytes, policy_ref.as_ref()],
        )
        .map_err(CommandError::from)?;

        self.digest = Tpm2bDigest::try_from(final_digest_bytes.as_slice())
            .map_err(|_| CommandError::InvalidDigestSize(final_digest_bytes.len()))?;

        Ok(())
    }

    /// Applies a `TPM2_PolicyRestart` action to the session.
    fn policy_restart(&mut self) -> Result<(), Error> {
        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(|_| CommandError::InvalidDigestSize(self.digest_size))?;
        Ok(())
    }

    /// Retrieves the final policy digest from the session.
    fn get_digest(&self) -> Tpm2bDigest {
        self.digest
    }
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
