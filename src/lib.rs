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

pub use self::error::{Error, LanguageError};
pub use auth::*;
pub use expression::*;
pub use handle::*;

use std::{collections::HashMap, fmt, iter::Peekable, slice::Iter};
use tpm2_crypto::Hash;
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

/// Parses a PCR selection string (e.g., "sha1:0,1+sha256:7") into a
/// `TpmlPcrSelection` using context from the `PolicyState`.
fn parse_tpml_pcr_selection_str(
    selection_str: &str,
    context: &PolicyState,
) -> Result<TpmlPcrSelection, LanguageError> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = context.pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX as usize {
        return Err(LanguageError::PcrSelectionTooLarge);
    }

    for part in selection_str.split('+') {
        let (alg_str, indices_str) = part
            .split_once(':')
            .ok_or(LanguageError::InvalidPcrSelection)?;

        let alg = alg_str
            .parse::<Hash>()
            .map_err(|_| LanguageError::InvalidPcrDigestAlgorithm)?;
        if !context.pcr_banks.contains(&alg.into()) {
            return Err(LanguageError::PcrBankNotAvailable(alg));
        }

        let indices: Vec<u32> = indices_str
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| LanguageError::InvalidPcrSelection)?;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= context.pcr_count {
                return Err(LanguageError::PcrIndexTooLarge);
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.push(TpmsPcrSelection {
            hash: alg.into(),
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())
                .map_err(|_| LanguageError::PcrDigestTooLarge)?,
        })
        .map_err(|_| LanguageError::PcrSelectionTooLarge)?;
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
) -> Result<Expression, Error> {
    parse_or(tokens, context)
}

fn parse_binary_expression<'a, F, G>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    mut operand_parser: F,
    operator: &Token,
    mut expression_combiner: G,
    context: &PolicyState,
) -> Result<Expression, Error>
where
    F: FnMut(&mut Peekable<Iter<'a, Token<'a>>>, &PolicyState) -> Result<Expression, Error>,
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
) -> Result<Expression, Error> {
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
) -> Result<Expression, Error> {
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
) -> Result<Expression, Error> {
    let token = tokens.next().ok_or(LanguageError::UnexpectedEnd)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens, context)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(LanguageError::ParenthesisMismatch.into());
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => Ok(parse_pcr_call(tokens, context)?),
            "secret" => parse_secret_call(tokens, context),
            _ => parse_literal(name),
        },
        _ => Err(LanguageError::InvalidToken(token.to_string()).into()),
    }
}

fn parse_literal(s: &str) -> Result<Expression, Error> {
    use std::str::FromStr;
    if let Ok(auth) = Auth::from_str(s) {
        Ok(Expression::Auth(auth))
    } else if let Ok(handle) = Handle::from_str(s) {
        Ok(Expression::Handle(handle))
    } else {
        Err(LanguageError::InvalidToken(s.to_string()).into())
    }
}

fn parse_call_args<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Vec<Expression>, Error> {
    match tokens.next() {
        Some(Token::LParen) => {}
        Some(actual_token) => {
            return Err(LanguageError::InvalidToken(actual_token.to_string()).into());
        }
        None => {
            return Err(LanguageError::UnexpectedEnd.into());
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
                return Err(LanguageError::InvalidToken(actual_token.to_string()).into());
            }
            None => return Err(LanguageError::ParenthesisMismatch.into()),
        }
    }
    Ok(args)
}

fn parse_pcr_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, LanguageError> {
    match tokens.next() {
        Some(Token::LParen) => {}
        Some(actual_token) => {
            return Err(LanguageError::InvalidToken(actual_token.to_string()));
        }
        None => {
            return Err(LanguageError::UnexpectedEnd);
        }
    }

    let mut buf = String::new();
    loop {
        match tokens.next() {
            Some(Token::RParen) => break,
            Some(Token::Ident(s)) => buf.push_str(s),
            Some(Token::Comma) => buf.push(','),
            Some(tok @ (Token::And | Token::Or | Token::LParen)) => {
                return Err(LanguageError::InvalidToken(tok.to_string()));
            }
            None => return Err(LanguageError::UnexpectedEnd),
        }
    }

    match parse_tpml_pcr_selection_str(&buf, context) {
        Ok(selections) => Ok(Expression::Pcr {
            selections,
            digest: None,
            count: None,
        }),
        Err(err) => {
            if let Some((selection_part, digest_part)) = buf.rsplit_once(':') {
                let selections = parse_tpml_pcr_selection_str(selection_part, context)?;
                hex::decode(digest_part).map_err(|_| LanguageError::InvalidPcrDigest)?;
                Ok(Expression::Pcr {
                    selections,
                    digest: Some(digest_part.to_string()),
                    count: None,
                })
            } else {
                Err(err)
            }
        }
    }
}

fn parse_secret_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &PolicyState,
) -> Result<Expression, Error> {
    let args = parse_call_args(tokens, context)?;

    if args.is_empty() || args.len() > 2 {
        return Err(LanguageError::InvalidSecretCall.into());
    }

    let mut arg_iter = args.into_iter();
    let auth_handle = if let Some(handle) = arg_iter.next() {
        Box::new(handle)
    } else {
        return Err(LanguageError::InvalidSecretCall.into());
    };
    let password = arg_iter.next().map(Box::new);

    Ok(Expression::Secret {
        auth_handle,
        password,
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
) -> Result<(), LanguageError> {
    let cc_bytes = (cc as u32).to_be_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(2 + params.len());
    chunks.push(current_digest.as_ref());
    chunks.push(&cc_bytes);
    chunks.extend(params.iter());

    let new_digest_bytes = Hash::from(hash_alg)
        .digest(&chunks)
        .map_err(|_| LanguageError::OperationFailed)?;
    *current_digest = Tpm2bDigest::try_from(new_digest_bytes.as_slice())
        .map_err(|_| LanguageError::OperationFailed)?;

    Ok(())
}

impl SoftwarePolicySession {
    /// Creates a new software policy session.
    fn new(hash_alg: TpmAlgId) -> Result<Self, LanguageError> {
        let digest_size = Hash::from(hash_alg).size();
        let digest = Tpm2bDigest::try_from(vec![0; digest_size].as_slice())
            .map_err(|_| LanguageError::OperationFailed)?;
        Ok(Self {
            digest,
            hash_alg,
            digest_size,
        })
    }

    /// Applies a `TPM2_PolicyPCR` action to the session.
    fn policy_pcr(&mut self, cmd: &TpmPolicyPcrCommand) -> Result<(), LanguageError> {
        let mut pcrs_bytes = vec![0u8; TpmlPcrSelection::SIZE];
        let pcrs_bytes_len = {
            let mut writer = TpmWriter::new(&mut pcrs_bytes);
            cmd.pcrs
                .marshal(&mut writer)
                .map_err(|_| LanguageError::OperationFailed)?;
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
    fn policy_or(&mut self, cmd: &TpmPolicyOrCommand) -> Result<(), LanguageError> {
        let mut digests_as_bytes = Vec::with_capacity(cmd.p_hash_list.len() * self.digest_size);
        for digest in cmd.p_hash_list.iter() {
            digests_as_bytes.extend_from_slice(digest.as_ref());
        }

        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(|_| LanguageError::OperationFailed)?;

        update_policy_digest(
            &mut self.digest,
            self.hash_alg,
            TpmCc::PolicyOR,
            &[&digests_as_bytes],
        )
    }

    /// Applies a `TPM2_PolicySecret` action to the session.
    fn policy_secret(&mut self, auth_handle_name: &Tpm2bName) -> Result<(), LanguageError> {
        let policy_ref = Tpm2bNonce::default();
        let cc_bytes = (TpmCc::PolicySecret as u32).to_be_bytes();

        let intermediate_digest_bytes = Hash::from(self.hash_alg)
            .digest(&[self.digest.as_ref(), &cc_bytes, auth_handle_name.as_ref()])
            .map_err(|_| LanguageError::OperationFailed)?;

        let final_digest_bytes = Hash::from(self.hash_alg)
            .digest(&[&intermediate_digest_bytes, policy_ref.as_ref()])
            .map_err(|_| LanguageError::OperationFailed)?;

        self.digest = Tpm2bDigest::try_from(final_digest_bytes.as_slice())
            .map_err(|_| LanguageError::OperationFailed)?;

        Ok(())
    }

    /// Applies a `TPM2_PolicyRestart` action to the session.
    fn policy_restart(&mut self) -> Result<(), LanguageError> {
        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(|_| LanguageError::OperationFailed)?;
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
