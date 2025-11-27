// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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

pub mod error;
pub mod expression;

pub use error::*;
pub use expression::*;

use std::{collections::HashMap, fmt, iter::Peekable, slice::Iter};

use tpm2_crypto::TpmHash;
use tpm2_protocol::{
    basic::TpmHandle,
    constant::TPM_PCR_SELECT_MAX,
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmHt, TpmlPcrSelection,
        TpmsPcrSelect, TpmsPcrSelection,
    },
    frame::{TpmPolicyOrCommand, TpmPolicyPcrCommand},
    TpmMarshal, TpmSized, TpmWriter,
};

/// Pre-resolved data needed for policy execution.
///
/// This structure must be populated by the caller and passed to
/// [`Expression::to_command_list()`].
#[derive(Debug, Clone, Default)]
pub struct TpmPolicyState {
    names: HashMap<TpmHandle, Tpm2bName>,
    pcrs: HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>>,
    pcr_count: usize,
}

impl TpmPolicyState {
    /// Initialize and return a new instace.
    ///
    /// # Errors
    ///
    /// Returns [`PcrCountMismatch`](crate::TpmPolicyError::PcrCountMismatch) when
    /// PCR banks don't have exact same amount of PCRs.
    pub fn new(
        names: HashMap<TpmHandle, Tpm2bName>,
        pcrs: HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>>,
    ) -> Result<Self, TpmPolicyError> {
        let mut pcr_count = 0;

        for bank in pcrs.values() {
            if pcr_count == 0 {
                pcr_count = bank.len();
            }

            if pcr_count != bank.len() {
                return Err(TpmPolicyError::PcrCountMismatch);
            }
        }

        Ok(Self {
            names,
            pcrs,
            pcr_count,
        })
    }

    #[must_use]
    pub fn names(&self) -> &HashMap<TpmHandle, Tpm2bName> {
        &self.names
    }
}

/// Parses a PCR selection string (e.g., "sha1:0,1+sha256:7") into a
/// `TpmlPcrSelection` using context from the `PolicyState`.
fn parse_tpml_pcr_selection_str(
    selection_str: &str,
    context: &TpmPolicyState,
) -> Result<TpmlPcrSelection, TpmPolicyError> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = context.pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX as usize {
        return Err(TpmPolicyError::PcrSelectionTooLarge);
    }

    for part in selection_str.split('+') {
        let (alg_str, indices_str) = part
            .split_once(':')
            .ok_or(TpmPolicyError::InvalidPcrSelection)?;

        let alg = alg_str
            .parse::<TpmHash>()
            .map_err(|_| TpmPolicyError::InvalidPcrDigestAlgorithm)?;

        if !context.pcrs.contains_key(&alg.into()) {
            return Err(TpmPolicyError::PcrBankNotAvailable(alg));
        }

        let indices: Vec<u32> = indices_str
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| TpmPolicyError::InvalidPcrSelection)?;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= context.pcr_count {
                return Err(TpmPolicyError::PcrIndexTooLarge);
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.try_push(TpmsPcrSelection {
            hash: alg.into(),
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())
                .map_err(|_| TpmPolicyError::PcrDigestTooLarge)?,
        })
        .map_err(|_| TpmPolicyError::PcrSelectionTooLarge)?;
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
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    parse_or(tokens, context)
}

fn parse_binary_expression<'a, F, G>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    mut operand_parser: F,
    operator: &Token,
    mut expression_combiner: G,
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError>
where
    F: FnMut(
        &mut Peekable<Iter<'a, Token<'a>>>,
        &TpmPolicyState,
    ) -> Result<TpmPolicyExpression, TpmPolicyError>,
    G: FnMut(TpmPolicyExpression, TpmPolicyExpression) -> TpmPolicyExpression,
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
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    parse_binary_expression(
        tokens,
        parse_and,
        &Token::Or,
        |lhs, rhs| match lhs {
            TpmPolicyExpression::Or(mut terms) => {
                terms.push(rhs);
                TpmPolicyExpression::Or(terms)
            }
            _ => TpmPolicyExpression::Or(vec![lhs, rhs]),
        },
        context,
    )
}

fn parse_and<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    parse_binary_expression(
        tokens,
        parse_primary,
        &Token::And,
        |lhs, rhs| match lhs {
            TpmPolicyExpression::And(mut factors) => {
                factors.push(rhs);
                TpmPolicyExpression::And(factors)
            }
            _ => TpmPolicyExpression::And(vec![lhs, rhs]),
        },
        context,
    )
}

fn parse_primary<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    let token = tokens.next().ok_or(TpmPolicyError::UnexpectedEnd)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens, context)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(TpmPolicyError::ParenthesisMismatch);
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => Ok(parse_pcr_call(tokens, context)?),
            "secret" => Ok(parse_secret_call(tokens, context)?),
            _ => parse_literal(name),
        },
        _ => Err(TpmPolicyError::InvalidToken(token.to_string())),
    }
}

fn parse_literal(s: &str) -> Result<TpmPolicyExpression, TpmPolicyError> {
    if s.len() != 8 {
        return Err(TpmPolicyError::InvalidToken(s.to_string()));
    }

    let raw =
        u32::from_str_radix(s, 16).map_err(|_| TpmPolicyError::InvalidToken(s.to_string()))?;

    let ht_byte = (raw >> 24) as u8;
    TpmHt::try_from(ht_byte).map_err(|_| TpmPolicyError::InvalidHandleType(ht_byte))?;

    Ok(TpmPolicyExpression::Handle(TpmHandle::from(raw)))
}

fn parse_pcr_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    match tokens.next() {
        Some(Token::LParen) => {}
        Some(actual_token) => {
            return Err(TpmPolicyError::InvalidToken(actual_token.to_string()));
        }
        None => {
            return Err(TpmPolicyError::UnexpectedEnd);
        }
    }

    let mut buf = String::new();
    loop {
        match tokens.next() {
            Some(Token::RParen) => break,
            Some(Token::Ident(s)) => buf.push_str(s),
            Some(Token::Comma) => buf.push(','),
            Some(tok @ (Token::And | Token::Or | Token::LParen)) => {
                return Err(TpmPolicyError::InvalidToken(tok.to_string()));
            }
            None => return Err(TpmPolicyError::UnexpectedEnd),
        }
    }

    if let Some((selection_part, digest_part)) = buf.rsplit_once(':') {
        if let Ok(selections) = parse_tpml_pcr_selection_str(selection_part, context) {
            if let Ok(digest_bytes) = hex::decode(digest_part) {
                if let Ok(digest) = Tpm2bDigest::try_from(digest_bytes.as_slice()) {
                    return Ok(TpmPolicyExpression::Pcr {
                        selections,
                        digest: Some(digest),
                    });
                }
            }
        }
    }

    let selections = parse_tpml_pcr_selection_str(&buf, context)?;
    Ok(TpmPolicyExpression::Pcr {
        selections,
        digest: None,
    })
}

fn parse_secret_call<'a>(
    tokens: &mut Peekable<Iter<'a, Token<'a>>>,
    context: &TpmPolicyState,
) -> Result<TpmPolicyExpression, TpmPolicyError> {
    match tokens.next() {
        Some(Token::LParen) => {}
        Some(actual_token) => {
            return Err(TpmPolicyError::InvalidToken(actual_token.to_string()));
        }
        None => {
            return Err(TpmPolicyError::UnexpectedEnd);
        }
    }

    let auth_handle =
        parse_or(tokens, context).map_err(|e| TpmPolicyError::InvalidToken(e.to_string()))?;

    let copy_ref = match tokens.peek() {
        Some(Token::Comma) => {
            tokens.next();

            let copy_ref_ident = match tokens.next() {
                Some(Token::Ident(s)) => s,
                Some(actual_token) => {
                    return Err(TpmPolicyError::InvalidToken(actual_token.to_string()));
                }
                None => {
                    return Err(TpmPolicyError::UnexpectedEnd);
                }
            };

            let (key, value) = copy_ref_ident
                .split_once(':')
                .ok_or_else(|| TpmPolicyError::InvalidToken((*copy_ref_ident).to_string()))?;

            if key != "copy_ref" {
                return Err(TpmPolicyError::InvalidToken((*copy_ref_ident).to_string()));
            }

            let bytes = hex::decode(value)
                .map_err(|_| TpmPolicyError::InvalidToken((*copy_ref_ident).to_string()))?;

            if bytes.is_empty() {
                None
            } else {
                let digest = Tpm2bDigest::try_from(bytes.as_slice())
                    .map_err(|_| TpmPolicyError::InvalidToken((*copy_ref_ident).to_string()))?;
                Some(digest)
            }
        }
        Some(Token::RParen) => None,
        Some(actual_token) => {
            return Err(TpmPolicyError::InvalidToken(actual_token.to_string()));
        }
        None => {
            return Err(TpmPolicyError::UnexpectedEnd);
        }
    };

    match tokens.next() {
        Some(Token::RParen) => {}
        Some(actual_token) => {
            return Err(TpmPolicyError::InvalidToken(actual_token.to_string()));
        }
        None => {
            return Err(TpmPolicyError::UnexpectedEnd);
        }
    }

    Ok(TpmPolicyExpression::Secret {
        auth_handle: Box::new(auth_handle),
        copy_ref,
    })
}

/// A session that simulates TPM policy digest calculations in software.
struct TpmPolicySession {
    digest: Tpm2bDigest,
    hash_alg: TpmAlgId,
    digest_size: usize,
}

impl TpmPolicySession {
    /// Creates a new software policy session.
    fn new(hash_alg: TpmAlgId) -> Result<Self, TpmPolicyError> {
        let digest_size = TpmHash::from(hash_alg).size();
        let digest = Tpm2bDigest::try_from(vec![0; digest_size].as_slice())
            .map_err(TpmPolicyError::Marshal)?;
        Ok(Self {
            digest,
            hash_alg,
            digest_size,
        })
    }

    /// Applies a `TPM2_PolicyPCR` action to the session.
    fn policy_pcr(&mut self, cmd: &TpmPolicyPcrCommand) -> Result<(), TpmPolicyError> {
        let mut pcrs_bytes = vec![0u8; TpmlPcrSelection::SIZE];
        let pcrs_bytes_len = {
            let mut writer = TpmWriter::new(&mut pcrs_bytes);
            cmd.pcrs
                .marshal(&mut writer)
                .map_err(TpmPolicyError::Marshal)?;
            writer.len()
        };
        pcrs_bytes.truncate(pcrs_bytes_len);

        let cc_bytes = (TpmCc::PolicyPcr as u32).to_be_bytes();
        let chunks: Vec<&[u8]> = vec![
            self.digest.as_ref(),
            &cc_bytes,
            &pcrs_bytes,
            cmd.pcr_digest.as_ref(),
        ];

        let new_digest_bytes = TpmHash::from(self.hash_alg)
            .digest(&chunks)
            .map_err(TpmPolicyError::Crypto)?;
        self.digest =
            Tpm2bDigest::try_from(new_digest_bytes.as_slice()).map_err(TpmPolicyError::Marshal)?;
        Ok(())
    }

    /// Applies a `TPM2_PolicyOR` action to the session.
    fn policy_or(&mut self, cmd: &TpmPolicyOrCommand) -> Result<(), TpmPolicyError> {
        let mut digests_as_bytes = Vec::with_capacity(cmd.p_hash_list.len() * self.digest_size);
        for digest in cmd.p_hash_list.iter() {
            digests_as_bytes.extend_from_slice(digest.as_ref());
        }

        let zero_digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(TpmPolicyError::Marshal)?;
        self.digest = zero_digest;

        let cc_bytes = (TpmCc::PolicyOr as u32).to_be_bytes();
        let chunks: Vec<&[u8]> = vec![self.digest.as_ref(), &cc_bytes, digests_as_bytes.as_slice()];

        let new_digest_bytes = TpmHash::from(self.hash_alg)
            .digest(&chunks)
            .map_err(TpmPolicyError::Crypto)?;
        self.digest =
            Tpm2bDigest::try_from(new_digest_bytes.as_slice()).map_err(TpmPolicyError::Marshal)?;
        Ok(())
    }

    /// Applies a `TPM2_PolicySecret` action to the session.
    fn policy_secret(
        &mut self,
        auth_handle_name: &Tpm2bName,
        policy_ref: &Tpm2bNonce,
    ) -> Result<(), TpmPolicyError> {
        let cc_bytes = (TpmCc::PolicySecret as u32).to_be_bytes();

        let first_chunks: Vec<&[u8]> =
            vec![self.digest.as_ref(), &cc_bytes, auth_handle_name.as_ref()];

        let first_digest_bytes = TpmHash::from(self.hash_alg)
            .digest(&first_chunks)
            .map_err(TpmPolicyError::Crypto)?;
        let first_digest = Tpm2bDigest::try_from(first_digest_bytes.as_slice())
            .map_err(TpmPolicyError::Marshal)?;

        let second_chunks: Vec<&[u8]> = vec![first_digest.as_ref(), policy_ref.as_ref()];

        let new_digest_bytes = TpmHash::from(self.hash_alg)
            .digest(&second_chunks)
            .map_err(TpmPolicyError::Crypto)?;
        self.digest =
            Tpm2bDigest::try_from(new_digest_bytes.as_slice()).map_err(TpmPolicyError::Marshal)?;
        Ok(())
    }

    /// Applies a `TPM2_PolicyRestart` action to the session.
    fn policy_restart(&mut self) -> Result<(), TpmPolicyError> {
        self.digest = Tpm2bDigest::try_from(vec![0; self.digest_size].as_slice())
            .map_err(TpmPolicyError::Marshal)?;
        Ok(())
    }

    /// Retrieves the final policy digest from the session.
    fn get_digest(&self) -> Tpm2bDigest {
        self.digest
    }
}

/// Conditionally wraps a list of expressions in `Expression::And`.
/// If the list contains exactly one item, it is returned directly.
fn build_and_branch(mut branch: Vec<TpmPolicyExpression>) -> TpmPolicyExpression {
    if branch.len() == 1 {
        match branch.pop() {
            Some(expr) => expr,
            None => TpmPolicyExpression::And(Vec::new()),
        }
    } else {
        TpmPolicyExpression::And(branch)
    }
}
