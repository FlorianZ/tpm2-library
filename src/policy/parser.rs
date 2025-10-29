// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! A stateless, recursive-descent parser for the policy language.

use super::{Auth, Expression, Handle, PolicyError};
use crate::pcr::pcr_selection_vec_from_str;
use std::{fmt, iter::Peekable, slice::Iter, str::FromStr};
use tpm2_crypto::hash_size as crypto_hash_size;
use tpm2_protocol::data::TpmAlgId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token<'a> {
    And,
    Or,
    LParen,
    RParen,
    Comma,
    Ident(&'a str),
}

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

pub(super) fn tokenize(input: &str) -> Vec<Token<'_>> {
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

pub(super) fn parse_expression(
    tokens: &mut Peekable<Iter<'_, Token<'_>>>,
) -> Result<Expression, PolicyError> {
    parse_or(tokens)
}

fn parse_or(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, PolicyError> {
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

fn parse_and(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, PolicyError> {
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

fn parse_primary(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, PolicyError> {
    let token = tokens
        .next()
        .ok_or(PolicyError::UnexpectedEndOfExpression)?;

    match token {
        Token::LParen => {
            let expr = parse_or(tokens)?;
            if tokens.next() != Some(&Token::RParen) {
                return Err(PolicyError::UnmatchedParenthesis);
            }
            Ok(expr)
        }
        Token::Ident(name) => match *name {
            "pcr" => parse_pcr_call(tokens),
            "secret" => parse_secret_call(tokens),
            _ => parse_literal(name),
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

fn parse_call_args(
    tokens: &mut Peekable<Iter<'_, Token<'_>>>,
) -> Result<Vec<Expression>, PolicyError> {
    match tokens.peek() {
        Some(&&Token::LParen) => {
            tokens.next();
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
    if tokens.peek() == Some(&&Token::RParen) {
        tokens.next();
        return Ok(args);
    }

    loop {
        if let Some(Token::Ident(ident)) = tokens.peek() {
            if let Ok(selections) = pcr_selection_vec_from_str(ident) {
                tokens.next();
                args.push(Expression::Pcr {
                    selections,
                    digest: None,
                    count: None,
                });
            } else {
                args.push(parse_or(tokens)?);
            }
        } else {
            args.push(parse_or(tokens)?);
        }

        match tokens.peek() {
            Some(&&Token::RParen) => {
                tokens.next();
                break;
            }
            Some(&&Token::Comma) => {
                tokens.next();
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

fn parse_pcr_call(tokens: &mut Peekable<Iter<'_, Token<'_>>>) -> Result<Expression, PolicyError> {
    let mut args = parse_call_args(tokens)?;
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
                    && digest.len() >= crypto_hash_size(TpmAlgId::Sha1).unwrap_or(20) * 2
                {
                    (selection.to_string(), Some(digest.to_string()))
                } else {
                    (pcr_content, None)
                }
            } else {
                (pcr_content, None)
            };

        let selections = pcr_selection_vec_from_str(&selection_part)?;
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

fn parse_secret_call(
    tokens: &mut Peekable<Iter<'_, Token<'_>>>,
) -> Result<Expression, PolicyError> {
    let args = parse_call_args(tokens)?;
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
