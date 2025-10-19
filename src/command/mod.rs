// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::doc_markdown)]

pub mod algorithm;
pub mod certificate;
pub mod common;
pub mod convert;
pub mod create;
pub mod create_primary;
pub mod delete;
pub mod evict;
pub mod key;
pub mod load;
pub mod memory;
pub mod pcr_event;
pub mod policy;
pub mod reset_lock;
pub mod return_code;
pub mod session;
pub mod unseal;

pub use algorithm::*;
pub use certificate::*;
pub use common::*;
pub use convert::*;
pub use create::*;
pub use create_primary::*;
pub use delete::*;
pub use evict::*;
pub use key::*;
pub use load::*;
pub use memory::*;
pub use pcr_event::*;
pub use policy::*;
pub use reset_lock::*;
pub use return_code::*;
pub use session::*;
pub use unseal::*;

use crate::{
    auth::AuthError,
    crypto::CryptoError,
    device::DeviceError,
    key::KeyCacheError,
    key::{AlgInfo, KeyError},
    pcr::PcrError,
    policy::PolicyError,
    session::SessionError,
    uri::UriError,
};
use std::{
    fmt,
    io::{IsTerminal, Write},
    num::TryFromIntError,
};
use tabled::{
    settings::{object::Rows, Format, Modify, Padding, Style},
    Table, Tabled,
};
use thiserror::Error;
use tpm2_protocol::{data::TpmCc, TpmErrorKind};

/// Creates, styles, and prints a table from a vector of `Tabled` items.
///
/// # Errors
///
/// Returns an I/O error if writing to the writer fails.
pub fn print_table<T>(writer: &mut dyn Write, items: Vec<T>) -> Result<(), std::io::Error>
where
    T: Tabled,
{
    if !items.is_empty() {
        let mut table = Table::new(items);

        table.with(Style::blank()).with(Padding::new(0, 1, 0, 0));
        if std::io::stdout().is_terminal() {
            table.with(
                Modify::new(Rows::first())
                    .with(Format::content(|s: &str| format!("\x1b[1m{s}\x1b[0m"))),
            );
        }
        writeln!(writer, "{table}")?;
    }
    Ok(())
}

/// Returns an error if the provided algorithm is `KeyedHash`.
///
/// # Errors
///
/// Returns `CommandError::UnsupportedKeyAlgorithm` if the algorithm is keyedhash.
pub fn deny_keyedhash(algorithm: &crate::key::Alg) -> Result<(), CommandError> {
    if algorithm.params == AlgInfo::KeyedHash {
        Err(CommandError::UnsupportedKeyAlgorithm(algorithm.clone()))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("capability not found: {0}")]
    CapabilityMissing(tpm2_protocol::data::TpmCap),
    #[error("context: {0}")]
    KeyCacheError(#[from] KeyCacheError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("dictionary attack lockout is active")]
    DictionaryAttackLocked,
    #[error("empty authentication denied")]
    EmptyAuthenticationDenied,
    #[error("non-empty authentication denied")]
    NonEmptyAuthenticationDenied,
    #[error("format: {0}")]
    Fmt(#[from] fmt::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid output: {0}")]
    InvalidOutput(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("parent missing")]
    ParentMissing,
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("session: {0}")]
    Session(#[from] SessionError),
    #[error("unsupported key algorithm: '{0}'")]
    UnsupportedKeyAlgorithm(crate::key::Alg),
    #[error("unsupported session: {0}")]
    UnsupportedSession(String),
    #[error("uri: {0}")]
    Uri(#[from] UriError),
    #[error("auth: {0}")]
    Auth(#[from] AuthError),
}

impl From<hex::FromHexError> for CommandError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidInput(err.to_string())
    }
}

impl From<TpmErrorKind> for CommandError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Device(err.into())
    }
}

impl From<TryFromIntError> for CommandError {
    fn from(err: TryFromIntError) -> Self {
        Self::Device(err.into())
    }
}
