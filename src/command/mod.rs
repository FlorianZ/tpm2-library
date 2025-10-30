// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::doc_markdown)]

pub mod algorithm;
pub mod cache;
pub mod common;
pub mod convert;
pub mod create;
pub mod create_primary;
pub mod delete;
pub mod evict;
pub mod load;
pub mod memory;
pub mod pcr_event;
pub mod policy;
pub mod reset_lock;
pub mod return_code;
pub mod unseal;

pub use algorithm::*;
pub use cache::*;
pub use common::*;
pub use convert::*;
pub use create::*;
pub use create_primary::*;
pub use delete::*;
pub use evict::*;
pub use load::*;
pub use memory::*;
pub use pcr_event::*;
pub use policy::*;
pub use reset_lock::*;
pub use return_code::*;
pub use unseal::*;

use crate::{
    device::DeviceError,
    key::{AlgInfo, KeyError},
    pcr::PcrError,
    policy::PolicyError,
    session::SessionError,
    vtpm::VtpmError,
};
use clap::builder::styling::Style as AnsiStyle;
use std::{
    io::{IsTerminal, Write},
    num::TryFromIntError,
};
use thiserror::Error;
use tpm2_crypto::CryptoError;
use tpm2_policy_language::ParseError as PolicyParseError;
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase},
    TpmError,
};

/// A trait for data structures that can be represented as a table row.
pub trait Tabled {
    /// Returns the headers for the table.
    fn headers() -> Vec<String>;
    /// Returns the data for a single row.
    fn row(&self) -> Vec<String>;
}

/// Creates, styles, and prints a table from a vector of `Tabled` items.
///
/// # Errors
///
/// Returns an I/O error if writing to the writer fails.
pub fn print_table<T>(writer: &mut dyn Write, items: &[T]) -> Result<(), std::io::Error>
where
    T: Tabled,
{
    if items.is_empty() {
        return Ok(());
    }

    let headers = T::headers();
    let rows: Vec<Vec<String>> = items.iter().map(T::row).collect();
    let num_columns = headers.len();
    let mut max_widths = vec![0; num_columns];

    for i in 0..num_columns {
        max_widths[i] = headers[i].len();
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > max_widths[i] {
                max_widths[i] = cell.len();
            }
        }
    }

    let bold = AnsiStyle::new().bold();
    let header_line = headers
        .iter()
        .zip(&max_widths)
        .map(|(header, &width)| format!("{header:<width$}"))
        .collect::<Vec<String>>()
        .join("  ");

    if std::io::stdout().is_terminal() {
        writeln!(writer, "{bold}{header_line}{bold:#}")?;
    } else {
        writeln!(writer, "{header_line}")?;
    }

    for row in &rows {
        let row_line = row
            .iter()
            .zip(&max_widths)
            .map(|(cell, &width)| format!("{cell:<width$}"))
            .collect::<Vec<String>>()
            .join("  ");
        writeln!(writer, "{row_line}")?;
    }

    Ok(())
}

/// Returns an error if the provided algorithm is `KeyedHash`.
///
/// # Errors
///
/// Returns [`UnsupportedKeyAlgorithm`](crate::command::CommandError::UnsupportedKeyAlgorithm)
/// if the algorithm is keyedhash.
pub fn deny_keyedhash(algorithm: &crate::key::Alg) -> Result<(), CommandError> {
    if algorithm.params == AlgInfo::KeyedHash {
        Err(CommandError::UnsupportedKeyAlgorithm(algorithm.clone()))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("authentication denied")]
    AuthenticationDenied,
    #[error("dictionary attack lockout is active")]
    DictionaryAttackLocked,
    #[error("invalid key format")]
    InvalidFormat,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid output: {0}")]
    InvalidOutput(String),
    #[error("invalid parent: {0}{1:08x}")]
    InvalidParent(&'static str, u32),
    #[error("handle pattern not allowed: {0}")]
    PatternNotAllowed(String),
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("sensitive data denied")]
    SensitiveDataDenied,
    #[error("sensitive data missing")]
    SensitiveDataMissing,
    #[error("too many authorizations provided")]
    TooManyAuths,
    #[error("unknown handle: {0}")]
    UnknownHandle(String),
    #[error("unknown parent")]
    UnknownParent,
    #[error("unsupported key algorithm: '{0}'")]
    UnsupportedKeyAlgorithm(crate::key::Alg),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(crate::key::Alg),
    #[error("missing ECC curve parameters")]
    MissingEccCurveParameters,
    #[error("cache: {0}")]
    Cache(VtpmError),
    #[error("job: {0}")]
    Session(SessionError),
    #[error("device: {0}")]
    Device(DeviceError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("policy parse: {0}")]
    PolicyParse(#[from] PolicyParseError),
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    TpmProtocol(TpmError),
}

impl From<SessionError> for CommandError {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::InvalidParent(prefix, handle) => Self::InvalidParent(prefix, handle),
            SessionError::Device(dev_err) => Self::from(dev_err),
            SessionError::Vtpm(VtpmError::HandleNotFound(prefix, handle)) => {
                Self::InvalidParent(prefix, handle)
            }
            SessionError::Vtpm(e) => Self::Cache(e),
            SessionError::Key(e) => Self::Key(e),
            SessionError::Crypto(e) => Self::Crypto(e),
            SessionError::Io(e) => Self::Io(e),
            SessionError::IntDecode(e) => Self::IntDecode(e),
            _ => Self::Session(err),
        }
    }
}

impl From<VtpmError> for CommandError {
    fn from(err: VtpmError) -> Self {
        Self::Cache(err)
    }
}

impl From<DeviceError> for CommandError {
    fn from(err: DeviceError) -> Self {
        if let DeviceError::TpmRc(rc) = &err {
            let base = rc.base();
            if base == TpmRcBase::AuthFail || base == TpmRcBase::AuthMissing {
                return Self::AuthenticationDenied;
            }
            if base == TpmRcBase::Lockout {
                return Self::DictionaryAttackLocked;
            }
        }
        Self::Device(err)
    }
}

impl From<TpmError> for CommandError {
    fn from(err: TpmError) -> Self {
        Self::TpmProtocol(err)
    }
}
