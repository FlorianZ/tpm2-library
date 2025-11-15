//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//! Copyright (c) 2025 Opinsys Oy

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
pub use reset_lock::*;
pub use return_code::*;
pub use unseal::*;

use crate::{
    alg::{AlgError, AlgInfo},
    device::DeviceError,
    pcr::PcrError,
    task::{TaskError, TaskState},
    vtpm::VtpmError,
};
use openssl::error::ErrorStack;
use std::num::TryFromIntError;
use tabled::{
    settings::{object::Rows, Color, Modify, Padding, Style},
    Table, Tabled,
};
use thiserror::Error;
use tpm2_crypto::Error as CryptoError;
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase},
    TpmProtocolError,
};

/// Creates, styles, and prints a table from a vector of `Tabled` items.
///
/// # Errors
///
/// Returns [`Io`](CommandError::Io) if writing to the writer fails.
pub fn print_table<T>(session: &mut TaskState, items: &[T]) -> Result<(), CommandError>
where
    T: Tabled,
{
    if items.is_empty() {
        return Ok(());
    }

    let mut table = Table::new(items);

    table.with(Style::blank()).with(Padding::new(0, 2, 0, 0));

    if session.is_tty {
        table.with(Modify::new(Rows::first()).with(Color::BOLD));
    }

    writeln!(session.writer, "{table}").map_err(CommandError::Io)?;
    Ok(())
}

/// Returns an error if the provided algorithm is `KeyedHash`.
///
/// # Errors
///
/// Returns [`UnsupportedKeyAlgorithm`](crate::command::CommandError::UnsupportedKeyAlgorithm)
/// if the algorithm is keyedhash.
pub fn deny_keyedhash(algorithm: &crate::alg::Alg) -> Result<(), CommandError> {
    if algorithm.params == AlgInfo::KeyedHash {
        Err(CommandError::UnsupportedKeyAlgorithm(algorithm.clone()))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("access denied")]
    AccessDenied,
    #[error("authentication missing")]
    AuthenticationMissing,
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("dictionary attack lockout is active")]
    DictionaryAttackLocked,
    #[error("invalid key format")]
    InvalidFormat,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid parent object handle: {0}")]
    InvalidParentHandle(String),
    #[error("invalid parent key type")]
    InvalidParentType,
    #[error("invalid policy expression: {0}")]
    InvalidPolicyExpression(String),
    #[error("handle pattern not allowed: {0}")]
    PatternNotAllowed(String),
    #[error("policy denied")]
    PolicyDenied,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("sensitive data denied")]
    SensitiveDataDenied,
    #[error("sensitive data missing")]
    SensitiveDataMissing,
    #[error("unknown handle: {0}")]
    UnknownHandle(String),
    #[error("unknown parent")]
    UnknownParent,
    #[error("unsupported key algorithm: '{0}'")]
    UnsupportedKeyAlgorithm(crate::alg::Alg),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(crate::alg::Alg),
    #[error("cache: {0}")]
    Cache(VtpmError),
    #[error("task_state: {0}")]
    Session(TaskError),
    #[error("device: {0}")]
    Device(DeviceError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("key error: {0}")]
    Key(#[from] AlgError),
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("policy parse: {0}")]
    PolicyLanguage(#[from] tpm2_policy_language::Error),
    #[error("ECDH private key generation failed")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("openssl: {0}")]
    Openssl(#[from] ErrorStack),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
}

impl CommandError {
    /// Maps common device errors to `CommandError::InvalidParentHandle`.
    ///
    /// # Errors
    ///
    /// Returns `CommandError::InvalidParentHandle` if the error is a `TpmRc`
    /// with base `Handle`, `ReferenceH0`, or `Type`. Otherwise, returns
    /// the error converted into a `CommandError`.
    #[must_use]
    pub fn from_device_error(err: DeviceError, context: String) -> Self {
        if let DeviceError::TpmRc(rc) = err {
            match rc.base() {
                TpmRcBase::Handle | TpmRcBase::ReferenceH0 | TpmRcBase::Type => {
                    Self::InvalidParentHandle(context)
                }
                TpmRcBase::AuthFail => Self::AccessDenied,
                TpmRcBase::AuthMissing => Self::AuthenticationMissing,
                TpmRcBase::Lockout => Self::DictionaryAttackLocked,
                TpmRcBase::PolicyFail => Self::PolicyDenied,
                _ => Self::Device(DeviceError::TpmRc(rc)),
            }
        } else {
            Self::Device(err)
        }
    }
}

impl From<TaskError> for CommandError {
    fn from(err: TaskError) -> Self {
        match err {
            TaskError::Device(dev_err) => Self::from(dev_err),
            TaskError::InvalidParent(prefix, handle)
            | TaskError::Vtpm(VtpmError::HandleNotFound(prefix, handle)) => {
                Self::InvalidParentHandle(format!("{prefix}{handle:08x}"))
            }
            TaskError::Vtpm(e) => Self::Cache(e),
            TaskError::Key(e) => Self::Key(e),
            TaskError::Crypto(e) => Self::Crypto(e),
            TaskError::Io(e) => Self::Io(e),
            TaskError::IntDecode(e) => Self::IntDecode(e),
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
        Self::from_device_error(err, String::new())
    }
}
