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
    alg::{AlgInfo, KeyError},
    device::DeviceError,
    pcr::PcrError,
    policy::PolicyError,
    task::{SessionError, TaskState},
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
    #[error("authentication denied")]
    AuthenticationDenied,
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
    #[error("invalid output: {0}")]
    InvalidOutput(String),
    #[error("invalid parent object handle: {0}{1:08x}")]
    InvalidParentHandle(&'static str, u32),
    #[error("invalid parent key type")]
    InvalidParentType,
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
    #[error("too many authorizations provided")]
    TooManyAuths,
    #[error("unknown handle: {0}")]
    UnknownHandle(String),
    #[error("unknown parent")]
    UnknownParent,
    #[error("unsupported key algorithm: '{0}'")]
    UnsupportedKeyAlgorithm(crate::alg::Alg),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(crate::alg::Alg),
    #[error("missing ECC curve parameters")]
    MissingEccCurveParameters,
    #[error("cache: {0}")]
    Cache(VtpmError),
    #[error("task_state: {0}")]
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

impl From<SessionError> for CommandError {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::Device(dev_err) => Self::from(dev_err),
            SessionError::InvalidParent(prefix, handle)
            | SessionError::Vtpm(VtpmError::HandleNotFound(prefix, handle)) => {
                Self::InvalidParentHandle(prefix, handle)
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
            if base == TpmRcBase::PolicyFail {
                return Self::PolicyDenied;
            }
        }
        Self::Device(err)
    }
}
