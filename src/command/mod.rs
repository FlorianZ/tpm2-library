// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::doc_markdown)]

pub mod algorithm;
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

use crate::{pcr::PcrError, task::TaskError};

use std::io::Write;

use tabled::{
    settings::{object::Rows, Color, Modify, Padding, Style},
    Table, Tabled,
};
use thiserror::Error;
use tpm2_crypto::{TpmCryptoError, TpmPublicTemplate};
use tpm2_device::TpmDeviceError;
use tpm2_protocol::data::{TpmAlgId, TpmCc, TpmRcBase, TpmtPublic, TpmuPublicParms};
use tpm2_vtpm::VtpmError;

/// Creates, styles, and prints a table from a vector of `Tabled` items.
///
/// # Errors
///
/// Returns [`Io`](CommandError::Io) if writing to the writer fails.
pub fn print_table<T>(items: &[T], writer: &mut dyn Write, is_tty: bool) -> Result<(), CommandError>
where
    T: Tabled,
{
    if items.is_empty() {
        return Ok(());
    }

    let mut table = Table::new(items);

    table.with(Style::blank()).with(Padding::new(0, 2, 0, 0));

    if is_tty {
        table.with(Modify::new(Rows::first()).with(Color::BOLD));
    }

    writeln!(writer, "{table}").map_err(CommandError::Io)?;
    Ok(())
}

/// Returns an error if the provided algorithm is `KeyedHash`.
///
/// # Errors
///
/// Returns [`UnsupportedKeyAlgorithm`](crate::command::CommandError::UnsupportedKeyAlgorithm)
/// if the algorithm is keyedhash.
pub fn deny_keyedhash(algorithm: &TpmPublicTemplate) -> Result<(), CommandError> {
    if algorithm.object_type == TpmAlgId::KeyedHash {
        Err(CommandError::UnsupportedKeyAlgorithm)
    } else {
        Ok(())
    }
}

/// Converts a `TpmtPublic` structure to a `TpmPublicTemplate`.
///
/// # Errors
///
/// Returns [`UnsupportedKeyAlgorithm`](CommandError::UnsupportedKeyAlgorithm) if the object type
/// is not RSA, ECC, or KeyedHash.
/// Returns [`InvalidInput`](CommandError::InvalidInput) if the parameters do not match the object type.
pub fn public_to_template(public: &TpmtPublic) -> Result<TpmPublicTemplate, CommandError> {
    match public.object_type {
        TpmAlgId::Rsa => {
            if let TpmuPublicParms::Rsa(parms) = &public.parameters {
                Ok(TpmPublicTemplate::new_rsa(
                    parms.key_bits.value(),
                    public.name_alg,
                ))
            } else {
                Err(CommandError::InvalidRsaParameters)
            }
        }
        TpmAlgId::Ecc => {
            if let TpmuPublicParms::Ecc(parms) = &public.parameters {
                Ok(TpmPublicTemplate::new_ecc(parms.curve_id, public.name_alg))
            } else {
                Err(CommandError::InvalidEccParameters)
            }
        }
        TpmAlgId::KeyedHash => Ok(TpmPublicTemplate::new_keyedhash(public.name_alg)),
        _ => Err(CommandError::UnsupportedKeyAlgorithm),
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
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),
    #[error("device: {0}")]
    Device(TpmDeviceError),
    #[error("dictionary attack lockout is active")]
    DictionaryAttackLocked,
    #[error("encrypting duplicate blob for external key failed")]
    EncryptingDuplicateFailed,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid ECC parameters")]
    InvalidEccParameters,
    #[error("invalid handle")]
    InvalidHandle,
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid parent handle")]
    InvalidParentHandle,
    #[error("invalid parent key type")]
    InvalidParentType,
    #[error("password is not a valid hex string")]
    InvalidPassword,
    #[error("invalid policy expression: {0}")]
    InvalidPolicyExpression(String),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid RSA parameters")]
    InvalidRsaParameters,
    #[error("sensitive data is not a valid hex string")]
    InvalidSensitiveData,
    #[error("integer overflow")]
    IntegerOverflow,
    #[error("key: {0}")]
    Key(#[from] tpm2_tpmkey::TpmKeyError),
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),
    #[error("handle pattern not allowed: {0}")]
    PatternNotAllowed(String),
    #[error("pcr: {0}")]
    Pcr(#[from] PcrError),
    #[error("policy: {0}")]
    Policy(#[from] tpm2_policy_language::TpmPolicyError),
    #[error("policy denied")]
    PolicyDenied,
    #[error("parent missing")]
    ParentMissing,
    #[error("response mismatch: {0}")]
    ResponseMismatch(TpmCc),
    #[error("sensitive data denied")]
    SensitiveDataDenied,
    #[error("sensitive data missing")]
    SensitiveDataMissing,
    #[error("task: {0}")]
    Task(#[from] TaskError),
    #[error("unknown handle: {0}")]
    UnknownHandle(String),
    #[error("unknown parent")]
    UnknownParent,
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
    #[error("unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("unsupported key algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("vtpm: {0}")]
    Vtpm(#[from] VtpmError),
}

impl From<std::num::TryFromIntError> for CommandError {
    fn from(_: std::num::TryFromIntError) -> Self {
        CommandError::IntegerOverflow
    }
}

impl From<TpmDeviceError> for CommandError {
    fn from(err: TpmDeviceError) -> Self {
        if let TpmDeviceError::TpmRc(rc) = err {
            match rc.base() {
                TpmRcBase::Handle | TpmRcBase::ReferenceH0 | TpmRcBase::Type => {
                    Self::InvalidParentHandle
                }
                TpmRcBase::AuthFail => Self::AccessDenied,
                TpmRcBase::AuthMissing => Self::AuthenticationMissing,
                TpmRcBase::Lockout => Self::DictionaryAttackLocked,
                TpmRcBase::PolicyFail => Self::PolicyDenied,
                _ => Self::Device(TpmDeviceError::TpmRc(rc)),
            }
        } else {
            Self::Device(err)
        }
    }
}
