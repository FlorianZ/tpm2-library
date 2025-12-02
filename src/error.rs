// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use thiserror::Error;
use tpm2_crypto::TpmCryptoError;
use tpm2_device::TpmDeviceError;
use tpm2_protocol::{
    basic::TpmHandle,
    data::{Tpm2bName, TpmAlgId, TpmCc, TpmRcBase},
    TpmProtocolError,
};
use tpm2_tpmkey::TpmKeyError;
use tpm2_vtpm::VtpmError;

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
    #[error("delete failed")]
    DeleteFailed,
    #[error("device: {0}")]
    Device(TpmDeviceError),
    #[error("dictionary attack lockout is active")]
    DictionaryAttackLocked,
    #[error("encrypting duplicate blob for external key failed")]
    EncryptingDuplicateFailed,
    #[error("handle already tracked: {0}")]
    HandleAlreadyTracked(TpmHandle),
    #[error("handle not found: {0:08x}")]
    HandleNotFound(TpmHandle),
    #[error("handle name not found: {}", hex::encode(.0.as_ref()))]
    HandleNameNotFound(Tpm2bName),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid auth")]
    InvalidAuth,
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
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("invalid RSA parameters")]
    InvalidRsaParameters,
    #[error("sensitive data is not a valid hex string")]
    InvalidSensitiveData,
    #[error("integer overflow")]
    IntegerOverflow,
    #[error("key: {0}")]
    Key(#[from] TpmKeyError),
    #[error("key description missing")]
    KeyDescriptionMissing,
    #[error("malformed data")]
    MalformedData,
    #[error("marshal: {0}")]
    Marshal(TpmProtocolError),
    #[error("out of memory")]
    OutOfMemory,
    #[error("handle pattern not allowed: {0}")]
    PatternNotAllowed(String),
    #[error("PCR digest missing")]
    PcrDigestMissing,
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
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("too many auths")]
    TooManyAuths,
    #[error("unknown handle: {0}")]
    UnknownHandle(String),
    #[error("unknown parent")]
    UnknownParent,
    #[error("unmarshal: {0}")]
    Unmarshal(TpmProtocolError),
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
