//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{EccCurve, Hash};
use thiserror::Error;

/// The top-level error type for cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Hash algorithm is not supported in the context of use.
    #[error("invalid hash algorithm: {0}")]
    InvalidHash(Hash),
    /// ECC curve is not supported in the context of use.
    #[error("invalid ECC curve: {0}")]
    InvalidEccCurve(EccCurve),
    /// A zero-length key was provided.
    #[error("the provided key has zero length")]
    KeyIsEmpty,
    /// A cryptographic operation failed.
    #[error("operation failed")]
    OperationFailed,
    /// Not enough memory available.
    #[error("out of memory")]
    OutOfMemory,
    /// The provided HMAC does not match to the expected value.
    #[error("permission denied")]
    PermissionDenied,
}
