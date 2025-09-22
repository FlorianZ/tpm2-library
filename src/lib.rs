// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! # TPM 2.0 Protocol
//!
//! A library for building and parsing TCG TPM 2.0 protocol messages.
//!
//! ## Constraints
//!
//! * `alloc` is disallowed.
//! * Dependencies are disallowed.
//! * Developer dependencies are disallowed.
//! * Panics are disallowed.
//!
//! ## Design Goals
//!
//! * The crate must compile with GNU make and rustc without any external
//!   dependencies.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![recursion_limit = "256"]

pub mod buffer;
pub mod constant;
pub mod data;
pub mod list;
#[macro_use]
pub mod r#macro;
pub mod message;

use crate::data::TpmAlgId;
pub use buffer::TpmBuffer;
use core::{
    convert::{From, TryFrom},
    fmt,
    mem::size_of,
    result::Result,
};
pub use list::TpmList;

tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmTransient
}
tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmSession
}
tpm_handle! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    TpmPersistent
}

#[derive(Debug, PartialEq, Eq)]
pub enum TpmNotDiscriminant {
    Signed(i64),
    Unsigned(u64),
}

impl fmt::LowerHex for TpmNotDiscriminant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmNotDiscriminant::Signed(v) => write!(f, "{v:x}"),
            TpmNotDiscriminant::Unsigned(v) => write!(f, "{v:x}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TpmErrorKind {
    /// A value would exceed a capacity limit
    Capacity(usize),
    /// Invalid value
    InvalidValue,
    /// Not a valid discriminant for the target enum
    NotDiscriminant(&'static str, TpmNotDiscriminant),
    /// Trailing left data after parsing
    TrailingData,
    /// Not enough bytes to parse the full data structure.
    Underflow,
    /// An unresolvable internal error
    Failure,
}

impl fmt::Display for TpmErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(size) => write!(f, "exceeds capacity {size}"),
            Self::InvalidValue => write!(f, "invalid value"),
            Self::NotDiscriminant(type_name, value) => {
                write!(f, "not discriminant for {type_name}: 0x{value:x}")
            }
            Self::TrailingData => write!(f, "trailing data"),
            Self::Underflow => write!(f, "parse underflow"),
            Self::Failure => write!(f, "unreachable"),
        }
    }
}

impl From<core::num::TryFromIntError> for TpmErrorKind {
    fn from(_: core::num::TryFromIntError) -> Self {
        Self::Capacity(usize::MAX)
    }
}

pub type TpmResult<T> = Result<T, TpmErrorKind>;

/// Writes into a mutable byte slice.
pub struct TpmWriter<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> TpmWriter<'a> {
    /// Creates a new writer for the given buffer.
    #[must_use]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cursor
    }

    /// Returns `true` if no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    /// Appends a slice of bytes to the writer.
    ///
    /// # Errors
    ///
    /// Returns `TpmErrorKind::Failure` if the writer does not have enough
    /// capacity to hold the new bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self.cursor + bytes.len();
        if end > self.buffer.len() {
            return Err(TpmErrorKind::Failure);
        }
        self.buffer[self.cursor..end].copy_from_slice(bytes);
        self.cursor = end;
        Ok(())
    }
}

/// Provides two ways to determine the size of an object: a compile-time maximum
/// and a runtime exact size.
pub trait TpmSized {
    /// The estimated size of the object in its serialized form evaluated at
    /// compile-time (always larger than the realized length).
    const SIZE: usize;

    /// Returns the exact serialized size of the object.
    fn len(&self) -> usize;

    /// Returns `true` if the object has a serialized length of zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait TpmBuild: TpmSized {
    /// Builds the object into the given writer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a build failure.
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

pub trait TpmParse: Sized + TpmSized {
    /// Parses an object from the given buffer.
    ///
    /// Returns the parsed type and the remaining portion of the buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a parse failure.
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])>;
}

/// Types that are composed of a tag and a value e.g., a union.
pub trait TpmTagged {
    /// The type of the tag/discriminant.
    type Tag: TpmParse + TpmBuild + Copy;
    /// The type of the value/union.
    type Value;
}

/// Parses a tagged object from a buffer.
pub trait TpmParseTagged: Sized {
    /// Parses a tagged object from the given buffer using the provided tag.
    ///
    /// # Errors
    ///
    /// This method can return any error of the underlying type's `TpmParse` implementation,
    /// such as a `TpmErrorKind::Underflow` if the buffer is too small or an
    /// `TpmErrorKind::InvalidValue` if the data is malformed.
    fn parse_tagged(tag: <Self as TpmTagged>::Tag, buf: &[u8]) -> TpmResult<(Self, &[u8])>
    where
        Self: TpmTagged,
        <Self as TpmTagged>::Tag: TpmParse + TpmBuild;
}

tpm_integer!(u8, Unsigned);
tpm_integer!(i8, Signed);
tpm_integer!(i32, Signed);
tpm_integer!(u16, Unsigned);
tpm_integer!(u32, Unsigned);
tpm_integer!(u64, Unsigned);

/// Builds a TPM2B sized buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Capacity` if the size exceeds `u16`.
pub fn build_tpm2b(writer: &mut TpmWriter, data: &[u8]) -> TpmResult<()> {
    let len_u16 = u16::try_from(data.len()).map_err(|_| TpmErrorKind::Capacity(u16::MAX.into()))?;
    TpmBuild::build(&len_u16, writer)?;
    writer.write_bytes(data)
}

/// Parses a TPM2B sized buffer.
///
/// # Errors
///
/// * `TpmErrorKind::Underflow` if the buffer is too small.
/// * `TpmErrorKind::Capacity` if the size prefix exceeds `TPM_MAX_COMMAND_SIZE`.
pub fn parse_tpm2b(buf: &[u8]) -> TpmResult<(&[u8], &[u8])> {
    let (size, buf) = u16::parse(buf)?;
    let size = size as usize;

    if size > crate::constant::TPM_MAX_COMMAND_SIZE {
        return Err(TpmErrorKind::Capacity(
            crate::constant::TPM_MAX_COMMAND_SIZE,
        ));
    }

    if buf.len() < size {
        return Err(TpmErrorKind::Underflow);
    }
    Ok(buf.split_at(size))
}

/// Returns the size of a hash digest in bytes for a given hash algorithm.
#[must_use]
pub const fn tpm_hash_size(alg_id: &TpmAlgId) -> Option<usize> {
    match alg_id {
        TpmAlgId::Sha1 => Some(20),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Some(32),
        TpmAlgId::Sha384 => Some(48),
        TpmAlgId::Sha512 => Some(64),
        _ => None,
    }
}
