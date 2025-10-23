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

pub use buffer::TpmBuffer;
pub use list::TpmList;

use core::{convert::From, mem::size_of, result::Result};

/// A TPM handle, which is a 32-bit unsigned integer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmHandle(pub u32);

impl From<u32> for TpmHandle {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmHandle> for u32 {
    fn from(val: TpmHandle) -> Self {
        val.0
    }
}

impl TpmBuild for TpmHandle {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        TpmBuild::build(&self.0, writer)
    }
}

impl TpmParse for TpmHandle {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (val, buf) = u32::parse(buf)?;
        Ok((Self(val), buf))
    }
}

impl TpmSized for TpmHandle {
    const SIZE: usize = size_of::<u32>();
    fn len(&self) -> usize {
        Self::SIZE
    }
}

impl core::fmt::Display for TpmHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl core::fmt::LowerHex for TpmHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::UpperHex for TpmHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.0, f)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TpmDiscriminant {
    Signed(i64),
    Unsigned(u64),
}

impl core::fmt::LowerHex for TpmDiscriminant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TpmDiscriminant::Signed(v) => write!(f, "{v:x}"),
            TpmDiscriminant::Unsigned(v) => write!(f, "{v:x}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
/// TPM protocol data error.
pub enum TpmError {
    /// A specification capacity has been exceeded,
    CapacityExceeded,
    /// Not enough bytes to parse the full data structure.
    DataTruncated,
    /// The buffer contains malformed data.
    MalformedData,
    /// Trailing left data after parsing
    TrailingData,
    /// Unknown discriminant.
    UnknownDiscriminant(&'static str, TpmDiscriminant),
}

impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapacityExceeded => write!(f, "capacity exceeded"),
            Self::DataTruncated => write!(f, "data truncated"),
            Self::MalformedData => write!(f, "malformed data"),
            Self::TrailingData => write!(f, "trailing data"),
            Self::UnknownDiscriminant(type_name, value) => {
                write!(f, "unknown discriminant: {type_name}:  0x{value:x}")
            }
        }
    }
}

impl From<core::num::TryFromIntError> for TpmError {
    fn from(_: core::num::TryFromIntError) -> Self {
        Self::CapacityExceeded
    }
}

pub type TpmResult<T> = Result<T, TpmError>;

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
    /// Returns `TpmError::CapacityExceeded` if the writer does not have enough
    /// capacity to hold the new bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self.cursor + bytes.len();
        if end > self.buffer.len() {
            return Err(TpmError::CapacityExceeded);
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
    /// Returns `Err(TpmError)` on a build failure.
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

pub trait TpmParse: Sized + TpmSized {
    /// Parses an object from the given buffer.
    ///
    /// Returns the parsed type and the remaining portion of the buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` on a parse failure.
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
    /// such as a `TpmError::DataTruncated` if the buffer is too small or an
    /// `TpmError::MalformedData` if the data is malformed.
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
