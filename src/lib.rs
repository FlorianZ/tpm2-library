// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! # TPM 2.0 Protocol
//!
//! A library for marshaling and unmarshaling TCG TPM 2.0 protocol messages.
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

pub mod basic;
pub mod constant;
pub mod data;
#[macro_use]
pub mod r#macro;
pub mod frame;

/// A TPM handle, which is a 32-bit unsigned integer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmHandle(pub u32);

impl core::convert::From<u32> for TpmHandle {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl core::convert::From<TpmHandle> for u32 {
    fn from(val: TpmHandle) -> Self {
        val.0
    }
}

impl TpmMarshal for TpmHandle {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        TpmMarshal::marshal(&self.0, writer)
    }
}

impl TpmUnmarshal for TpmHandle {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (val, buf) = u32::unmarshal(buf)?;
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

/// TPM protocol data error.
#[derive(Debug, PartialEq, Eq)]
pub enum TpmProtocolError {
    /// The amount data exceeds the maximum capacity of a type, as defined in
    /// the TCG specifications.
    CapacityExceeded,
    /// An [`TpmAttest`](crate::data::TpmAttest) instance contains an invalid
    /// magic value.
    InvalidAttestMagic,
    /// Tag is neither [`Sessions`](crate::data::TpmSt::Sessions) nor
    /// [`NoSessions`](crate::data::TpmSt::NoSessions).
    InvalidTag,
    /// A value is not defined for the type.
    InvalidValue,
    /// An enum variant is not valid for the context of use.
    InvalidVariant,
    /// A cryptographic operation failed.
    OperationFailed,
    /// The number of list items exceeds the maximum capability of a type, as
    /// defined in the TCG specifications.
    TooManyItems,
    /// Trailing data left after unmarshaling.
    TrailingData,
    /// Not enough bytes to unmarshal.
    UnexpectedEnd,
}

impl core::fmt::Display for TpmProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapacityExceeded => write!(f, "buffer capacity exceeded"),
            Self::InvalidAttestMagic => write!(f, "invalid attestation magiC"),
            Self::InvalidTag => write!(f, "invalid tag"),
            Self::InvalidValue => write!(f, "invalid value"),
            Self::InvalidVariant => write!(f, "invalid variant"),
            Self::OperationFailed => write!(f, "operation failed"),
            Self::TooManyItems => write!(f, "too many list items"),
            Self::TrailingData => write!(f, "trailing data"),
            Self::UnexpectedEnd => write!(f, "unexpected end"),
        }
    }
}

impl core::error::Error for TpmProtocolError {}

pub type TpmResult<T> = Result<T, TpmProtocolError>;

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
    /// Returns [`CapacityExceeded`](crate::TpmProtocolError::CapacitExceeded)
    /// when the capacity of the buffer is exceeded.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self.cursor + bytes.len();
        if end > self.buffer.len() {
            return Err(TpmProtocolError::CapacityExceeded);
        }
        self.buffer[self.cursor..end].copy_from_slice(bytes);
        self.cursor = end;
        Ok(())
    }
}

/// Provides two ways to determine the size of an oBject: a compile-time maximum
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

pub trait TpmMarshal: TpmSized {
    /// Marshals the object into the given writer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` on a marshal failure.
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

pub trait TpmUnmarshal: Sized + TpmSized {
    /// Unmarshals an object from the given buffer.
    ///
    /// Returns the unmarshald type and the remaining portion of the buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` on a unmarshal failure.
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])>;
}

/// Types that are composed of a tag and a value e.g., a union.
pub trait TpmTagged {
    /// The type of the tag/discriminant.
    type Tag: TpmUnmarshal + TpmMarshal + Copy;
    /// The type of the value/union.
    type Value;
}

/// Unmarshals a tagged object from a buffer.
pub trait TpmUnmarshalTagged: Sized {
    /// Unmarshals a tagged object from the given buffer using the provided tag.
    ///
    /// # Errors
    ///
    /// This method can return any error of the underlying type's `TpmUnmarshal` implementation,
    /// such as a `TpmProtocolError::UnexpectedEnd` if the buffer is too small or an
    /// `TpmProtocolError::MalformedValue` if the data is malformed.
    fn unmarshal_tagged(tag: <Self as TpmTagged>::Tag, buf: &[u8]) -> TpmResult<(Self, &[u8])>
    where
        Self: TpmTagged,
        <Self as TpmTagged>::Tag: TpmUnmarshal + TpmMarshal;
}

tpm_integer!(u8, Unsigned);
tpm_integer!(i8, Signed);
tpm_integer!(i32, Signed);
tpm_integer!(u16, Unsigned);
tpm_integer!(u32, Unsigned);
tpm_integer!(u64, Unsigned);
