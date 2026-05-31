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
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::all)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::pedantic)]
#![recursion_limit = "256"]

pub mod basic;
pub mod constant;
pub mod data;
#[macro_use]
pub mod r#macro;
pub mod frame;

/// A byte-backed TPM wire view.
#[repr(transparent)]
pub struct TpmWire([u8]);

impl TpmWire {
    /// Casts a byte slice into a TPM wire view.
    #[must_use]
    pub fn cast(buf: &[u8]) -> &Self {
        // SAFETY: `TpmWire` accepts any byte slice as its backing storage.
        unsafe { Self::cast_unchecked(buf) }
    }

    /// Casts a byte slice into a TPM wire view without validation.
    ///
    /// # Safety
    ///
    /// `TpmWire` has no additional validity requirements beyond the validity
    /// of `buf`. Callers must still ensure any higher-level protocol
    /// invariants required by later typed accessors have been validated.
    #[must_use]
    pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        let ptr = core::ptr::from_ref(buf) as *const Self;

        // SAFETY: `TpmWire` is `repr(transparent)` over `[u8]`, so it has the
        // same layout, metadata, and alignment as the referenced slice.
        unsafe { &*ptr }
    }

    /// Casts a mutable byte slice into a mutable TPM wire view.
    #[must_use]
    pub fn cast_mut(buf: &mut [u8]) -> &mut Self {
        // SAFETY: `TpmWire` accepts any mutable byte slice as its backing
        // storage. The `&mut` input provides exclusive access.
        unsafe { Self::cast_mut_unchecked(buf) }
    }

    /// Casts a mutable byte slice into a mutable TPM wire view without validation.
    ///
    /// # Safety
    ///
    /// `TpmWire` has no additional validity requirements beyond the validity
    /// of `buf`. Callers must still ensure any higher-level protocol
    /// invariants required by later typed accessors have been validated. The
    /// returned reference inherits the exclusive access represented by `buf`.
    #[must_use]
    pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        let ptr = core::ptr::from_mut(buf) as *mut Self;

        // SAFETY: `TpmWire` is `repr(transparent)` over `[u8]`, so it has the
        // same layout, metadata, and alignment as the referenced slice.
        unsafe { &mut *ptr }
    }

    /// Returns the backing bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the mutable backing bytes.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the number of backing bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the backing byte slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for TpmWire {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for TpmWire {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

/// A byte-backed TPM wire view with a fixed byte length.
#[repr(transparent)]
pub struct TpmWireBytes<const N: usize>([u8; N]);

impl<const N: usize> TpmWireBytes<N> {
    /// Casts a byte slice into a fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmProtocolError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    /// Returns [`TrailingData`](crate::TpmProtocolError::TrailingData) when
    /// `buf` is larger than `N` bytes.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        if buf.len() < N {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        if buf.len() > N {
            return Err(TpmProtocolError::TrailingData);
        }

        // SAFETY: The length check above guarantees that `buf` has exactly the
        // byte length required by `TpmWireBytes<N>`.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts a byte slice into a fixed-size TPM wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf.len() == N`. Callers must also ensure
    /// any higher-level protocol invariants required by later typed accessors
    /// have been validated.
    #[must_use]
    pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        let ptr = buf.as_ptr().cast::<Self>();

        // SAFETY: `TpmWireBytes<N>` is `repr(transparent)` over `[u8; N]`, so it
        // has the same layout and alignment. The caller guarantees exact size.
        unsafe { &*ptr }
    }

    /// Casts a mutable byte slice into a fixed-size mutable TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmProtocolError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    /// Returns [`TrailingData`](crate::TpmProtocolError::TrailingData) when
    /// `buf` is larger than `N` bytes.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        if buf.len() < N {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        if buf.len() > N {
            return Err(TpmProtocolError::TrailingData);
        }

        // SAFETY: The length check above guarantees that `buf` has exactly the
        // byte length required by `TpmWireBytes<N>`. The `&mut` input provides
        // exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts a mutable byte slice into a fixed-size mutable TPM wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf.len() == N`. Callers must also ensure
    /// any higher-level protocol invariants required by later typed accessors
    /// have been validated. The returned reference inherits the exclusive
    /// access represented by `buf`.
    #[must_use]
    pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        let ptr = buf.as_mut_ptr().cast::<Self>();

        // SAFETY: `TpmWireBytes<N>` is `repr(transparent)` over `[u8; N]`, so it
        // has the same layout and alignment. The caller guarantees exact size.
        unsafe { &mut *ptr }
    }

    /// Returns the backing bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Returns the mutable backing bytes.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Returns the number of backing bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` when the backing byte array is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for TpmWireBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const N: usize> AsMut<[u8]> for TpmWireBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

/// TPM frame marshaling and unmarshaling error type containing variants
/// for all the possible error conditions.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmProtocolError {
    /// Trying to marshal more bytes than buffer has space. This is unexpected
    /// situation, and should be considered possible bug in the crate itself.
    BufferOverflow,

    /// Integer overflow while converting to an integer of a different size.
    IntegerTooLarge,

    /// Boolean value was expected but the value is neither `0` nor `1`.
    InvalidBoolean,

    /// Non-existent command code encountered.
    InvalidCc,

    /// An [`TpmAttest`](crate::data::TpmAttest) instance contains an invalid
    /// magic value.
    InvalidMagicNumber,

    /// Tag is neither [`Sessions`](crate::data::TpmSt::Sessions) nor
    /// [`NoSessions`](crate::data::TpmSt::NoSessions).
    InvalidTag,

    /// Buffer contains more bytes than allowed by the TCG specifications.
    TooManyBytes,

    /// List contains more items than allowed by the TCG specifications.
    TooManyItems,

    /// Trailing data left after unmarshaling.
    TrailingData,

    /// Run out of bytes while unmarshaling.
    UnexpectedEnd,

    /// The variant accessed is not available.
    VariantNotAvailable,
}

impl core::fmt::Display for TpmProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::InvalidBoolean => write!(f, "invalid boolean value"),
            Self::InvalidCc => write!(f, "invalid command code"),
            Self::InvalidMagicNumber => write!(f, "invalid magic number"),
            Self::InvalidTag => write!(f, "invalid tag"),
            Self::IntegerTooLarge => write!(f, "integer overflow"),
            Self::TooManyBytes => write!(f, "buffer capacity surpassed"),
            Self::TooManyItems => write!(f, "list capaacity surpassed"),
            Self::TrailingData => write!(f, "trailing data"),
            Self::UnexpectedEnd => write!(f, "unexpected end"),
            Self::VariantNotAvailable => write!(f, "enum variant is not available"),
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
    /// Returns [`OutOfMemory`](crate::TpmProtocolError::OutOfMemory)
    /// when the capacity of the buffer is exceeded.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or(TpmProtocolError::BufferOverflow)?;

        if end > self.buffer.len() {
            return Err(TpmProtocolError::BufferOverflow);
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

pub trait TpmMarshal {
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
