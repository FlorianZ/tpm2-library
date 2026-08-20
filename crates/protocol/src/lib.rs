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
//!
//! ## Zero-Copy Contract
//!
//! Read-side protocol APIs operate on caller-owned byte slices and return
//! borrowed wire views into those slices. Implementations must not copy payload
//! bytes to inspect frames or nested TPM values. Scalar fields may be read by
//! value from their big-endian wire representation.
//!
//! Validation must prove all exposed borrowed views are bounded by the original
//! input slice. Any malformed length, tag, selector, or trailing byte condition
//! must be reported as [`TpmError`] instead of panicking.
//!
//! The crate does not use the external `zerocopy` crate.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::all)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::pedantic)]
#![recursion_limit = "256"]

pub mod basic;
pub mod constant;
pub mod data;
mod error;
#[macro_use]
pub mod r#macro;
pub mod frame;

pub use self::error::{TpmError, TpmResult, tpm_offset, tpm_value};

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

    /// Casts a byte slice into a TPM wire view and returns no remainder.
    #[must_use]
    pub fn cast_prefix(buf: &[u8]) -> (&Self, &[u8]) {
        (Self::cast(buf), &buf[buf.len()..])
    }

    /// Casts a mutable byte slice into a mutable TPM wire view.
    #[must_use]
    pub fn cast_mut(buf: &mut [u8]) -> &mut Self {
        // SAFETY: `TpmWire` accepts any mutable byte slice as its backing
        // storage. The `&mut` input provides exclusive access.
        unsafe { Self::cast_mut_unchecked(buf) }
    }

    /// Casts a mutable byte slice into a mutable TPM wire view and returns no remainder.
    #[must_use]
    pub fn cast_prefix_mut(buf: &mut [u8]) -> (&mut Self, &mut [u8]) {
        let len = buf.len();
        let (head, tail) = buf.split_at_mut(len);

        (Self::cast_mut(head), tail)
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

crate::tpm_byte_view!(TpmWire);

/// A byte-backed TPM wire view with a fixed byte length.
#[repr(transparent)]
pub struct TpmWireBytes<const N: usize>([u8; N]);

impl<const N: usize> TpmWireBytes<N> {
    /// Casts a byte slice into a fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` is larger than `N` bytes.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate(buf)?;

        // SAFETY: The validation above guarantees that `buf` has exactly the
        // byte length required by `TpmWireBytes<N>`.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Validates an exact fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` is larger than `N` bytes.
    pub fn validate(buf: &[u8]) -> TpmResult<()> {
        Self::validate_prefix(buf)?;

        if buf.len() > N {
            return Err(TpmError::TrailingData {
                offset: N,
                actual: buf.len() - N,
            });
        }

        Ok(())
    }

    /// Validates that `buf` starts with a fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    pub fn validate_prefix(buf: &[u8]) -> TpmResult<()> {
        if buf.len() < N {
            return Err(TpmError::UnexpectedEnd {
                offset: 0,
                needed: N,
                available: buf.len(),
            });
        }

        Ok(())
    }

    /// Casts the first `N` bytes into a fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    pub fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::validate_prefix(buf)?;

        let (head, tail) = buf.split_at(N);

        // SAFETY: The validation above guarantees that `head` has exactly
        // the byte length required by `TpmWireBytes<N>`.
        Ok((unsafe { Self::cast_unchecked(head) }, tail))
    }

    /// Casts a mutable byte slice into a fixed-size mutable TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` is larger than `N` bytes.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate(buf)?;

        // SAFETY: The validation above guarantees that `buf` has exactly the
        // byte length required by `TpmWireBytes<N>`. The `&mut` input provides
        // exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts the first `N` mutable bytes into a fixed-size TPM wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than `N` bytes.
    pub fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::validate_prefix(buf)?;

        let (head, tail) = buf.split_at_mut(N);

        // SAFETY: The validation above guarantees that `head` has exactly
        // the byte length required by `TpmWireBytes<N>`.
        Ok((unsafe { Self::cast_mut_unchecked(head) }, tail))
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

crate::tpm_byte_view!(array TpmWireBytes<const N: usize>);

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

/// Casts caller-owned bytes into a TPM wire view.
pub trait TpmCast {
    /// Casts `buf` into `Self` after validating the wire-view invariants.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buf` does not satisfy the
    /// invariants for `Self`.
    fn cast(buf: &[u8]) -> TpmResult<&Self>;

    /// Casts the first wire value in `buf` into `Self` and returns the remainder.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buf` does not start with a valid `Self`.
    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        let value = Self::cast(buf)?;

        Ok((value, &buf[buf.len()..]))
    }

    /// Casts `buf` into `Self` without validating the wire-view invariants.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` satisfies the same invariants checked
    /// by [`TpmCast::cast`].
    unsafe fn cast_unchecked(buf: &[u8]) -> &Self;
}

/// Casts caller-owned mutable bytes into a mutable TPM wire view.
pub trait TpmCastMut: TpmCast {
    /// Casts `buf` into mutable `Self` after validating the wire-view invariants.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buf` does not satisfy the
    /// invariants for `Self`.
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self>;

    /// Casts the first mutable wire value in `buf` into `Self` and returns the remainder.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buf` does not start with a valid `Self`.
    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        let len = buf.len();
        let (head, tail) = buf.split_at_mut(len);
        let value = Self::cast_mut(head)?;

        Ok((value, tail))
    }

    /// Casts `buf` into mutable `Self` without validating the wire-view invariants.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` satisfies the same invariants checked
    /// by [`TpmCastMut::cast_mut`]. The returned reference inherits the
    /// exclusive access represented by `buf`.
    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self;
}

/// Reads one field from a TPM wire structure.
pub trait TpmField<'a> {
    type View;

    /// Reads the first field from `buf` and returns the remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buf` does not start with a valid field.
    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])>;
}

/// Reads a union field selected by a previously-read tag.
pub trait TpmTaggedField<'a, Tag> {
    type View;

    /// Reads the tagged field from `buf` and returns the remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `tag` does not select a valid variant or
    /// `buf` does not start with a valid selected field.
    fn cast_tagged_prefix_field(tag: Tag, buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])>;
}

impl<'a, T: TpmCast + ?Sized + 'a> TpmField<'a> for T {
    type View = &'a T;

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        T::cast_prefix(buf)
    }
}

impl TpmCast for TpmWire {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Ok(Self::cast(buf))
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Ok(Self::cast_prefix(buf))
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `TpmWire`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl TpmCastMut for TpmWire {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Ok(Self::cast_mut(buf))
    }

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Ok(Self::cast_prefix_mut(buf))
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmWire`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl<const N: usize> TpmCast for TpmWireBytes<N> {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::cast_prefix(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for
        // `TpmWireBytes<N>`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl<const N: usize> TpmCastMut for TpmWireBytes<N> {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::cast_prefix_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmWireBytes<N>`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

/// Builds TPM wire bytes into a caller-provided mutable byte slice.
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

    /// Returns the bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.cursor]
    }

    /// Appends a slice of bytes to the writer.
    ///
    /// # Errors
    ///
    /// Returns [`BufferOverflow`](crate::TpmError::BufferOverflow) when the
    /// capacity of the buffer is exceeded.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TpmResult<()> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or(TpmError::BufferOverflow {
                offset: self.cursor,
                needed: bytes.len(),
                available: 0,
            })?;

        if end > self.buffer.len() {
            return Err(TpmError::BufferOverflow {
                offset: self.cursor,
                needed: bytes.len(),
                available: self.buffer.len().saturating_sub(self.cursor),
            });
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
    /// Returns `Err(TpmError)` on a marshal failure.
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

/// Reconstructs an owned TPM value from wire bytes.
pub trait TpmUnmarshal: Sized {
    /// Reads one owned value from the start of `buffer`.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `buffer` does not start with a valid value.
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])>;
}

/// Reconstructs an owned tagged union payload selected by a previously-read tag.
pub trait TpmUnmarshalTagged<Tag>: Sized {
    /// Reads one owned tagged value from the start of `buffer`.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `tag` does not select a valid variant or
    /// `buffer` does not start with a valid selected payload.
    fn unmarshal_tagged(tag: Tag, buffer: &[u8]) -> TpmResult<(Self, &[u8])>;
}
