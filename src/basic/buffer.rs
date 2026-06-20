// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    TpmCast, TpmCastMut, TpmError, TpmMarshal, TpmResult, TpmSized, TpmWriter, basic::TpmUint16,
};
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
    mem::{MaybeUninit, size_of},
    ops::Deref,
    slice,
};

const TPM2B_SIZE_LEN: usize = size_of::<TpmUint16>();

/// A zero-copy TPM2B wire view over caller-owned bytes.
#[repr(transparent)]
pub struct Tpm2b<const CAPACITY: usize>([u8]);

impl<const CAPACITY: usize> Tpm2b<CAPACITY> {
    /// Casts a byte slice into a TPM2B wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is shorter than the TPM2B header or declared payload size.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` contains bytes after the declared payload.
    /// Returns [`TooManyBytes`](crate::TpmError::TooManyBytes) when
    /// the declared payload exceeds `CAPACITY`.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate(buf)?;

        // SAFETY: `validate` checked the complete TPM2B byte range and size
        // limit for this transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts the first TPM2B value in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the first TPM2B value is malformed.
    pub fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        let wire_len = Self::validate_prefix(buf)?;
        let (head, tail) = buf.split_at(wire_len);

        // SAFETY: `validate_prefix` checked the complete TPM2B byte range and
        // size limit for `head`.
        Ok((unsafe { Self::cast_unchecked(head) }, tail))
    }

    /// Casts a mutable byte slice into a mutable TPM2B wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is shorter than the TPM2B header or declared payload size.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` contains bytes after the declared payload.
    /// Returns [`TooManyBytes`](crate::TpmError::TooManyBytes) when
    /// the declared payload exceeds `CAPACITY`.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate(buf)?;

        // SAFETY: `validate` checked the complete TPM2B byte range and size
        // limit for this transparent wire view. The `&mut` input provides
        // exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts the first mutable TPM2B value in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the first TPM2B value is malformed.
    pub fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        let wire_len = Self::validate_prefix(buf)?;
        let (head, tail) = buf.split_at_mut(wire_len);

        // SAFETY: `validate_prefix` checked the complete TPM2B byte range and
        // size limit for `head`.
        Ok((unsafe { Self::cast_mut_unchecked(head) }, tail))
    }

    /// Returns the complete TPM2B byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the complete mutable TPM2B byte representation.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the declared payload size.
    #[must_use]
    pub fn size(&self) -> usize {
        Self::read_size(&self.0)
    }

    /// Returns the payload bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.0[TPM2B_SIZE_LEN..]
    }

    /// Returns the mutable payload bytes.
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0[TPM2B_SIZE_LEN..]
    }

    /// Returns the complete TPM2B wire length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the TPM2B payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Validates an exact TPM2B wire value.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the TPM2B value is malformed or has
    /// trailing data.
    pub fn validate(buf: &[u8]) -> TpmResult<()> {
        let wire_len = Self::validate_prefix(buf)?;

        if buf.len() > wire_len {
            return Err(TpmError::TrailingData {
                offset: wire_len,
                actual: buf.len() - wire_len,
            });
        }

        Ok(())
    }

    /// Validates the first TPM2B wire value and returns its wire length.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the first TPM2B value is malformed.
    pub fn validate_prefix(buf: &[u8]) -> TpmResult<usize> {
        if buf.len() < TPM2B_SIZE_LEN {
            return Err(TpmError::UnexpectedEnd {
                offset: 0,
                needed: TPM2B_SIZE_LEN,
                available: buf.len(),
            });
        }

        let payload_len = Self::read_size(buf);
        if payload_len > CAPACITY {
            return Err(TpmError::TooManyBytes {
                offset: 0,
                limit: CAPACITY,
                actual: payload_len,
            });
        }

        let wire_len =
            TPM2B_SIZE_LEN
                .checked_add(payload_len)
                .ok_or(TpmError::IntegerTooLarge {
                    offset: 0,
                    value: crate::tpm_value(payload_len),
                })?;

        if buf.len() < wire_len {
            return Err(TpmError::UnexpectedEnd {
                offset: TPM2B_SIZE_LEN,
                needed: payload_len,
                available: buf.len().saturating_sub(TPM2B_SIZE_LEN),
            });
        }

        Ok(wire_len)
    }

    fn read_size(buf: &[u8]) -> usize {
        usize::from(u16::from_be_bytes([buf[0], buf[1]]))
    }
}

impl<const CAPACITY: usize> TpmCast for Tpm2b<CAPACITY> {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::cast_prefix(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `Tpm2b`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl<const CAPACITY: usize> TpmCastMut for Tpm2b<CAPACITY> {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::cast_prefix_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `Tpm2b`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl<'a, const CAPACITY: usize> crate::TpmField<'a> for TpmBuffer<CAPACITY> {
    type View = &'a Tpm2b<CAPACITY>;

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        Tpm2b::<CAPACITY>::cast_prefix(buf)
    }
}

crate::tpm_byte_view!(Tpm2b<const CAPACITY: usize>);

/// A buffer in the TPM2B wire format.
///
/// The `size` field is stored in native endian and converted to big-endian
/// only during marshaling.
#[derive(Clone, Copy)]
pub struct TpmBuffer<const CAPACITY: usize> {
    size: u16,
    data: [MaybeUninit<u8>; CAPACITY],
}

impl<const CAPACITY: usize> TpmBuffer<CAPACITY> {
    /// Creates a new, empty `TpmBuffer`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: 0,
            data: [const { MaybeUninit::uninit() }; CAPACITY],
        }
    }

    /// Appends a byte to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`BufferOverflow`](crate::TpmError::BufferOverflow) when the
    /// buffer is full or the size exceeds `u16::MAX`.
    pub fn try_push(&mut self, byte: u8) -> TpmResult<()> {
        if (self.size as usize) >= CAPACITY || self.size == u16::MAX {
            return Err(TpmError::BufferOverflow {
                offset: self.size as usize,
                needed: 1,
                available: CAPACITY.saturating_sub(self.size as usize),
            });
        }
        self.data[self.size as usize].write(byte);
        self.size += 1;
        Ok(())
    }

    /// Appends a slice of bytes to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`BufferOverflow`](crate::TpmError::BufferOverflow) when the
    /// resulting size exceeds the buffer capacity or `u16::MAX`.
    pub fn try_extend_from_slice(&mut self, slice: &[u8]) -> TpmResult<()> {
        let current_len = self.size as usize;
        let new_len = current_len
            .checked_add(slice.len())
            .ok_or(TpmError::BufferOverflow {
                offset: current_len,
                needed: slice.len(),
                available: CAPACITY.saturating_sub(current_len),
            })?;

        if new_len > CAPACITY {
            return Err(TpmError::BufferOverflow {
                offset: current_len,
                needed: slice.len(),
                available: CAPACITY.saturating_sub(current_len),
            });
        }

        self.size = u16::try_from(new_len).map_err(|_| TpmError::BufferOverflow {
            offset: current_len,
            needed: slice.len(),
            available: (u16::MAX as usize).saturating_sub(current_len),
        })?;

        for (dest, src) in self.data[current_len..new_len].iter_mut().zip(slice) {
            dest.write(*src);
        }
        Ok(())
    }
}

impl<const CAPACITY: usize> Deref for TpmBuffer<CAPACITY> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let size = self.size as usize;

        // SAFETY: The first `size` bytes are initialized by the mutation APIs,
        // and `MaybeUninit<u8>` has the same layout as `u8`.
        unsafe { slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), size) }
    }
}

impl<const CAPACITY: usize> Default for TpmBuffer<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> PartialEq for TpmBuffer<CAPACITY> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<const CAPACITY: usize> Eq for TpmBuffer<CAPACITY> {}

impl<const CAPACITY: usize> Hash for TpmBuffer<CAPACITY> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

impl<const CAPACITY: usize> TpmSized for TpmBuffer<CAPACITY> {
    const SIZE: usize = size_of::<TpmUint16>() + CAPACITY;
    fn len(&self) -> usize {
        size_of::<TpmUint16>() + self.size as usize
    }
}

impl<const CAPACITY: usize> TpmMarshal for TpmBuffer<CAPACITY> {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        TpmUint16::from(self.size).marshal(writer)?;
        writer.write_bytes(self)
    }
}

impl<const CAPACITY: usize> TryFrom<&[u8]> for TpmBuffer<CAPACITY> {
    type Error = TpmError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let mut buffer = Self::new();
        buffer.try_extend_from_slice(slice)?;
        Ok(buffer)
    }
}

impl<const CAPACITY: usize> AsRef<[u8]> for TpmBuffer<CAPACITY> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<const CAPACITY: usize> Debug for TpmBuffer<CAPACITY> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TpmBuffer(")?;
        for byte in self.iter() {
            write!(f, "{byte:02X}")?;
        }
        write!(f, ")")
    }
}
