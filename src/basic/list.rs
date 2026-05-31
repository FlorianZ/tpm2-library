// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    TpmCast, TpmCastMut, TpmError, TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, basic::TpmUint32,
};
use core::{
    convert::TryFrom,
    fmt::Debug,
    mem::{MaybeUninit, size_of},
    ops::Deref,
    slice,
};

const TPML_COUNT_LEN: usize = size_of::<TpmUint32>();

/// A zero-copy TPML wire view over caller-owned bytes.
#[repr(transparent)]
pub struct Tpml<const CAPACITY: usize>([u8]);

impl<const CAPACITY: usize> Tpml<CAPACITY> {
    /// Casts a byte slice into a TPML wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is shorter than the TPML count field.
    /// Returns [`TooManyItems`](crate::TpmError::TooManyItems) when
    /// the declared item count exceeds `CAPACITY`.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate(buf)?;

        // SAFETY: `validate` checked the TPML header and count limit for this
        // transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts a byte slice into a TPML wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` starts with a complete TPML count
    /// field and that the declared item count does not exceed `CAPACITY`.
    #[must_use]
    pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        let ptr = core::ptr::from_ref(buf) as *const Self;

        // SAFETY: `Tpml` is `repr(transparent)` over `[u8]`, so it has the
        // same layout, metadata, and alignment as the referenced slice.
        unsafe { &*ptr }
    }

    /// Casts a mutable byte slice into a mutable TPML wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is shorter than the TPML count field.
    /// Returns [`TooManyItems`](crate::TpmError::TooManyItems) when
    /// the declared item count exceeds `CAPACITY`.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate(buf)?;

        // SAFETY: `validate` checked the TPML header and count limit for this
        // transparent wire view. The `&mut` input provides exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts a mutable byte slice into a mutable TPML wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` starts with a complete TPML count
    /// field and that the declared item count does not exceed `CAPACITY`. The
    /// returned reference inherits the exclusive access represented by `buf`.
    #[must_use]
    pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        let ptr = core::ptr::from_mut(buf) as *mut Self;

        // SAFETY: `Tpml` is `repr(transparent)` over `[u8]`, so it has the
        // same layout, metadata, and alignment as the referenced slice.
        unsafe { &mut *ptr }
    }

    /// Returns the complete TPML byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the complete mutable TPML byte representation.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the declared item count.
    #[must_use]
    pub fn count(&self) -> usize {
        Self::read_count(&self.0)
    }

    /// Returns the bytes after the count field.
    #[must_use]
    pub fn items_bytes(&self) -> &[u8] {
        &self.0[TPML_COUNT_LEN..]
    }

    /// Returns the mutable bytes after the count field.
    #[must_use]
    pub fn items_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0[TPML_COUNT_LEN..]
    }

    /// Returns the complete TPML wire length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the declared item count is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    fn validate(buf: &[u8]) -> TpmResult<()> {
        if buf.len() < TPML_COUNT_LEN {
            return Err(TpmError::UnexpectedEnd(
                crate::TpmErrorValue::new(0).size(TPML_COUNT_LEN, buf.len()),
            ));
        }

        let item_count = Self::read_count(buf);
        if item_count > CAPACITY {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(CAPACITY, item_count),
            ));
        }

        Ok(())
    }

    fn read_count(buf: &[u8]) -> usize {
        let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

        raw as usize
    }
}

impl<const CAPACITY: usize> TpmCast for Tpml<CAPACITY> {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `Tpml`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl<const CAPACITY: usize> TpmCastMut for Tpml<CAPACITY> {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `Tpml`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl<const CAPACITY: usize> AsRef<[u8]> for Tpml<CAPACITY> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const CAPACITY: usize> AsMut<[u8]> for Tpml<CAPACITY> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

/// A fixed-capacity list for TPM structures, implemented over a fixed-size array.
#[derive(Clone, Copy)]
pub struct TpmList<T: Copy, const CAPACITY: usize> {
    items: [MaybeUninit<T>; CAPACITY],
    len: usize,
}

impl<T: Copy, const CAPACITY: usize> TpmList<T, CAPACITY> {
    /// Creates a new, empty `TpmList`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: [const { MaybeUninit::uninit() }; CAPACITY],
            len: 0,
        }
    }

    /// Returns `true` if the list contains no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends an element to the back of the list.
    ///
    /// # Errors
    ///
    /// Returns [`TooManyItems`](crate::TpmError::TooManyItems) if the list is at
    /// full capacity.
    pub fn try_push(&mut self, item: T) -> Result<(), TpmError> {
        if self.len >= CAPACITY {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(CAPACITY, self.len + 1),
            ));
        }
        self.items[self.len].write(item);
        self.len += 1;
        Ok(())
    }

    /// Appends a slice of elements to the back of the list.
    ///
    /// # Errors
    ///
    /// Returns [`TooManyItems`](crate::TpmError::TooManyItems) if the list cannot
    /// fit all elements from the slice.
    pub fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TpmError> {
        let new_len = self
            .len
            .checked_add(slice.len())
            .ok_or(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(CAPACITY, usize::MAX),
            ))?;

        if new_len > CAPACITY {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(CAPACITY, new_len),
            ));
        }

        for (dest, src) in self.items[self.len..new_len].iter_mut().zip(slice) {
            dest.write(*src);
        }
        self.len = new_len;
        Ok(())
    }
}

impl<T: Copy, const CAPACITY: usize> Deref for TpmList<T, CAPACITY> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        // SAFETY: The first `self.len` items are initialized by the mutation APIs,
        // and `MaybeUninit<T>` has the same layout as `T`.
        unsafe { slice::from_raw_parts(self.items.as_ptr().cast::<T>(), self.len) }
    }
}

impl<T: Copy, const CAPACITY: usize> Default for TpmList<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Debug, const CAPACITY: usize> Debug for TpmList<T, CAPACITY> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Copy + PartialEq, const CAPACITY: usize> PartialEq for TpmList<T, CAPACITY> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Copy + Eq, const CAPACITY: usize> Eq for TpmList<T, CAPACITY> {}

impl<T: TpmSized + Copy, const CAPACITY: usize> TpmSized for TpmList<T, CAPACITY> {
    const SIZE: usize = size_of::<TpmUint32>() + (T::SIZE * CAPACITY);
    fn len(&self) -> usize {
        size_of::<TpmUint32>() + self.iter().map(TpmSized::len).sum::<usize>()
    }
}

impl<T: TpmMarshal + Copy, const CAPACITY: usize> TpmMarshal for TpmList<T, CAPACITY> {
    fn marshal(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        let len = TpmUint32::try_from(self.len).map_err(|_| {
            TpmError::IntegerTooLarge(crate::TpmErrorValue::new(0).value_usize(self.len))
        })?;
        TpmMarshal::marshal(&len, writer)?;
        for item in &**self {
            TpmMarshal::marshal(item, writer)?;
        }
        Ok(())
    }
}

impl<T: TpmUnmarshal + Copy, const CAPACITY: usize> TpmUnmarshal for TpmList<T, CAPACITY> {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (count_u32, mut buf) = TpmUint32::unmarshal(buf)?;
        let count = u32::from(count_u32) as usize;
        if count > CAPACITY {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(CAPACITY, count),
            ));
        }

        let mut list = Self::new();
        for _ in 0..count {
            let (item, rest) = T::unmarshal(buf)?;
            list.try_push(item)?;
            buf = rest;
        }

        Ok((list, buf))
    }
}
