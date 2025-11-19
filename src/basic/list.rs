// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmMarshal, TpmProtocolError, TpmResult, TpmSized, TpmUnmarshal};
use core::{
    convert::TryFrom,
    fmt::Debug,
    mem::{size_of, MaybeUninit},
    ops::Deref,
    slice,
};

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
    /// Returns [`TooManyItems`](crate::TpmProtocolError::TooManyItems) if the list is at
    /// full capacity.
    pub fn try_push(&mut self, item: T) -> Result<(), TpmProtocolError> {
        if self.len >= CAPACITY {
            return Err(TpmProtocolError::TooManyItems);
        }
        self.items[self.len].write(item);
        self.len += 1;
        Ok(())
    }

    /// Appends a slice of elements to the back of the list.
    ///
    /// # Errors
    ///
    /// Returns [`TooManyItems`](crate::TpmProtocolError::TooManyItems) if the list cannot
    /// fit all elements from the slice.
    pub fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TpmProtocolError> {
        let new_len = self
            .len
            .checked_add(slice.len())
            .ok_or(TpmProtocolError::TooManyItems)?;

        if new_len > CAPACITY {
            return Err(TpmProtocolError::TooManyItems);
        }

        for (dest, src) in self.items[self.len..new_len].iter_mut().zip(slice) {
            dest.write(*src);
        }
        self.len = new_len;
        Ok(())
    }
}

#[allow(unsafe_code)]
impl<T: Copy, const CAPACITY: usize> Deref for TpmList<T, CAPACITY> {
    type Target = [T];

    /// # Safety
    ///
    /// This implementation uses `unsafe` to provide a view into the initialized
    /// portion of the list. The caller can rely on this being safe because:
    /// 1. The first `self.len` items are guaranteed to be initialized by the `push` method.
    /// 2. `MaybeUninit<T>` is guaranteed to have the same memory layout as `T`.
    fn deref(&self) -> &Self::Target {
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
    const SIZE: usize = size_of::<u32>() + (T::SIZE * CAPACITY);
    fn len(&self) -> usize {
        size_of::<u32>() + self.iter().map(TpmSized::len).sum::<usize>()
    }
}

impl<T: TpmMarshal + Copy, const CAPACITY: usize> TpmMarshal for TpmList<T, CAPACITY> {
    fn marshal(&self, writer: &mut crate::TpmWriter) -> TpmResult<()> {
        let len = u32::try_from(self.len).map_err(|_| TpmProtocolError::OperationFailed)?;
        TpmMarshal::marshal(&len, writer)?;
        for item in &**self {
            TpmMarshal::marshal(item, writer)?;
        }
        Ok(())
    }
}

impl<T: TpmUnmarshal + Copy, const CAPACITY: usize> TpmUnmarshal for TpmList<T, CAPACITY> {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (count_u32, mut buf) = u32::unmarshal(buf)?;
        let count = count_u32 as usize;
        if count > CAPACITY {
            return Err(TpmProtocolError::TooManyItems);
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
