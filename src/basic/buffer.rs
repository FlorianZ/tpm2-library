// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    basic::TpmUint16, TpmMarshal, TpmProtocolError, TpmResult, TpmSized, TpmUnmarshal, TpmWriter,
};
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
    mem::{size_of, MaybeUninit},
    ops::Deref,
    slice,
};

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
    /// Returns [`OutOfMemory`](crate::TpmProtocolError::OutOfMemory) when the
    /// buffer is full or the size exceeds `u16::MAX`.
    pub fn try_push(&mut self, byte: u8) -> TpmResult<()> {
        if (self.size as usize) >= CAPACITY || self.size == u16::MAX {
            return Err(TpmProtocolError::BufferOverflow);
        }
        self.data[self.size as usize].write(byte);
        self.size += 1;
        Ok(())
    }

    /// Appends a slice of bytes to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfMemory`](crate::TpmProtocolError::OutOfMemory) when the
    /// resulting size exceeds the buffer capacity or `u16::MAX`.
    pub fn try_extend_from_slice(&mut self, slice: &[u8]) -> TpmResult<()> {
        let current_len = self.size as usize;
        let new_len = current_len
            .checked_add(slice.len())
            .ok_or(TpmProtocolError::BufferOverflow)?;

        if new_len > CAPACITY {
            return Err(TpmProtocolError::BufferOverflow);
        }

        self.size = u16::try_from(new_len).map_err(|_| TpmProtocolError::BufferOverflow)?;

        for (dest, src) in self.data[current_len..new_len].iter_mut().zip(slice) {
            dest.write(*src);
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
impl<const CAPACITY: usize> Deref for TpmBuffer<CAPACITY> {
    type Target = [u8];

    /// # Safety
    ///
    /// This implementation uses `unsafe` to provide a view into the initialized
    /// portion of the buffer. The caller can rely on this being safe because:
    /// 1. The first `self.size` bytes are guaranteed to be initialized by the
    ///    `try_push` and `try_extend_from_slice` methods.
    /// 2. `MaybeUninit<u8>` is guaranteed to have the same memory layout as `u8`.
    fn deref(&self) -> &Self::Target {
        let size = self.size as usize;
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

impl<const CAPACITY: usize> TpmUnmarshal for TpmBuffer<CAPACITY> {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (native_size, remainder) = TpmUint16::unmarshal(buf)?;
        let size_usize = u16::from(native_size) as usize;

        if size_usize > CAPACITY {
            return Err(TpmProtocolError::TooManyBytes);
        }

        if remainder.len() < size_usize {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        let mut buffer = Self::new();
        buffer.try_extend_from_slice(&remainder[..size_usize])?;
        Ok((buffer, &remainder[size_usize..]))
    }
}

impl<'a, const CAPACITY: usize> TryFrom<&'a [u8]> for TpmBuffer<CAPACITY> {
    type Error = TpmProtocolError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        if slice.len() > CAPACITY {
            return Err(TpmProtocolError::TooManyBytes);
        }
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
