// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmError, TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, TpmWriter};
use core::{convert::TryFrom, fmt::Debug, mem::size_of, ops::Deref};

/// A buffer in the native TPM2B wire format.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmBuffer<const CAPACITY: usize> {
    size: u16,
    data: [u8; CAPACITY],
}

impl<const CAPACITY: usize> TpmBuffer<CAPACITY> {
    /// Creates a new, empty `TpmBuffer`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: 0,
            data: [0; CAPACITY],
        }
    }

    /// Reads the size field from the buffer's header.
    fn size(&self) -> u16 {
        u16::from_be(self.size)
    }

    /// Writes the size field to the buffer's header.
    fn set_size(&mut self, size: u16) {
        self.size = size.to_be();
    }
}

impl<const CAPACITY: usize> Deref for TpmBuffer<CAPACITY> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let size = self.size() as usize;
        &self.data[..size]
    }
}

impl<const CAPACITY: usize> Default for TpmBuffer<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> TpmSized for TpmBuffer<CAPACITY> {
    const SIZE: usize = size_of::<u16>() + CAPACITY;
    fn len(&self) -> usize {
        size_of::<u16>() + self.size() as usize
    }
}

impl<const CAPACITY: usize> TpmMarshal for TpmBuffer<CAPACITY> {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        let native_size = self.size();
        native_size.marshal(writer)?;
        writer.write_bytes(&self.data[..native_size as usize])
    }
}

impl<const CAPACITY: usize> TpmUnmarshal for TpmBuffer<CAPACITY> {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (native_size, remainder) = u16::unmarshal(buf)?;
        let size_usize = native_size as usize;

        if size_usize > CAPACITY {
            return Err(TpmError::CapacityExceeded);
        }

        if remainder.len() < size_usize {
            return Err(TpmError::Truncated);
        }

        let mut buffer = Self::new();
        buffer.set_size(native_size);
        buffer.data[..size_usize].copy_from_slice(&remainder[..size_usize]);
        Ok((buffer, &remainder[size_usize..]))
    }
}

impl<const CAPACITY: usize> TryFrom<&[u8]> for TpmBuffer<CAPACITY> {
    type Error = TpmError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() > CAPACITY {
            return Err(TpmError::CapacityExceeded);
        }
        let mut buffer = Self::new();
        let len_u16 = u16::try_from(slice.len())?;
        buffer.set_size(len_u16);
        buffer.data[..slice.len()].copy_from_slice(slice);
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
