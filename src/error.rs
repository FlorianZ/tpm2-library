// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

/// Additional structured data for a TPM protocol error.
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct TpmErrorValue {
    /// Byte offset from the start of the parsed buffer.
    pub offset: usize,

    /// Raw value associated with the error.
    pub value: u64,

    /// Required byte or item count.
    pub needed: usize,

    /// Available byte or item count.
    pub available: usize,

    /// Maximum allowed byte or item count.
    pub limit: usize,

    /// Actual byte or item count.
    pub actual: usize,
}

impl TpmErrorValue {
    /// Creates empty error data at a byte offset.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self {
            offset,
            value: 0,
            needed: 0,
            available: 0,
            limit: 0,
            actual: 0,
        }
    }

    /// Sets the raw value associated with the error.
    #[must_use]
    pub const fn value(mut self, value: u64) -> Self {
        self.value = value;
        self
    }

    /// Sets a raw `usize` value associated with the error.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn value_usize(mut self, value: usize) -> Self {
        self.value = value as u64;
        self
    }

    /// Sets an actual count without a corresponding limit.
    #[must_use]
    pub const fn actual(mut self, actual: usize) -> Self {
        self.actual = actual;
        self
    }

    /// Sets the required and available counts.
    #[must_use]
    pub const fn size(mut self, needed: usize, available: usize) -> Self {
        self.needed = needed;
        self.available = available;
        self
    }

    /// Sets the maximum allowed and actual counts.
    #[must_use]
    pub const fn limit(mut self, limit: usize, actual: usize) -> Self {
        self.limit = limit;
        self.actual = actual;
        self
    }

    /// Creates error data from a cursor slice inside a base slice.
    #[must_use]
    pub fn at(base: &[u8], cursor: &[u8]) -> Self {
        Self::new(Self::offset(base, cursor))
    }

    /// Returns the byte offset of a cursor slice inside a base slice.
    #[must_use]
    pub fn offset(base: &[u8], cursor: &[u8]) -> usize {
        let base_addr = base.as_ptr() as usize;
        let cursor_addr = cursor.as_ptr() as usize;

        cursor_addr.saturating_sub(base_addr).min(base.len())
    }
}

/// TPM frame marshaling and unmarshaling error type.
///
/// Every variant carries [`TpmErrorValue`] with the byte offset and any
/// applicable raw value, size, or limit information.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmError {
    /// Trying to marshal more bytes than buffer has space. This is unexpected
    /// situation, and should be considered possible bug in the crate itself.
    BufferOverflow(TpmErrorValue),

    /// Integer overflow while converting to an integer of a different size.
    IntegerTooLarge(TpmErrorValue),

    /// Boolean value was expected but the value is neither `0` nor `1`.
    InvalidBoolean(TpmErrorValue),

    /// Non-existent command code encountered.
    InvalidCc(TpmErrorValue),

    /// An [`TpmAttest`](crate::data::TpmAttest) instance contains an invalid
    /// magic value.
    InvalidMagicNumber(TpmErrorValue),

    /// Invalid TPM response code encountered.
    InvalidRc(TpmErrorValue),

    /// Tag is neither [`Sessions`](crate::data::TpmSt::Sessions) nor
    /// [`NoSessions`](crate::data::TpmSt::NoSessions).
    InvalidTag(TpmErrorValue),

    /// Buffer contains more bytes than allowed by the TCG specifications.
    TooManyBytes(TpmErrorValue),

    /// List contains more items than allowed by the TCG specifications.
    TooManyItems(TpmErrorValue),

    /// Trailing data left after unmarshaling.
    TrailingData(TpmErrorValue),

    /// Run out of bytes while unmarshaling.
    UnexpectedEnd(TpmErrorValue),

    /// The variant accessed is not available.
    VariantNotAvailable(TpmErrorValue),
}

impl TpmError {
    /// Returns the structured value carried by the error.
    #[must_use]
    pub const fn value(self) -> TpmErrorValue {
        match self {
            Self::BufferOverflow(value)
            | Self::IntegerTooLarge(value)
            | Self::InvalidBoolean(value)
            | Self::InvalidCc(value)
            | Self::InvalidMagicNumber(value)
            | Self::InvalidRc(value)
            | Self::InvalidTag(value)
            | Self::TooManyBytes(value)
            | Self::TooManyItems(value)
            | Self::TrailingData(value)
            | Self::UnexpectedEnd(value)
            | Self::VariantNotAvailable(value) => value,
        }
    }
}

impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (message, value) = match *self {
            Self::BufferOverflow(value) => ("buffer overflow", value),
            Self::InvalidBoolean(value) => ("invalid boolean value", value),
            Self::InvalidCc(value) => ("invalid command code", value),
            Self::InvalidMagicNumber(value) => ("invalid magic number", value),
            Self::InvalidRc(value) => ("invalid response code", value),
            Self::InvalidTag(value) => ("invalid tag", value),
            Self::IntegerTooLarge(value) => ("integer overflow", value),
            Self::TooManyBytes(value) => ("buffer capacity surpassed", value),
            Self::TooManyItems(value) => ("list capacity surpassed", value),
            Self::TrailingData(value) => ("trailing data", value),
            Self::UnexpectedEnd(value) => ("unexpected end", value),
            Self::VariantNotAvailable(value) => ("enum variant is not available", value),
        };

        write!(f, "{message} at offset {}", value.offset)?;
        if value.value != 0 {
            write!(f, ", value=0x{:x}", value.value)?;
        }
        if value.needed != 0 || value.available != 0 {
            write!(
                f,
                ", needed={}, available={}",
                value.needed, value.available
            )?;
        }
        if value.limit != 0 || value.actual != 0 {
            write!(f, ", limit={}, actual={}", value.limit, value.actual)?;
        }

        Ok(())
    }
}

impl core::error::Error for TpmError {}

pub type TpmResult<T> = Result<T, TpmError>;
