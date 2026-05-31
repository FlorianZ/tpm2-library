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
}

/// TPM frame marshaling and unmarshaling error type containing variants
/// for all the possible error conditions.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmError {
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

impl core::fmt::Display for TpmError {
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

impl core::error::Error for TpmError {}

pub type TpmResult<T> = Result<T, TpmError>;
