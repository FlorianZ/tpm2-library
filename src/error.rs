// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

/// Returns the byte offset of a cursor slice inside a base slice.
#[must_use]
pub fn tpm_offset(base: &[u8], cursor: &[u8]) -> usize {
    let base_addr = base.as_ptr() as usize;
    let cursor_addr = cursor.as_ptr() as usize;

    cursor_addr.saturating_sub(base_addr).min(base.len())
}

/// Widens a `usize` count into the `u64` carried by value-bearing errors.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn tpm_value(value: usize) -> u64 {
    value as u64
}

/// TPM frame marshaling and unmarshaling error type.
///
/// Every variant carries the byte `offset` from the start of the parsed buffer
/// along with the diagnostic counts relevant to that failure.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[non_exhaustive]
pub enum TpmError {
    /// A write exceeded the capacity of the destination buffer.
    BufferOverflow {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },

    /// Integer overflow while converting to an integer of a different size.
    IntegerTooLarge {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw value that did not fit.
        value: u64,
    },

    /// Boolean value was expected but the value is neither `0` nor `1`.
    InvalidBoolean {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw value encountered.
        value: u64,
    },

    /// Non-existent command code encountered.
    InvalidCc {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw command code encountered.
        value: u64,
    },

    /// A [`TpmsAttest`](crate::data::TpmsAttest) instance does not begin with
    /// the [`TPM_GENERATED_VALUE`](crate::constant::TPM_GENERATED_VALUE) magic.
    InvalidMagicNumber {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw magic value encountered.
        value: u64,
    },

    /// Invalid TPM response code encountered.
    InvalidRc {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw response code encountered.
        value: u64,
    },

    /// Tag is neither [`Sessions`](crate::data::TpmSt::Sessions) nor
    /// [`NoSessions`](crate::data::TpmSt::NoSessions).
    InvalidTag {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw tag encountered.
        value: u64,
    },

    /// Buffer contains more bytes than allowed by the TCG specifications.
    TooManyBytes {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Maximum allowed byte count.
        limit: usize,
        /// Actual byte count.
        actual: usize,
    },

    /// List contains more items than allowed by the TCG specifications.
    TooManyItems {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Maximum allowed item count.
        limit: usize,
        /// Actual item count.
        actual: usize,
    },

    /// Trailing data left after unmarshaling.
    TrailingData {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Trailing byte or item count.
        actual: usize,
    },

    /// Run out of bytes while unmarshaling.
    UnexpectedEnd {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        available: usize,
    },

    /// The variant accessed is not available.
    VariantNotAvailable {
        /// Byte offset from the start of the buffer.
        offset: usize,
        /// Raw value encountered.
        value: u64,
    },
}

/// Renders [`TpmError`] as its variant name in lowercase, space-separated words
/// (e.g. [`BufferOverflow`](Self::BufferOverflow) renders as `buffer overflow`).
///
/// As the lowest-level crate in the stack, errors expose only the variant name
/// here. Callers read the structured fields directly and decide how to present
/// the diagnostic detail.
impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::BufferOverflow { .. } => "buffer overflow",
            Self::IntegerTooLarge { .. } => "integer too large",
            Self::InvalidBoolean { .. } => "invalid boolean",
            Self::InvalidCc { .. } => "invalid cc",
            Self::InvalidMagicNumber { .. } => "invalid magic number",
            Self::InvalidRc { .. } => "invalid rc",
            Self::InvalidTag { .. } => "invalid tag",
            Self::TooManyBytes { .. } => "too many bytes",
            Self::TooManyItems { .. } => "too many items",
            Self::TrailingData { .. } => "trailing data",
            Self::UnexpectedEnd { .. } => "unexpected end",
            Self::VariantNotAvailable { .. } => "variant not available",
        };

        f.write_str(name)
    }
}

impl core::error::Error for TpmError {}

pub type TpmResult<T> = Result<T, TpmError>;
