// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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
