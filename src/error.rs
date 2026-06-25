// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use tpm2_protocol::data::TpmCc;

/// Language interpretation and compilation errors.
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `InvalidToken` becomes `invalid token`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
#[non_exhaustive]
pub enum TpmPolicyError {
    /// A digest calculation failed.
    Crypto(tpm2_crypto::TpmCryptoError),

    /// An invalid command code was encountered.
    InvalidCc(TpmCc),

    /// An invalid expression was encountered.
    InvalidExpression,

    /// Handle type byte is not valid.
    InvalidHandleType(u8),

    /// An invalid token was encountered.
    InvalidToken(String),

    /// An invalid PCR digest was encountered.
    InvalidPcrDigest,

    /// An invalid PCR digest algorithm was encountered.
    InvalidPcrDigestAlgorithm,

    /// An invalid PCR selection was encountered.
    InvalidPcrSelection,

    /// TPM data marshaling failed.
    Marshal(tpm2_protocol::TpmError),

    /// A command stream requires more branches than it has provided.
    CommandStreamBranchUnderflow,

    /// A command stream left unmerged branches after parsing.
    CommandStreamUnbalancedBranches,

    /// Parenthesis mismatch in expression.
    ParenthesisMismatch,

    /// PCR bank is not available.
    PcrBankNotAvailable(tpm2_crypto::TpmHash),

    /// PCR count mismatch.
    PcrCountMismatch,

    /// PCR digest is missing.
    PcrDigestMissing,

    /// PCR digest is too large.
    PcrDigestTooLarge,

    /// PCR index is too large.
    PcrIndexTooLarge,

    /// PCR selection size is too large.
    PcrSelectionTooLarge,

    /// Too many branches were provided.
    TooManyBranches,

    /// After unmarshaling, there was still data left over.
    TrailingData,

    /// Unmarshaling could not be completed because there was not enough data.
    UnexpectedEnd,
}

impl core::fmt::Display for TpmPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for TpmPolicyError {}

impl From<tpm2_crypto::TpmCryptoError> for TpmPolicyError {
    fn from(err: tpm2_crypto::TpmCryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<tpm2_protocol::TpmError> for TpmPolicyError {
    fn from(err: tpm2_protocol::TpmError) -> Self {
        Self::Marshal(err)
    }
}
