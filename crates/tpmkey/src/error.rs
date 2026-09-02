// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmKeyType;

/// Error type for encoding/decoding and data validation.
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `InvalidPemTag` becomes `invalid pem tag`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
#[non_exhaustive]
pub enum TpmKeyError {
    /// Command code in a policy command is not a valid `TPM_CC`.
    InvalidCc(u32),

    /// ASN.1 object identifier is not one of the supported TPM key OIDs.
    InvalidOid(rasn::prelude::ObjectIdentifier),

    /// Public key algorithm is invalid for the key type.
    InvalidKeyAlgorithm(TpmKeyType, tpm2_protocol::data::TpmAlgId),

    /// Decoding ASN.1 DER encoded data failed.
    Asn1DecodingFailed(rasn::der::de::DecodeError),

    /// Encoding ASN.1 DER encoded data failed.
    Asn1EncodingFailed(rasn::der::enc::EncodeError),

    /// PEM tag is not 'TSS2 PRIVATE KEY'.
    InvalidPemTag(String),

    /// A policy command body is malformed or invalid for that command.
    InvalidPolicy,

    /// Importable key is missing its encrypted seed (`secret`).
    MissingSecret,

    /// A loadable key carries a `secret`, which the format forbids.
    UnexpectedSecret,

    /// The `secret` field is not a well-formed `TPM2B_ENCRYPTED_SECRET`.
    InvalidSecret,

    /// Marshaling a TPM protocol encoded object failed.
    Marshal(tpm2_protocol::TpmError),

    /// Decoding PEM encoded data failed.
    PemDecodingFailed(pem::PemError),

    /// Unmarshaling a TPM protocol encoded object failed.
    Unmarshal(tpm2_protocol::TpmError),
}

impl core::fmt::Display for TpmKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for c in self.as_ref().chars() {
            for lc in c.to_lowercase() {
                core::fmt::Write::write_char(f, lc)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for TpmKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Asn1DecodingFailed(err) => Some(err),
            Self::Asn1EncodingFailed(err) => Some(err),
            Self::PemDecodingFailed(err) => Some(err),
            Self::Marshal(err) | Self::Unmarshal(err) => Some(err),
            _ => None,
        }
    }
}
