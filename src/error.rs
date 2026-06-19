// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmKeyType;

/// Error type for encoding/decoding and data validation.
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `InvalidPemTag` becomes `invalid pem tag`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
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

    /// Marshaling a TPM protocol encoded object failed.
    Marshal(tpm2_protocol::TpmError),

    /// Decoding PEM encoded data failed.
    PemDecodingFailed(pem::PemError),

    /// Unmarshaling a TPM protocol encoded object failed.
    Unmarshal(tpm2_protocol::TpmError),
}

impl core::fmt::Display for TpmKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for TpmKeyError {}
