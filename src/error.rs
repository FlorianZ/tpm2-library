// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2024-2025 Jarkko Sakkinen

/// Error type for encoding/decoding and data validation.
#[derive(Debug, thiserror::Error)]
pub enum TpmKeyError {
    /// Command code in a policy command is not a valid `TPM_CC`.
    #[error("invalid CC: {0}")]
    InvalidCc(tpm2_protocol::data::TpmCc),

    /// ASN.1 object identifier is not one of the supported TPM key OIDs.
    #[error("invalid OID: {0}")]
    InvalidOid(rasn::prelude::ObjectIdentifier),

    /// Invalid importable key algorithm.
    #[error("invalid importable key algorithm: {0:?}")]
    InvalidImportable(tpm2_protocol::data::TpmAlgId),

    /// Invalid loadable key algorithm.
    #[error("invalid loadable key algorithm: {0:?}")]
    InvalidLoadable(tpm2_protocol::data::TpmAlgId),

    /// Invalid sealed key algorithm.
    #[error("invalid sealed key algorithm: {0:?}")]
    InvalidSealed(tpm2_protocol::data::TpmAlgId),

    /// Decoding DER encoded ASN.1 data failed.
    #[error("DER decoding failed: {0}")]
    DerDecodingFailed(rasn::der::de::DecodeError),

    /// Encoding DER encoded ASN.1 data failed.
    #[error("DER encoding failed: {0}")]
    DerEncodingFailed(rasn::der::enc::EncodeError),

    /// PEM tag is not 'TSS2 PRIVATE KEY'.
    #[error("invalid PEM tag: {0}")]
    InvalidPemTag(String),

    /// A policy command body is malformed or invalid for that command.
    #[error("invalid policy")]
    InvalidPolicy,

    /// Importable key is missing its encrypted seed (`secret`).
    #[error("missing secret for importable key")]
    MissingSecret,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    /// Decoding PEM encoded DER data failed.
    #[error("PEM encoding failed: {0}")]
    PemDecodingFailed(pem::PemError),

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
}
