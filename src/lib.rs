// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 cryptographic for TPM 2.0 interactions.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod ecc;
mod error;
mod hash;
mod rsa;
mod template;

pub use ecc::*;
pub use error::*;
pub use hash::*;
pub use rsa::*;
pub use template::*;

pub const KDF_LABEL_DUPLICATE: &[u8] = b"DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &[u8] = b"INTEGRITY";
pub const KDF_LABEL_STORAGE: &[u8] = b"STORAGE";

/// Trait for cryptographic public keys.
pub trait TpmExternalKey
where
    Self: Sized,
{
    /// TPM buffer type holding the sensitive private component.
    type Sensitive;

    /// Parses a DER-encoded private key.
    ///
    /// Returns the public key structure and the sensitive private component.
    ///
    /// # Errors
    ///
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    fn from_der(bytes: &[u8]) -> Result<(Self, Self::Sensitive), TpmCryptoError>;

    /// Converts the public key to a `TpmtPublic` structure. Populates
    /// `objectAttributes` `nameALg` and `symmetric` fields from the provided
    /// template.
    fn to_public(&self, template: &TpmPublicTemplate) -> tpm2_protocol::data::TpmtPublic;

    /// Creates a seed and an encrypted seed (aka `inSymSeed`) for
    /// `TPM2_Import`.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::TpmCryptoError::Marshal) when marshal
    /// operation on TPM protocol compliant data fails.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    /// Returns [`Unmarshal`](crate::TpmCryptoError::Unmarshal) when unmarshal
    /// operation on TPM protocol compliant data fails.
    fn to_seed(
        &self,
        name_alg: TpmHash,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<
        (
            tpm2_protocol::data::Tpm2bDigest,
            tpm2_protocol::data::Tpm2bEncryptedSecret,
        ),
        TpmCryptoError,
    >;
}

/// Calculates the cryptographics name of a transient or persistent TPM object.
///
/// # Errors
///
/// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the hash
/// algorithm is not recognized.
/// Returns [`Marshal`](crate::TpmCryptoError::Marshal) when marshal operation
/// on TPM protocol compliant data fails.
/// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
/// Returns [`Unmarshal`](crate::TpmCryptoError::Unmarshal) when unmarshal
/// operation on TPM protocol compliant data fails.
pub fn tpm_make_name(
    public: &tpm2_protocol::data::TpmtPublic,
) -> Result<tpm2_protocol::data::Tpm2bName, TpmCryptoError> {
    use tpm2_protocol::{TpmMarshal, TpmSized};

    let name_alg = TpmHash::try_from(public.name_alg)?;
    let alg_bytes = public.name_alg.value().to_be_bytes();

    let mut public_bytes = [0u8; tpm2_protocol::data::TpmtPublic::SIZE];
    let len = {
        let mut writer = tpm2_protocol::TpmWriter::new(&mut public_bytes);
        public
            .marshal(&mut writer)
            .map_err(TpmCryptoError::Marshal)?;
        writer.len()
    };

    let mut digest = [0u8; tpm2_protocol::constant::MAX_DIGEST_SIZE];
    let digest_len = name_alg.digest_into(&[&public_bytes[..len]], &mut digest)?;

    let mut final_buf = [0u8; tpm2_protocol::constant::MAX_DIGEST_SIZE + 2];
    final_buf[..2].copy_from_slice(&alg_bytes);
    final_buf[2..2 + digest_len].copy_from_slice(&digest[..digest_len]);

    tpm2_protocol::data::Tpm2bName::try_from(&final_buf[..2 + digest_len])
        .map_err(TpmCryptoError::Unmarshal)
}
