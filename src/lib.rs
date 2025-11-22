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

use openssl::{
    bn::BigNumContext,
    ec::{EcGroupRef, EcPointRef, PointConversionForm},
};
use rand::{CryptoRng, RngCore};
use tpm2_protocol::{
    constant::MAX_DIGEST_SIZE,
    data::{
        Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, TpmAlgId, TpmaObject, TpmtPublic,
        TpmtSymDefObject,
    },
    TpmMarshal, TpmSized, TpmWriter,
};

pub use ecc::*;
pub use error::*;
pub use hash::*;
pub use rsa::*;

const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// Trait for cryptographic public keys.
pub trait TpmExternalKey
where
    Self: Sized,
{
    /// Parses a DER-encoded private key.
    ///
    /// Returns the public key structure and the sensitive private component.
    ///
    /// # Errors
    ///
    /// Returns [`OperationFailed`](crate::Error::OperationFailed)
    /// when the DER parsing or key extraction fails.
    /// Returns [`InvalidRsaParameters`](crate::Error::InvalidRsaParameters)
    /// when the key is not a valid RSA key.
    /// Returns [`InvalidEccParameters`](crate::Error::InvalidEccParameters)
    /// when the key is not a valid ECC key.
    fn from_der(bytes: &[u8]) -> Result<(Self, Vec<u8>), TpmCryptoError>;

    /// Converts the public key to a `TpmtPublic` structure.
    fn to_public(
        &self,
        hash_alg: TpmAlgId,
        object_attributes: TpmaObject,
        symmetric: TpmtSymDefObject,
    ) -> TpmtPublic;

    /// Creates a seed and an encrypted seed (inSymSeed) for `TPM2_Import`.
    ///
    /// # Errors
    ///
    /// Returns [`OperationFailed`](crate::Error::OperationFailed) if the seed
    /// generation or encryption fails.
    fn to_seed(
        &self,
        name_alg: TpmHash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, Tpm2bEncryptedSecret), TpmCryptoError>;
}

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

/// Calculates the cryptographics name of a transient or persistent TPM object.
///
/// # Errors
///
/// Returns [`InvalidHash`](crate::Error::InvalidHash) when the hash algorithm
/// is not recognized.
/// Returns [`OperationFailed`](crate::Error::OperationFailed) when an internal
/// cryptographic operation fails.
/// Returns [`OutOfMemory`](crate::Error::OutOfMemory) when memory allocation
/// for temporary data fails.
pub fn tpm_make_name(public: &TpmtPublic) -> Result<Tpm2bName, TpmCryptoError> {
    let name_alg = TpmHash::from(public.name_alg);
    let alg_bytes = (public.name_alg as u16).to_be_bytes();

    let len = public.len();
    let mut public_bytes = vec![0u8; len];
    let mut writer = TpmWriter::new(&mut public_bytes);
    public
        .marshal(&mut writer)
        .map_err(TpmCryptoError::Marshal)?;

    let digest = name_alg.digest(&[&public_bytes])?;
    let digest_len = digest.len();

    if digest_len > MAX_DIGEST_SIZE {
        return Err(TpmCryptoError::OperationFailed);
    }

    let mut final_buf = [0u8; MAX_DIGEST_SIZE + 2];
    final_buf[..2].copy_from_slice(&alg_bytes);
    final_buf[2..2 + digest_len].copy_from_slice(&digest);

    Tpm2bName::try_from(&final_buf[..2 + digest_len]).map_err(|_| TpmCryptoError::OperationFailed)
}

/// Converts an OpenSSL `EcPoint` to TPM `(x, y)` coordinate buffers.
///
/// This function handles the uncompressed point byte representation.
///
/// # Errors
///
/// Returns [`OperationFailed`](crate::Error::OperationFailed) if the OpenSSL
/// operation fails or the point format is invalid.
/// Returns [`OutOfMemory`](crate::Error::OutOfMemory) if allocation fails.
fn tpm_make_point(
    point: &EcPointRef,
    group: &EcGroupRef,
    ctx: &mut BigNumContext,
) -> Result<(Tpm2bEccParameter, Tpm2bEccParameter), TpmCryptoError> {
    let pub_bytes = point
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, ctx)
        .map_err(|_| TpmCryptoError::OperationFailed)?;

    if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(TpmCryptoError::InvalidEccParameters);
    }

    let coord_len = (pub_bytes.len() - 1) / 2;
    let x = Tpm2bEccParameter::try_from(&pub_bytes[1..=coord_len])
        .map_err(|_| TpmCryptoError::OperationFailed)?;
    let y = Tpm2bEccParameter::try_from(&pub_bytes[1 + coord_len..])
        .map_err(|_| TpmCryptoError::OperationFailed)?;

    Ok((x, y))
}
