//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 ECC curves and cryptographic operations.

use crate::{Error, Hash, KDF_LABEL_DUPLICATE, UNCOMPRESSED_POINT_TAG};
use num_bigint::{BigUint, RandBigInt};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::PKey,
};
use rand::{CryptoRng, RngCore};
use strum::{Display, EnumString};
use tpm2_protocol::data::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

/// TPM 2.0 ECC curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum EccCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
    #[strum(serialize = "bp-p256-r1")]
    BpP256R1,
    #[strum(serialize = "bp-p384-r1")]
    BpP384R1,
    #[strum(serialize = "bp-p512-r1")]
    BpP512R1,
    Curve25519,
    Curve448,
    None,
}

impl From<TpmEccCurve> for EccCurve {
    fn from(curve: TpmEccCurve) -> Self {
        match curve {
            TpmEccCurve::NistP192 => Self::NistP192,
            TpmEccCurve::NistP224 => Self::NistP224,
            TpmEccCurve::NistP256 => Self::NistP256,
            TpmEccCurve::NistP384 => Self::NistP384,
            TpmEccCurve::NistP521 => Self::NistP521,
            TpmEccCurve::BnP256 => Self::BnP256,
            TpmEccCurve::BnP638 => Self::BnP638,
            TpmEccCurve::Sm2P256 => Self::Sm2P256,
            TpmEccCurve::BpP256R1 => Self::BpP256R1,
            TpmEccCurve::BpP384R1 => Self::BpP384R1,
            TpmEccCurve::BpP512R1 => Self::BpP512R1,
            TpmEccCurve::Curve25519 => Self::Curve25519,
            TpmEccCurve::Curve448 => Self::Curve448,
            TpmEccCurve::None => Self::None,
        }
    }
}

impl From<EccCurve> for TpmEccCurve {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::NistP192 => Self::NistP192,
            EccCurve::NistP224 => Self::NistP224,
            EccCurve::NistP256 => Self::NistP256,
            EccCurve::NistP384 => Self::NistP384,
            EccCurve::NistP521 => Self::NistP521,
            EccCurve::BnP256 => Self::BnP256,
            EccCurve::BnP638 => Self::BnP638,
            EccCurve::Sm2P256 => Self::Sm2P256,
            EccCurve::BpP256R1 => Self::BpP256R1,
            EccCurve::BpP384R1 => Self::BpP384R1,
            EccCurve::BpP512R1 => Self::BpP512R1,
            EccCurve::Curve25519 => Self::Curve25519,
            EccCurve::Curve448 => Self::Curve448,
            EccCurve::None => Self::None,
        }
    }
}

impl EccCurve {
    /// Converts a TPM ECC parameter (big-endian bytes) to an OpenSSL `BigNum`.
    fn parameter_to_bignum(param: &Tpm2bEccParameter) -> Result<BigNum, Error> {
        BigNum::from_slice(param.as_ref()).map_err(|_| Error::OutOfMemory)
    }

    /// Maps a TPM ECC curve ID to an OpenSSL NID.
    fn to_nid(self) -> Result<Nid, Error> {
        match self {
            Self::NistP256 => Ok(Nid::X9_62_PRIME256V1),
            Self::NistP384 => Ok(Nid::SECP384R1),
            Self::NistP521 => Ok(Nid::SECP521R1),
            _ => Err(Error::InvalidEccCurve(self)),
        }
    }

    /// Performs ECDH and derives a seed using `KDFe` key derivation function from
    /// TCG TPM 2.0 Architeture specification.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEccCurve`](crate::Error::InvalidEccCurve)
    /// when the curve is not supported.
    /// Returns [`InvalidHashAlgorithm`](crate::Error::InvalidHashAlgorithm)
    /// when the hash algorithm is not recognized.
    /// Returns [`OperationFailed`](crate::Error::OperationFailed) when an internal
    /// cryptographic operation fails.
    /// Returns [`OutOfMemory`](crate::Error::OutOfMemory) when an allocation fails.
    pub fn ecdh(
        &self,
        parent_point: &TpmsEccPoint,
        name_alg: Hash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, TpmsEccPoint), Error> {
        let nid = (*self).to_nid()?;
        let group = EcGroup::from_curve_name(nid).map_err(|_| Error::OutOfMemory)?;
        let mut ctx = BigNumContext::new().map_err(|_| Error::OutOfMemory)?;

        let parent_x = Self::parameter_to_bignum(&parent_point.x)?;
        let parent_y = Self::parameter_to_bignum(&parent_point.y)?;
        let parent_key = EcKey::from_public_key_affine_coordinates(&group, &parent_x, &parent_y)
            .map_err(|_| Error::OperationFailed)?;
        let parent_public_key =
            PKey::from_ec_key(parent_key).map_err(|_| Error::OperationFailed)?;

        let mut order = BigNum::new().map_err(|_| Error::OutOfMemory)?;
        group
            .order(&mut order, &mut ctx)
            .map_err(|_| Error::OperationFailed)?;
        let order_uint = BigUint::from_bytes_be(&order.to_vec());
        let one = BigUint::from(1u8);

        let priv_uint = rng.gen_biguint_range(&one, &order_uint);
        let priv_bn =
            BigNum::from_slice(&priv_uint.to_bytes_be()).map_err(|_| Error::OutOfMemory)?;

        let mut ephemeral_pub_point = EcPoint::new(&group).map_err(|_| Error::OutOfMemory)?;
        ephemeral_pub_point
            .mul_generator(&group, &priv_bn, &ctx)
            .map_err(|_| Error::OperationFailed)?;
        let ephemeral_key = EcKey::from_private_components(&group, &priv_bn, &ephemeral_pub_point)
            .map_err(|_| Error::OutOfMemory)?;

        let ephemeral_public_key =
            PKey::from_ec_key(ephemeral_key).map_err(|_| Error::OutOfMemory)?;
        let mut deriver = Deriver::new(&ephemeral_public_key).map_err(|_| Error::OutOfMemory)?;
        deriver
            .set_peer(&parent_public_key)
            .map_err(|_| Error::OperationFailed)?;
        let z = deriver
            .derive_to_vec()
            .map_err(|_| Error::OperationFailed)?;

        let ephemeral_pub_bytes = ephemeral_pub_point
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|_| Error::OperationFailed)?;

        if ephemeral_pub_bytes.is_empty() || ephemeral_pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
            return Err(Error::OperationFailed);
        }

        let coord_len = (ephemeral_pub_bytes.len() - 1) / 2;
        let ephemeral_x = &ephemeral_pub_bytes[1..=coord_len];
        let ephemeral_y = &ephemeral_pub_bytes[1 + coord_len..];

        let seed_bits = u16::try_from(name_alg.size()? * 8).map_err(|_| Error::OperationFailed)?;

        let context_u = ephemeral_x;
        let context_v = parent_point.x.as_ref();

        let seed = name_alg.kdfe(&z, KDF_LABEL_DUPLICATE, context_u, context_v, seed_bits)?;

        let ephemeral_point_tpm = TpmsEccPoint {
            x: Tpm2bEccParameter::try_from(ephemeral_x).map_err(|_| Error::OperationFailed)?,
            y: Tpm2bEccParameter::try_from(ephemeral_y).map_err(|_| Error::OperationFailed)?,
        };

        Ok((seed, ephemeral_point_tpm))
    }
}
