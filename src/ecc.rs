// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 ECC curves and cryptographic operations.

use crate::{Hash, TpmCryptoError, TpmPublicKey, KDF_LABEL_DUPLICATE};
use num_bigint::{BigUint, RandBigInt};
use num_traits::ops::bytes::ToBytes;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Private},
};
use rand::{CryptoRng, RngCore};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, TpmAlgId, TpmEccCurve, TpmaObject,
        TpmsEccParms, TpmsEccPoint, TpmsSchemeHash, TpmtEccScheme, TpmtKdfScheme, TpmtPublic,
        TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId, TpmuPublicParms,
    },
    TpmMarshal, TpmWriter,
};

fn from_ecc_curve_to_nid(value: TpmEccCurve) -> Nid {
    match value {
        TpmEccCurve::NistP192 => Nid::X9_62_PRIME192V1,
        TpmEccCurve::NistP224 => Nid::SECP224R1,
        TpmEccCurve::NistP256 => Nid::X9_62_PRIME256V1,
        TpmEccCurve::NistP384 => Nid::SECP384R1,
        TpmEccCurve::NistP521 => Nid::SECP521R1,
        TpmEccCurve::BpP256R1 => Nid::BRAINPOOL_P256R1,
        TpmEccCurve::BpP384R1 => Nid::BRAINPOOL_P384R1,
        TpmEccCurve::BpP512R1 => Nid::BRAINPOOL_P512R1,
        TpmEccCurve::Sm2P256 => Nid::SM2,
        _ => Nid::UNDEF,
    }
}

fn from_nid_to_ecc_curve(value: Nid) -> TpmEccCurve {
    match value {
        Nid::X9_62_PRIME192V1 => TpmEccCurve::NistP192,
        Nid::SECP224R1 => TpmEccCurve::NistP224,
        Nid::X9_62_PRIME256V1 => TpmEccCurve::NistP256,
        Nid::SECP384R1 => TpmEccCurve::NistP384,
        Nid::SECP521R1 => TpmEccCurve::NistP521,
        Nid::BRAINPOOL_P256R1 => TpmEccCurve::BpP256R1,
        Nid::BRAINPOOL_P384R1 => TpmEccCurve::BpP384R1,
        Nid::BRAINPOOL_P512R1 => TpmEccCurve::BpP512R1,
        Nid::SM2 => TpmEccCurve::Sm2P256,
        _ => TpmEccCurve::None,
    }
}

/// ECC public key parameters.
#[derive(Debug, Clone)]
pub struct TpmEccPublicKey {
    pub curve: TpmEccCurve,
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

impl TryFrom<&TpmtPublic> for TpmEccPublicKey {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        let params = match &public.parameters {
            TpmuPublicParms::Ecc(params) => Ok(params),
            _ => Err(TpmCryptoError::InvalidEccParameters),
        }?;

        let (x, y) = match &public.unique {
            TpmuPublicId::Ecc(point) => Ok((point.x, point.y)),
            _ => Err(TpmCryptoError::InvalidEccParameters),
        }?;

        Ok(Self {
            curve: params.curve_id.into(),
            x,
            y,
        })
    }
}

impl TryFrom<&PKey<Private>> for TpmEccPublicKey {
    type Error = TpmCryptoError;

    fn try_from(pkey: &PKey<Private>) -> Result<Self, Self::Error> {
        let ec_key = pkey
            .ec_key()
            .map_err(|_| TpmCryptoError::InvalidEccParameters)?;
        let group = ec_key.group();
        let nid = group
            .curve_name()
            .ok_or(TpmCryptoError::InvalidEccParameters)?;
        let curve = from_nid_to_ecc_curve(nid);

        let mut ctx = BigNumContext::new().map_err(|_| TpmCryptoError::OutOfMemory)?;
        let (x, y) = crate::tpm_make_point(ec_key.public_key(), group, &mut ctx)?;

        Ok(Self { curve, x, y })
    }
}

impl TpmPublicKey for TpmEccPublicKey {
    fn from_der(bytes: &[u8]) -> Result<(Self, Vec<u8>), TpmCryptoError> {
        let pkey =
            PKey::private_key_from_der(bytes).map_err(|_| TpmCryptoError::OperationFailed)?;
        let public_key = TpmEccPublicKey::try_from(&pkey)?;
        let ec_key = pkey
            .ec_key()
            .map_err(|_| TpmCryptoError::InvalidEccParameters)?;
        let sensitive = ec_key.private_key().to_vec();
        Ok((public_key, sensitive))
    }

    fn to_public(&self, hash_alg: TpmAlgId, symmetric: TpmtSymDefObject) -> TpmtPublic {
        tpm2_protocol::data::TpmtPublic {
            object_type: TpmAlgId::Ecc,
            name_alg: hash_alg,
            object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme: TpmtEccScheme {
                    scheme: TpmAlgId::Ecdh,
                    details: TpmuAsymScheme::Hash(TpmsSchemeHash { hash_alg }),
                },
                curve_id: self.curve.into(),
                kdf: TpmtKdfScheme::default(),
            }),
            unique: TpmuPublicId::Ecc(TpmsEccPoint {
                x: self.x,
                y: self.y,
            }),
        }
    }

    fn to_seed(
        &self,
        name_alg: Hash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, Tpm2bEncryptedSecret), TpmCryptoError> {
        let (derived_seed, ephemeral_point) = self.ecdh(name_alg, rng)?;

        let mut point_bytes_buf = [0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut point_bytes_buf);
            ephemeral_point
                .marshal(&mut writer)
                .map_err(TpmCryptoError::Marshal)?;
            writer.len()
        };
        let point_bytes = &point_bytes_buf[..len];

        let secret =
            Tpm2bEncryptedSecret::try_from(point_bytes).map_err(TpmCryptoError::Unmarshal)?;

        Ok((derived_seed, secret))
    }
}

impl TpmEccPublicKey {
    /// Performs ECDH and derives a seed using `KDFe` key derivation function from
    /// TCG TPM 2.0 Architecture specification.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEccCurve`](crate::Error::InvalidEccCurve)
    /// when the curve is not supported.
    /// Returns [`InvalidHash`](crate::Error::InvalidHash)
    /// when the hash algorithm is not recognized.
    /// Returns [`OperationFailed`](crate::Error::OperationFailed) when an internal
    /// cryptographic operation fails.
    /// Returns [`OutOfMemory`](crate::Error::OutOfMemory) when an allocation fails.
    fn ecdh(
        &self,
        name_alg: Hash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, TpmsEccPoint), TpmCryptoError> {
        let nid = from_ecc_curve_to_nid(self.curve);
        if nid == Nid::UNDEF {
            return Err(TpmCryptoError::InvalidEccCurve);
        }
        let group = EcGroup::from_curve_name(nid).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let mut ctx = BigNumContext::new().map_err(|_| TpmCryptoError::OutOfMemory)?;

        let parent_x =
            BigNum::from_slice(self.x.as_ref()).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let parent_y =
            BigNum::from_slice(self.y.as_ref()).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let parent_key = EcKey::from_public_key_affine_coordinates(&group, &parent_x, &parent_y)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        let parent_public_key =
            PKey::from_ec_key(parent_key).map_err(|_| TpmCryptoError::OperationFailed)?;

        let mut order = BigNum::new().map_err(|_| TpmCryptoError::OutOfMemory)?;
        group
            .order(&mut order, &mut ctx)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        let order_uint = BigUint::from_bytes_be(&order.to_vec());
        let one = BigUint::from(1u8);

        let priv_uint = rng.gen_biguint_range(&one, &order_uint);
        let priv_bn = BigNum::from_slice(&priv_uint.to_be_bytes())
            .map_err(|_| TpmCryptoError::OutOfMemory)?;

        let mut ephemeral_pub_point =
            EcPoint::new(&group).map_err(|_| TpmCryptoError::OutOfMemory)?;
        ephemeral_pub_point
            .mul_generator(&group, &priv_bn, &ctx)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        let ephemeral_key = EcKey::from_private_components(&group, &priv_bn, &ephemeral_pub_point)
            .map_err(|_| TpmCryptoError::OutOfMemory)?;

        let ephemeral_public_key =
            PKey::from_ec_key(ephemeral_key).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let mut deriver =
            Deriver::new(&ephemeral_public_key).map_err(|_| TpmCryptoError::OutOfMemory)?;
        deriver
            .set_peer(&parent_public_key)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        let z = deriver
            .derive_to_vec()
            .map_err(|_| TpmCryptoError::OperationFailed)?;

        let (ephemeral_x, ephemeral_y) =
            crate::tpm_make_point(&ephemeral_pub_point, &group, &mut ctx)?;

        let seed_bits =
            u16::try_from(name_alg.size() * 8).map_err(|_| TpmCryptoError::OperationFailed)?;
        let context_u = ephemeral_x.as_ref();
        let context_v = self.x.as_ref();

        let seed = name_alg.kdfe(&z, KDF_LABEL_DUPLICATE, context_u, context_v, seed_bits)?;

        let ephemeral_point_tpm = TpmsEccPoint {
            x: ephemeral_x,
            y: ephemeral_y,
        };

        Ok((seed, ephemeral_point_tpm))
    }
}
