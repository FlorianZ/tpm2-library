// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 ECC curves and cryptographic operations.

use super::TpmPublicTemplate;
use crate::{KDF_LABEL_DUPLICATE, TpmCryptoError, TpmExternalKey, TpmHash, TpmPublicAreaField};
use num_bigint::BigUint;
use num_traits::ops::bytes::ToBytes;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Private},
    rand::rand_bytes,
};
use strum::{Display, EnumString};
use tpm2_protocol::{
    TpmMarshal, TpmWriter,
    constant::{MAX_DIGEST_SIZE, MAX_ECC_KEY_BYTES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, TpmAlgId, TpmEccCurve, TpmsEccParms,
        TpmsEccPoint, TpmsSchemeHash, TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmuAsymScheme,
        TpmuPublicId, TpmuPublicParms,
    },
};

const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// TPM 2.0 ECC curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum TpmEllipticCurve {
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
}

impl TryFrom<TpmEccCurve> for TpmEllipticCurve {
    type Error = TpmCryptoError;

    fn try_from(curve: TpmEccCurve) -> Result<Self, Self::Error> {
        match curve {
            TpmEccCurve::NistP192 => Ok(Self::NistP192),
            TpmEccCurve::NistP224 => Ok(Self::NistP224),
            TpmEccCurve::NistP256 => Ok(Self::NistP256),
            TpmEccCurve::NistP384 => Ok(Self::NistP384),
            TpmEccCurve::NistP521 => Ok(Self::NistP521),
            TpmEccCurve::BnP256 => Ok(Self::BnP256),
            TpmEccCurve::BnP638 => Ok(Self::BnP638),
            TpmEccCurve::Sm2P256 => Ok(Self::Sm2P256),
            TpmEccCurve::BpP256R1 => Ok(Self::BpP256R1),
            TpmEccCurve::BpP384R1 => Ok(Self::BpP384R1),
            TpmEccCurve::BpP512R1 => Ok(Self::BpP512R1),
            TpmEccCurve::Curve25519 => Ok(Self::Curve25519),
            TpmEccCurve::Curve448 => Ok(Self::Curve448),
            curve @ TpmEccCurve::None => Err(TpmCryptoError::InvalidEccCurve(curve)),
        }
    }
}

impl From<TpmEllipticCurve> for TpmEccCurve {
    fn from(curve: TpmEllipticCurve) -> Self {
        match curve {
            TpmEllipticCurve::NistP192 => Self::NistP192,
            TpmEllipticCurve::NistP224 => Self::NistP224,
            TpmEllipticCurve::NistP256 => Self::NistP256,
            TpmEllipticCurve::NistP384 => Self::NistP384,
            TpmEllipticCurve::NistP521 => Self::NistP521,
            TpmEllipticCurve::BnP256 => Self::BnP256,
            TpmEllipticCurve::BnP638 => Self::BnP638,
            TpmEllipticCurve::Sm2P256 => Self::Sm2P256,
            TpmEllipticCurve::BpP256R1 => Self::BpP256R1,
            TpmEllipticCurve::BpP384R1 => Self::BpP384R1,
            TpmEllipticCurve::BpP512R1 => Self::BpP512R1,
            TpmEllipticCurve::Curve25519 => Self::Curve25519,
            TpmEllipticCurve::Curve448 => Self::Curve448,
        }
    }
}

impl TryFrom<TpmEllipticCurve> for Nid {
    type Error = TpmCryptoError;

    /// Maps a TPM ECC curve ID to an OpenSSL NID.
    fn try_from(curve: TpmEllipticCurve) -> Result<Self, Self::Error> {
        match curve {
            TpmEllipticCurve::NistP192 => Ok(Nid::X9_62_PRIME192V1),
            TpmEllipticCurve::NistP224 => Ok(Nid::SECP224R1),
            TpmEllipticCurve::NistP256 => Ok(Nid::X9_62_PRIME256V1),
            TpmEllipticCurve::NistP384 => Ok(Nid::SECP384R1),
            TpmEllipticCurve::NistP521 => Ok(Nid::SECP521R1),
            TpmEllipticCurve::BpP256R1 => Ok(Nid::BRAINPOOL_P256R1),
            TpmEllipticCurve::BpP384R1 => Ok(Nid::BRAINPOOL_P384R1),
            TpmEllipticCurve::BpP512R1 => Ok(Nid::BRAINPOOL_P512R1),
            TpmEllipticCurve::Sm2P256 => Ok(Nid::SM2),
            _ => Err(TpmCryptoError::InvalidEccCurve(curve.into())),
        }
    }
}

impl TryFrom<Nid> for TpmEllipticCurve {
    type Error = TpmCryptoError;

    fn try_from(nid: Nid) -> Result<Self, Self::Error> {
        match nid {
            Nid::X9_62_PRIME192V1 => Ok(TpmEllipticCurve::NistP192),
            Nid::SECP224R1 => Ok(TpmEllipticCurve::NistP224),
            Nid::X9_62_PRIME256V1 => Ok(TpmEllipticCurve::NistP256),
            Nid::SECP384R1 => Ok(TpmEllipticCurve::NistP384),
            Nid::SECP521R1 => Ok(TpmEllipticCurve::NistP521),
            Nid::BRAINPOOL_P256R1 => Ok(TpmEllipticCurve::BpP256R1),
            Nid::BRAINPOOL_P384R1 => Ok(TpmEllipticCurve::BpP384R1),
            Nid::BRAINPOOL_P512R1 => Ok(TpmEllipticCurve::BpP512R1),
            Nid::SM2 => Ok(TpmEllipticCurve::Sm2P256),
            _ => Err(TpmCryptoError::InvalidEccNid(nid)),
        }
    }
}

/// ECC public key parameters.
#[derive(Debug, Clone)]
pub struct TpmEccExternalKey {
    curve: TpmEllipticCurve,
    unique: TpmsEccPoint,
}

impl TpmEccExternalKey {
    /// Creates ECC public key parameters after validating the curve and point shape.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEccCurve`](crate::TpmCryptoError::InvalidEccCurve)
    /// when the curve is not supported by this crate's OpenSSL backend.
    /// Returns [`InvalidEccPoint`](crate::TpmCryptoError::InvalidEccPoint)
    /// when the affine point coordinate sizes do not match the curve.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn try_new(curve: TpmEllipticCurve, unique: TpmsEccPoint) -> Result<Self, TpmCryptoError> {
        let curve_id = curve.into();
        let nid = Nid::try_from(curve)?;
        let group = EcGroup::from_curve_name(nid).map_err(TpmCryptoError::Crypto)?;
        let coord_len = ecc_coord_len(&group)?;

        if unique.x.as_ref().len() != coord_len || unique.y.as_ref().len() != coord_len {
            return Err(TpmCryptoError::InvalidEccPoint {
                curve: curve_id,
                x_len: unique.x.as_ref().len(),
                y_len: unique.y.as_ref().len(),
                expected_len: coord_len,
            });
        }

        Ok(Self { curve, unique })
    }

    /// Returns the curve of the ECC key.
    #[must_use]
    pub fn curve(&self) -> TpmEllipticCurve {
        self.curve
    }
    /// Returns the unique point of the ECC key.
    #[must_use]
    pub fn unique(&self) -> &TpmsEccPoint {
        &self.unique
    }
}

impl TryFrom<&TpmtPublic> for TpmEccExternalKey {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        if public.object_type != TpmAlgId::Ecc {
            return Err(TpmCryptoError::InvalidPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::ObjectType,
            });
        }

        let params = match &public.parameters {
            TpmuPublicParms::Ecc(params) => Ok(params),
            _ => Err(TpmCryptoError::InvalidPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::Parameters,
            }),
        }?;

        let (x, y) = match &public.unique {
            TpmuPublicId::Ecc(point) => Ok((point.x, point.y)),
            _ => Err(TpmCryptoError::InvalidPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::Unique,
            }),
        }?;

        Self::try_new(params.curve_id.try_into()?, TpmsEccPoint { x, y })
    }
}

impl TryFrom<&PKey<Private>> for TpmEccExternalKey {
    type Error = TpmCryptoError;

    fn try_from(pkey: &PKey<Private>) -> Result<Self, Self::Error> {
        let ec_key = pkey.ec_key().map_err(TpmCryptoError::Crypto)?;
        let group = ec_key.group();
        let nid = group
            .curve_name()
            .ok_or(TpmCryptoError::InvalidEccNid(Nid::UNDEF))?;
        let curve = TpmEllipticCurve::try_from(nid)?;

        let mut ctx = BigNumContext::new().map_err(TpmCryptoError::Crypto)?;
        let unique = tpm_make_point(ec_key.public_key(), group, &mut ctx, curve)?;

        Self::try_new(curve, unique)
    }
}

impl TpmExternalKey for TpmEccExternalKey {
    type Sensitive = Tpm2bEccParameter;

    fn from_der(bytes: &[u8]) -> Result<(Self, Self::Sensitive), TpmCryptoError> {
        let pkey = PKey::private_key_from_der(bytes).map_err(TpmCryptoError::Crypto)?;
        let public_key = TpmEccExternalKey::try_from(&pkey)?;
        let ec_key = pkey.ec_key().map_err(TpmCryptoError::Crypto)?;
        let private_key = ec_key.private_key().to_vec();
        let sensitive = Tpm2bEccParameter::try_from(private_key.as_slice()).map_err(|_| {
            TpmCryptoError::InvalidPrivateKeySize {
                len: private_key.len(),
                max: MAX_ECC_KEY_BYTES,
            }
        })?;
        Ok((public_key, sensitive))
    }

    fn to_public(&self, template: &TpmPublicTemplate) -> TpmtPublic {
        TpmtPublic {
            object_type: TpmAlgId::Ecc,
            name_alg: template.name_alg(),
            object_attributes: template.object_attributes(),
            auth_policy: template.auth_policy(),
            parameters: TpmuPublicParms::Ecc(TpmsEccParms {
                symmetric: template.symmetric(),
                scheme: TpmtEccScheme {
                    scheme: TpmAlgId::Ecdh,
                    details: TpmuAsymScheme::Hash(TpmsSchemeHash {
                        hash_alg: template.name_alg(),
                    }),
                },
                curve_id: self.curve.into(),
                kdf: TpmtKdfScheme::default(),
            }),
            unique: TpmuPublicId::Ecc(self.unique),
        }
    }

    fn to_seed(
        &self,
        name_alg: TpmHash,
    ) -> Result<(Tpm2bDigest, Tpm2bEncryptedSecret), TpmCryptoError> {
        let (derived_seed, ephemeral_point) = self.ecdh(name_alg)?;

        let mut point_bytes_buf = [0u8; TPM_MAX_COMMAND_SIZE];
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

impl TpmEccExternalKey {
    /// Performs ECDH and derives a seed using `KDFe` key derivation function
    /// from TCG TPM 2.0 Architecture specification.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEccCurve`](crate::TpmCryptoError::InvalidEccCurve)
    /// when the curve is not supported.
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash)
    /// when the hash algorithm is not recognized.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    fn ecdh(&self, name_alg: TpmHash) -> Result<(Tpm2bDigest, TpmsEccPoint), TpmCryptoError> {
        let nid = Nid::try_from(self.curve)?;
        let group = EcGroup::from_curve_name(nid).map_err(TpmCryptoError::Crypto)?;
        let mut ctx = BigNumContext::new().map_err(TpmCryptoError::Crypto)?;

        let parent_x =
            BigNum::from_slice(self.unique.x.as_ref()).map_err(TpmCryptoError::Crypto)?;
        let parent_y =
            BigNum::from_slice(self.unique.y.as_ref()).map_err(TpmCryptoError::Crypto)?;
        let parent_key = EcKey::from_public_key_affine_coordinates(&group, &parent_x, &parent_y)
            .map_err(TpmCryptoError::Crypto)?;
        let parent_public_key = PKey::from_ec_key(parent_key).map_err(TpmCryptoError::Crypto)?;

        let mut order = BigNum::new().map_err(TpmCryptoError::Crypto)?;
        group
            .order(&mut order, &mut ctx)
            .map_err(TpmCryptoError::Crypto)?;
        let order_uint = BigUint::from_bytes_be(&order.to_vec());
        let one = BigUint::from(1u8);

        let priv_uint = gen_biguint_range(&one, &order_uint)?;
        let priv_bn =
            BigNum::from_slice(&priv_uint.to_be_bytes()).map_err(TpmCryptoError::Crypto)?;

        let mut ephemeral_pub_point = EcPoint::new(&group).map_err(TpmCryptoError::Crypto)?;
        ephemeral_pub_point
            .mul_generator2(&group, &priv_bn, &mut ctx)
            .map_err(TpmCryptoError::Crypto)?;
        let ephemeral_key = EcKey::from_private_components(&group, &priv_bn, &ephemeral_pub_point)
            .map_err(TpmCryptoError::Crypto)?;

        let ephemeral_public_key =
            PKey::from_ec_key(ephemeral_key).map_err(TpmCryptoError::Crypto)?;
        let mut deriver = Deriver::new(&ephemeral_public_key).map_err(TpmCryptoError::Crypto)?;
        deriver
            .set_peer(&parent_public_key)
            .map_err(TpmCryptoError::Crypto)?;
        let z = deriver.derive_to_vec().map_err(TpmCryptoError::Crypto)?;

        let ephemeral = tpm_make_point(&ephemeral_pub_point, &group, &mut ctx, self.curve)?;

        let seed_bits = name_alg.size() * 8;
        let context_u = ephemeral.x.as_ref();
        let context_v = self.unique.x.as_ref();

        let mut seed_buf = [0u8; MAX_DIGEST_SIZE];
        let len = name_alg.kdfe_into(
            &z,
            KDF_LABEL_DUPLICATE,
            context_u,
            context_v,
            seed_bits,
            &mut seed_buf,
        )?;
        let seed = Tpm2bDigest::try_from(&seed_buf[..len]).map_err(TpmCryptoError::Unmarshal)?;

        Ok((seed, ephemeral))
    }
}

fn tpm_make_point(
    point: &EcPointRef,
    group: &EcGroupRef,
    ctx: &mut BigNumContext,
    curve: TpmEllipticCurve,
) -> Result<TpmsEccPoint, TpmCryptoError> {
    let pub_bytes = point
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, ctx)
        .map_err(TpmCryptoError::Crypto)?;

    let expected_len = ecc_coord_len(group)?;
    let point_len = pub_bytes.len().saturating_sub(1);
    let x_len = point_len / 2;
    let y_len = point_len - x_len;

    if pub_bytes.first() != Some(&UNCOMPRESSED_POINT_TAG)
        || x_len != expected_len
        || y_len != expected_len
    {
        return Err(TpmCryptoError::InvalidEccPoint {
            curve: curve.into(),
            x_len,
            y_len,
            expected_len,
        });
    }

    let x = Tpm2bEccParameter::try_from(&pub_bytes[1..=expected_len])
        .map_err(TpmCryptoError::Unmarshal)?;
    let y = Tpm2bEccParameter::try_from(&pub_bytes[1 + expected_len..=2 * expected_len])
        .map_err(TpmCryptoError::Unmarshal)?;

    Ok(TpmsEccPoint { x, y })
}

fn ecc_coord_len(group: &EcGroupRef) -> Result<usize, TpmCryptoError> {
    let degree = group.degree();
    usize::try_from(degree.div_ceil(8)).map_err(|_| TpmCryptoError::InvalidEccGroupDegree(degree))
}

/// Samples a uniform [`BigUint`] in the half-open range `[low, high)` using
/// rejection sampling over the most significant byte mask.
///
/// # Errors
///
/// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
fn gen_biguint_range(low: &BigUint, high: &BigUint) -> Result<BigUint, TpmCryptoError> {
    debug_assert!(low < high);
    let range = high - low;
    let bits = range.bits();
    let byte_len = usize::try_from(bits.div_ceil(8)).unwrap_or(0).max(1);
    let high_mask = match bits % 8 {
        0 => 0xff,
        rem => (1u8 << rem) - 1,
    };
    let mut buf = vec![0u8; byte_len];
    loop {
        rand_bytes(&mut buf).map_err(TpmCryptoError::Crypto)?;
        buf[0] &= high_mask;
        let candidate = BigUint::from_bytes_be(&buf);
        if candidate < range {
            return Ok(low + candidate);
        }
    }
}
