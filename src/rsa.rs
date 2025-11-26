// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen
//! TPM 2.0 RSA cryptographic operations.

use crate::{TpmCryptoError, TpmExternalKey, TpmHash};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    rsa::{Padding, Rsa},
};
use rand::{CryptoRng, RngCore};
use tpm2_protocol::{
    basic::{TpmUint16, TpmUint32},
    data::{
        Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPublicKeyRsa, TpmAlgId, TpmaObject, TpmsRsaParms,
        TpmsSchemeHash, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId,
        TpmuPublicParms,
    },
};

/// RSA public key parameters.
#[derive(Debug, Clone)]
pub struct TpmRsaExternalKey {
    pub n: Tpm2bPublicKeyRsa,
    pub e: u32,
    pub key_bits: u16,
}

impl TryFrom<&TpmtPublic> for TpmRsaExternalKey {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        if public.object_type != TpmAlgId::Rsa {
            return Err(TpmCryptoError::InvalidRsaParameters);
        }

        let params = match &public.parameters {
            TpmuPublicParms::Rsa(params) => Ok(params),
            _ => Err(TpmCryptoError::InvalidRsaParameters),
        }?;

        let n = match &public.unique {
            TpmuPublicId::Rsa(n) => Ok(*n),
            _ => Err(TpmCryptoError::InvalidRsaParameters),
        }?;

        let exponent_u32 = u32::from(params.exponent);
        let e = if exponent_u32 == 0 {
            65537
        } else {
            exponent_u32
        };

        Ok(Self {
            n,
            e,
            key_bits: u16::from(params.key_bits),
        })
    }
}

impl TryFrom<&PKey<Private>> for TpmRsaExternalKey {
    type Error = TpmCryptoError;

    fn try_from(pkey: &PKey<Private>) -> Result<Self, Self::Error> {
        let rsa = pkey
            .rsa()
            .map_err(|_| TpmCryptoError::InvalidRsaParameters)?;
        let n = Tpm2bPublicKeyRsa::try_from(rsa.n().to_vec().as_slice())
            .map_err(|_| TpmCryptoError::InvalidRsaParameters)?;

        let e_bn = rsa.e();
        if e_bn.is_negative() || e_bn.num_bits() > 32 {
            return Err(TpmCryptoError::InvalidRsaParameters);
        }
        let e_bytes = e_bn.to_vec();
        let mut e_buf = [0u8; 4];
        e_buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
        let e = u32::from_be_bytes(e_buf);

        let key_bits =
            u16::try_from(rsa.size() * 8).map_err(|_| TpmCryptoError::InvalidRsaParameters)?;

        Ok(Self { n, e, key_bits })
    }
}

impl TpmExternalKey for TpmRsaExternalKey {
    fn from_der(bytes: &[u8]) -> Result<(Self, Vec<u8>), TpmCryptoError> {
        let pkey =
            PKey::private_key_from_der(bytes).map_err(|_| TpmCryptoError::OperationFailed)?;
        let public_key = TpmRsaExternalKey::try_from(&pkey)?;
        let rsa = pkey
            .rsa()
            .map_err(|_| TpmCryptoError::InvalidRsaParameters)?;
        let sensitive = rsa.p().ok_or(TpmCryptoError::OperationFailed)?.to_vec();
        Ok((public_key, sensitive))
    }

    fn to_public(
        &self,
        hash_alg: TpmAlgId,
        object_attributes: TpmaObject,
        symmetric: TpmtSymDefObject,
    ) -> TpmtPublic {
        TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: hash_alg,
            object_attributes,
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme: TpmtRsaScheme {
                    scheme: TpmAlgId::Oaep,
                    details: TpmuAsymScheme::Hash(TpmsSchemeHash { hash_alg }),
                },
                key_bits: TpmUint16::from(self.key_bits),
                exponent: if self.e == 65537 {
                    TpmUint32::from(0)
                } else {
                    TpmUint32::from(self.e)
                },
            }),
            unique: TpmuPublicId::Rsa(self.n),
        }
    }

    fn to_seed(
        &self,
        name_alg: TpmHash,
        _rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, Tpm2bEncryptedSecret), TpmCryptoError> {
        let seed_size = name_alg.size();
        let mut seed = vec![0u8; seed_size];
        rand_bytes(&mut seed).map_err(|_| TpmCryptoError::OperationFailed)?;

        let encrypted_seed_bytes = self.oaep(name_alg, &seed)?;

        let encrypted_seed = Tpm2bEncryptedSecret::try_from(encrypted_seed_bytes.as_slice())
            .map_err(|_| TpmCryptoError::OutOfMemory)?;

        Ok((seed, encrypted_seed))
    }
}

impl TpmRsaExternalKey {
    /// Performs RSA-OAEP.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::Error::InvalidHash)
    /// when the hash algorithm is not recognized.
    /// Returns [`OperationFailed`](crate::Error::OperationFailed) when an
    /// internal cryptographic operation fails.
    /// Returns [`OutOfMemory`](crate::Error::OutOfMemory) when an allocation
    /// fails.
    fn oaep(&self, name_alg: TpmHash, seed: &[u8]) -> Result<Vec<u8>, TpmCryptoError> {
        let md = Into::<MessageDigest>::into(name_alg);

        let oaep_md = Md::from_nid(md.type_()).ok_or(TpmCryptoError::OperationFailed)?;

        let n = BigNum::from_slice(self.n.as_ref()).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let e = BigNum::from_u32(self.e).map_err(|_| TpmCryptoError::OutOfMemory)?;
        let rsa = Rsa::from_public_components(n, e).map_err(|_| TpmCryptoError::OperationFailed)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| TpmCryptoError::OperationFailed)?;

        let mut ctx = PkeyCtx::new(&pkey).map_err(|_| TpmCryptoError::OutOfMemory)?;

        ctx.encrypt_init()
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        ctx.set_rsa_oaep_md(oaep_md)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        ctx.set_rsa_mgf1_md(oaep_md)
            .map_err(|_| TpmCryptoError::OperationFailed)?;
        ctx.set_rsa_oaep_label(b"DUPLICATE\0")
            .map_err(|_| TpmCryptoError::OperationFailed)?;

        let mut encrypted_seed = vec![0; pkey.size()];
        let len = ctx
            .encrypt(seed, Some(encrypted_seed.as_mut_slice()))
            .map_err(|_| TpmCryptoError::OperationFailed)?;

        encrypted_seed.truncate(len);
        Ok(encrypted_seed)
    }
}
