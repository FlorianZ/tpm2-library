// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen
//! TPM 2.0 RSA cryptographic operations.

use super::TpmPublicTemplate;
use crate::{TpmCryptoError, TpmExternalKey, TpmHash, TpmPublicAreaField};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use rand::{CryptoRng, RngCore};
use tpm2_protocol::{
    basic::{TpmUint16, TpmUint32},
    constant::{MAX_DIGEST_SIZE, MAX_RSA_KEY_BYTES},
    data::{
        Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmAlgId,
        TpmsRsaParms, TpmsSchemeHash, TpmtPublic, TpmtRsaScheme, TpmuAsymScheme, TpmuPublicId,
        TpmuPublicParms,
    },
};

/// RSA public key parameters.
#[derive(Debug, Clone)]
pub struct TpmRsaExternalKey {
    public_key: Tpm2bPublicKeyRsa,
    exponent: TpmUint32,
    key_bits: TpmUint16,
}

impl TpmRsaExternalKey {
    /// Creates RSA public key parameters after validating the modulus shape.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidKeyBits`](crate::TpmCryptoError::InvalidKeyBits) when
    /// `key_bits` is zero or not byte-aligned.
    /// Returns [`InvalidRsaModulus`](crate::TpmCryptoError::InvalidRsaModulus)
    /// when the modulus length does not match `key_bits`.
    /// Returns [`InvalidRsaExponent`](crate::TpmCryptoError::InvalidRsaExponent)
    /// when the exponent is not zero, odd, and at least three.
    pub fn try_new(
        public_key: Tpm2bPublicKeyRsa,
        exponent: TpmUint32,
        key_bits: TpmUint16,
    ) -> Result<Self, TpmCryptoError> {
        let key_bits_value = key_bits.value();
        if key_bits_value == 0 || key_bits_value % 8 != 0 {
            return Err(TpmCryptoError::InvalidKeyBits(key_bits_value));
        }

        if public_key.as_ref().len() != usize::from(key_bits_value / 8) {
            return Err(TpmCryptoError::InvalidRsaModulus(
                public_key.as_ref().to_vec(),
            ));
        }

        let exponent_value = exponent.value();
        if exponent_value != 0 && (exponent_value < 3 || exponent_value % 2 == 0) {
            return Err(TpmCryptoError::InvalidRsaExponent(exponent));
        }

        Ok(Self {
            public_key,
            exponent,
            key_bits,
        })
    }

    /// Returns the public key modulus.
    #[must_use]
    pub fn public_key(&self) -> &Tpm2bPublicKeyRsa {
        &self.public_key
    }

    /// Returns the public exponent.
    #[must_use]
    pub fn exponent(&self) -> TpmUint32 {
        self.exponent
    }

    /// Returns the key size in bits.
    #[must_use]
    pub fn key_bits(&self) -> TpmUint16 {
        self.key_bits
    }
}

impl TryFrom<&TpmtPublic> for TpmRsaExternalKey {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        if public.object_type != TpmAlgId::Rsa {
            return Err(TpmCryptoError::InvalidRsaPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::ObjectType,
            });
        }

        let params = match &public.parameters {
            TpmuPublicParms::Rsa(params) => Ok(params),
            _ => Err(TpmCryptoError::InvalidRsaPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::Parameters,
            }),
        }?;

        let n = match &public.unique {
            TpmuPublicId::Rsa(n) => Ok(*n),
            _ => Err(TpmCryptoError::InvalidRsaPublicArea {
                object_type: public.object_type,
                field: TpmPublicAreaField::Unique,
            }),
        }?;

        let exponent_u32 = u32::from(params.exponent);
        let e = if exponent_u32 == 65537 {
            0
        } else {
            exponent_u32
        };

        Self::try_new(n, TpmUint32::new(e), params.key_bits)
    }
}

impl TryFrom<&PKey<Private>> for TpmRsaExternalKey {
    type Error = TpmCryptoError;

    fn try_from(pkey: &PKey<Private>) -> Result<Self, Self::Error> {
        let rsa = pkey.rsa().map_err(TpmCryptoError::Crypto)?;
        let n_bytes = rsa.n().to_vec();
        let n = Tpm2bPublicKeyRsa::try_from(n_bytes.as_slice())
            .map_err(|_| TpmCryptoError::InvalidRsaModulus(n_bytes))?;

        let e_bn = rsa.e();
        if e_bn.is_negative() || e_bn.num_bits() > 32 {
            return Err(TpmCryptoError::InvalidRsaKey);
        }
        let e_bytes = e_bn.to_vec();
        let mut e_buf = [0u8; 4];
        e_buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
        let e = u32::from_be_bytes(e_buf);
        let e = if e == 65537 { 0 } else { e };

        let key_bits = u16::try_from(rsa.size() * 8).map_err(|_| TpmCryptoError::InvalidRsaKey)?;

        Self::try_new(n, TpmUint32::new(e), TpmUint16::new(key_bits))
    }
}

impl TpmExternalKey for TpmRsaExternalKey {
    type Sensitive = Tpm2bPrivateKeyRsa;

    fn from_der(bytes: &[u8]) -> Result<(Self, Self::Sensitive), TpmCryptoError> {
        let pkey = PKey::private_key_from_der(bytes).map_err(TpmCryptoError::Crypto)?;
        let public_key = TpmRsaExternalKey::try_from(&pkey)?;
        let rsa = pkey.rsa().map_err(TpmCryptoError::Crypto)?;
        let p = rsa
            .p()
            .ok_or(TpmCryptoError::MissingRsaPrivatePrime)?
            .to_vec();
        let sensitive = Tpm2bPrivateKeyRsa::try_from(p.as_slice()).map_err(|_| {
            TpmCryptoError::InvalidRsaPrivatePrime {
                len: p.len(),
                max: MAX_RSA_KEY_BYTES / 2,
            }
        })?;
        Ok((public_key, sensitive))
    }

    fn to_public(&self, template: &TpmPublicTemplate) -> TpmtPublic {
        TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: template.name_alg(),
            object_attributes: template.object_attributes(),
            auth_policy: template.auth_policy(),
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                symmetric: template.symmetric(),
                scheme: TpmtRsaScheme {
                    scheme: TpmAlgId::Oaep,
                    details: TpmuAsymScheme::Hash(TpmsSchemeHash {
                        hash_alg: template.name_alg(),
                    }),
                },
                key_bits: self.key_bits,
                exponent: self.exponent,
            }),
            unique: TpmuPublicId::Rsa(self.public_key),
        }
    }

    fn to_seed(
        &self,
        name_alg: TpmHash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Tpm2bDigest, Tpm2bEncryptedSecret), TpmCryptoError> {
        let seed_size = name_alg.size();
        let mut seed_buf = [0u8; MAX_DIGEST_SIZE];
        rng.fill_bytes(&mut seed_buf[..seed_size]);
        let seed =
            Tpm2bDigest::try_from(&seed_buf[..seed_size]).map_err(TpmCryptoError::Unmarshal)?;

        let encrypted_seed_bytes = self.oaep(name_alg, seed.as_ref())?;

        let encrypted_seed = Tpm2bEncryptedSecret::try_from(encrypted_seed_bytes.as_slice())
            .map_err(TpmCryptoError::Unmarshal)?;

        Ok((seed, encrypted_seed))
    }
}

impl TpmRsaExternalKey {
    /// Performs RSA-OAEP.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash)
    /// when the hash algorithm is not recognized.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    fn oaep(&self, name_alg: TpmHash, seed: &[u8]) -> Result<Vec<u8>, TpmCryptoError> {
        let md = Into::<MessageDigest>::into(name_alg);

        let oaep_md = Md::from_nid(md.type_())
            .ok_or_else(|| TpmCryptoError::InvalidMessageDigestNid(md.type_()))?;

        let n = BigNum::from_slice(self.public_key.as_ref()).map_err(TpmCryptoError::Crypto)?;
        let exponent_value = match self.exponent.value() {
            0 => 65537,
            value => value,
        };
        let e = BigNum::from_u32(exponent_value).map_err(TpmCryptoError::Crypto)?;
        let rsa = Rsa::from_public_components(n, e).map_err(TpmCryptoError::Crypto)?;
        let pkey = PKey::from_rsa(rsa).map_err(TpmCryptoError::Crypto)?;

        let mut ctx = PkeyCtx::new(&pkey).map_err(TpmCryptoError::Crypto)?;

        ctx.encrypt_init().map_err(TpmCryptoError::Crypto)?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(TpmCryptoError::Crypto)?;
        ctx.set_rsa_oaep_md(oaep_md)
            .map_err(TpmCryptoError::Crypto)?;
        ctx.set_rsa_mgf1_md(oaep_md)
            .map_err(TpmCryptoError::Crypto)?;
        ctx.set_rsa_oaep_label(b"DUPLICATE\0")
            .map_err(TpmCryptoError::Crypto)?;

        let mut encrypted_seed = vec![0; pkey.size()];
        let len = ctx
            .encrypt(seed, Some(encrypted_seed.as_mut_slice()))
            .map_err(TpmCryptoError::Crypto)?;

        encrypted_seed.truncate(len);
        Ok(encrypted_seed)
    }
}
