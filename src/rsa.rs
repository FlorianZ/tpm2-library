//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//! TPM 2.0 RSA cryptographic operations.

use crate::{Error, Hash};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use tpm2_protocol::data::{Tpm2bPublicKeyRsa, TpmAlgId, TpmtPublic, TpmuPublicId, TpmuPublicParms};

/// RSA public key parameters.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: Tpm2bPublicKeyRsa,
    pub e: u32,
}

impl TryFrom<&TpmtPublic> for RsaPublicKey {
    type Error = Error;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        if public.object_type != TpmAlgId::Rsa {
            return Err(Error::InvalidRsaParameters);
        }

        let params = match &public.parameters {
            TpmuPublicParms::Rsa(params) => Ok(params),
            _ => Err(Error::InvalidRsaParameters),
        }?;

        let n = match &public.unique {
            TpmuPublicId::Rsa(n) => Ok(*n),
            _ => Err(Error::InvalidRsaParameters),
        }?;

        let e = if params.exponent == 0 {
            65537
        } else {
            params.exponent
        };

        Ok(Self { n, e })
    }
}

impl TryFrom<&PKey<Private>> for RsaPublicKey {
    type Error = Error;

    fn try_from(pkey: &PKey<Private>) -> Result<Self, Self::Error> {
        let rsa = pkey.rsa().map_err(|_| Error::InvalidRsaParameters)?;
        let n = Tpm2bPublicKeyRsa::try_from(rsa.n().to_vec().as_slice())
            .map_err(|_| Error::InvalidRsaParameters)?;

        let e_bn = rsa.e();
        if e_bn.is_negative() || e_bn.num_bits() > 32 {
            return Err(Error::InvalidRsaParameters);
        }
        let e_bytes = e_bn.to_vec();
        if e_bytes.len() > 4 {
            return Err(Error::InvalidRsaParameters);
        }
        let mut e_buf = [0u8; 4];
        e_buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
        let e = u32::from_be_bytes(e_buf);

        Ok(Self { n, e })
    }
}

impl RsaPublicKey {
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
    pub fn oaep(&self, name_alg: Hash, seed: &[u8]) -> Result<Vec<u8>, Error> {
        let md = Into::<MessageDigest>::into(name_alg);

        let oaep_md = Md::from_nid(md.type_()).ok_or(Error::OperationFailed)?;

        let n = BigNum::from_slice(self.n.as_ref()).map_err(|_| Error::OutOfMemory)?;
        let e = BigNum::from_u32(self.e).map_err(|_| Error::OutOfMemory)?;
        let rsa = Rsa::from_public_components(n, e).map_err(|_| Error::OperationFailed)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| Error::OperationFailed)?;

        let mut ctx = PkeyCtx::new(&pkey).map_err(|_| Error::OutOfMemory)?;

        ctx.encrypt_init().map_err(|_| Error::OperationFailed)?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|_| Error::OperationFailed)?;
        ctx.set_rsa_oaep_md(oaep_md)
            .map_err(|_| Error::OperationFailed)?;
        ctx.set_rsa_mgf1_md(oaep_md)
            .map_err(|_| Error::OperationFailed)?;
        ctx.set_rsa_oaep_label(b"DUPLICATE\0")
            .map_err(|_| Error::OperationFailed)?;

        let mut encrypted_seed = vec![0; pkey.size()];
        let len = ctx
            .encrypt(seed, Some(encrypted_seed.as_mut_slice()))
            .map_err(|_| Error::OperationFailed)?;

        encrypted_seed.truncate(len);
        Ok(encrypted_seed)
    }
}
