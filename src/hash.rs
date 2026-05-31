// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 hash algorithms and cryptographic operations.

use crate::TpmCryptoError;
use openssl::{
    hash::{Hasher, MessageDigest},
    memcmp,
    pkey::PKey,
    sign::Signer,
};
use strum::{Display, EnumString};
use tpm2_protocol::{constant::MAX_DIGEST_SIZE, data::TpmAlgId};

/// TPM 2.0 hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum TpmHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl TryFrom<TpmAlgId> for TpmHash {
    type Error = TpmCryptoError;

    fn try_from(alg: TpmAlgId) -> Result<Self, Self::Error> {
        match alg {
            TpmAlgId::Sha1 => Ok(Self::Sha1),
            TpmAlgId::Sha256 => Ok(Self::Sha256),
            TpmAlgId::Sha384 => Ok(Self::Sha384),
            TpmAlgId::Sha512 => Ok(Self::Sha512),
            TpmAlgId::Sm3_256 => Ok(Self::Sm3_256),
            TpmAlgId::Sha3_256 => Ok(Self::Sha3_256),
            TpmAlgId::Sha3_384 => Ok(Self::Sha3_384),
            TpmAlgId::Sha3_512 => Ok(Self::Sha3_512),
            TpmAlgId::Shake128 => Ok(Self::Shake128),
            TpmAlgId::Shake256 => Ok(Self::Shake256),
            _ => Err(TpmCryptoError::InvalidHash),
        }
    }
}

impl From<TpmHash> for TpmAlgId {
    fn from(alg: TpmHash) -> Self {
        match alg {
            TpmHash::Sha1 => Self::Sha1,
            TpmHash::Sha256 => Self::Sha256,
            TpmHash::Sha384 => Self::Sha384,
            TpmHash::Sha512 => Self::Sha512,
            TpmHash::Sm3_256 => Self::Sm3_256,
            TpmHash::Sha3_256 => Self::Sha3_256,
            TpmHash::Sha3_384 => Self::Sha3_384,
            TpmHash::Sha3_512 => Self::Sha3_512,
            TpmHash::Shake128 => Self::Shake128,
            TpmHash::Shake256 => Self::Shake256,
        }
    }
}

impl From<TpmHash> for MessageDigest {
    fn from(alg: TpmHash) -> Self {
        match alg {
            TpmHash::Sha1 => MessageDigest::sha1(),
            TpmHash::Sha256 => MessageDigest::sha256(),
            TpmHash::Sha384 => MessageDigest::sha384(),
            TpmHash::Sha512 => MessageDigest::sha512(),
            TpmHash::Sm3_256 => MessageDigest::sm3(),
            TpmHash::Sha3_256 => MessageDigest::sha3_256(),
            TpmHash::Sha3_384 => MessageDigest::sha3_384(),
            TpmHash::Sha3_512 => MessageDigest::sha3_512(),
            TpmHash::Shake128 => MessageDigest::shake_128(),
            TpmHash::Shake256 => MessageDigest::shake_256(),
        }
    }
}

impl TpmHash {
    /// Returns the size of the digest size.
    #[must_use]
    pub fn size(&self) -> usize {
        Into::<MessageDigest>::into(*self).size()
    }

    /// Computes a cryptographic digest over a series of data chunks.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the
    /// hash algorithm is not recognized.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn digest(&self, data_chunks: &[&[u8]]) -> Result<Vec<u8>, TpmCryptoError> {
        let mut digest = vec![0; self.size()];
        let len = self.digest_into(data_chunks, &mut digest)?;
        digest.truncate(len);
        Ok(digest)
    }

    /// Computes a cryptographic digest into `output`.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`BufferTooSmall`](crate::TpmCryptoError::BufferTooSmall) when
    /// `output` is too small for the digest.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn digest_into(
        &self,
        data_chunks: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, TpmCryptoError> {
        check_output_len(output, self.size())?;

        let md = (*self).into();
        let mut hasher = Hasher::new(md).map_err(TpmCryptoError::Crypto)?;
        for chunk in data_chunks {
            hasher.update(chunk).map_err(TpmCryptoError::Crypto)?;
        }
        let digest = hasher.finish().map_err(TpmCryptoError::Crypto)?;
        output[..digest.len()].copy_from_slice(digest.as_ref());
        Ok(digest.len())
    }

    /// Computes an HMAC digest over a series of data chunks.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the
    /// hash algorithm is not recognized.
    /// Returns [`KeyIsEmpty`](crate::TpmCryptoError::KeyIsEmpty) when the
    /// provided key is empty.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn hmac(&self, key: &[u8], data_chunks: &[&[u8]]) -> Result<Vec<u8>, TpmCryptoError> {
        let mut hmac = vec![0; self.size()];
        let len = self.hmac_into(key, data_chunks, &mut hmac)?;
        hmac.truncate(len);
        Ok(hmac)
    }

    /// Computes an HMAC digest into `output`.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`BufferTooSmall`](crate::TpmCryptoError::BufferTooSmall) when
    /// `output` is too small for the HMAC digest.
    /// Returns [`KeyIsEmpty`](crate::TpmCryptoError::KeyIsEmpty) when the
    /// provided key is empty.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn hmac_into(
        &self,
        key: &[u8],
        data_chunks: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, TpmCryptoError> {
        if key.is_empty() {
            return Err(TpmCryptoError::KeyIsEmpty);
        }
        let md = (*self).into();
        let public_key = PKey::hmac(key).map_err(TpmCryptoError::Crypto)?;
        let mut signer = Signer::new(md, &public_key).map_err(TpmCryptoError::Crypto)?;
        for chunk in data_chunks {
            signer.update(chunk).map_err(TpmCryptoError::Crypto)?;
        }
        let len = signer.len().map_err(TpmCryptoError::Crypto)?;
        check_output_len(output, len)?;
        signer
            .sign(&mut output[..len])
            .map_err(TpmCryptoError::Crypto)
    }

    /// Verifies an HMAC signature over a series of data chunks.
    ///
    /// # Errors
    ///
    /// Returns [`PermissionDenied`](crate::TpmCryptoError::PermissionDenied)
    /// when the HMAC does not match the expected value.
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the
    /// hash algorithm is not recognized.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn hmac_verify(
        &self,
        key: &[u8],
        data_chunks: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), TpmCryptoError> {
        let expected = self.hmac(key, data_chunks)?;
        if memcmp::eq(&expected, signature) {
            Ok(())
        } else {
            Err(TpmCryptoError::PermissionDenied)
        }
    }

    /// Implements the `KDFa` key derivation function from the TPM
    /// specification.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the
    /// hash algorithm is not recognized.
    /// Returns [`KeyIsEmpty`](crate::TpmCryptoError::KeyIsEmpty) when the
    /// provided key is empty.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn kdfa(
        &self,
        hmac_key: &[u8],
        label: &str,
        context_a: &[u8],
        context_b: &[u8],
        key_bits: u16,
    ) -> Result<Vec<u8>, TpmCryptoError> {
        let mut key_stream = vec![0; (key_bits as usize).div_ceil(8)];
        let len = self.kdfa_into(
            hmac_key,
            label,
            context_a,
            context_b,
            key_bits,
            &mut key_stream,
        )?;
        key_stream.truncate(len);
        Ok(key_stream)
    }

    /// Implements `KDFa` into `output`.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`BufferTooSmall`](crate::TpmCryptoError::BufferTooSmall) when
    /// `output` is too small for the requested key size.
    /// Returns [`KeyIsEmpty`](crate::TpmCryptoError::KeyIsEmpty) when the
    /// provided key is empty.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn kdfa_into(
        &self,
        hmac_key: &[u8],
        label: &str,
        context_a: &[u8],
        context_b: &[u8],
        key_bits: u16,
        output: &mut [u8],
    ) -> Result<usize, TpmCryptoError> {
        if hmac_key.is_empty() {
            return Err(TpmCryptoError::KeyIsEmpty);
        }

        let key_bytes = (key_bits as usize).div_ceil(8);
        check_output_len(output, key_bytes)?;

        let mut counter: u32 = 1;
        let key_bits_bytes = u32::from(key_bits).to_be_bytes();

        let md = (*self).into();
        let pkey = PKey::hmac(hmac_key).map_err(TpmCryptoError::Crypto)?;
        let mut offset = 0;
        let mut block = [0u8; MAX_DIGEST_SIZE];
        let block_len = self.size();

        while offset < key_bytes {
            let counter_bytes = counter.to_be_bytes();
            let hmac_payload = [
                counter_bytes.as_slice(),
                label.as_bytes(),
                &[0u8],
                context_a,
                context_b,
                key_bits_bytes.as_slice(),
            ];

            let mut signer = Signer::new(md, &pkey).map_err(TpmCryptoError::Crypto)?;
            for chunk in &hmac_payload {
                signer.update(chunk).map_err(TpmCryptoError::Crypto)?;
            }
            let len = signer
                .sign(&mut block[..block_len])
                .map_err(TpmCryptoError::Crypto)?;

            let remaining = key_bytes - offset;
            let to_take = remaining.min(len);
            output[offset..offset + to_take].copy_from_slice(&block[..to_take]);
            offset += to_take;

            counter += 1;
        }

        Ok(key_bytes)
    }

    /// Implements the `KDFe` key derivation function from SP 800-56A for ECDH.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHash`](crate::TpmCryptoError::InvalidHash) when the
    /// hash algorithm is not recognized.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn kdfe(
        &self,
        z: &[u8],
        label: &str,
        context_u: &[u8],
        context_v: &[u8],
        key_bits: u16,
    ) -> Result<Vec<u8>, TpmCryptoError> {
        let mut key_stream = vec![0; (key_bits as usize).div_ceil(8)];
        let len = self.kdfe_into(z, label, context_u, context_v, key_bits, &mut key_stream)?;
        key_stream.truncate(len);
        Ok(key_stream)
    }

    /// Implements `KDFe` into `output`.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`BufferTooSmall`](crate::TpmCryptoError::BufferTooSmall) when
    /// `output` is too small for the requested key size.
    /// Returns [`Crypto`](crate::TpmCryptoError::Crypto) when libcrypto fails.
    pub fn kdfe_into(
        &self,
        z: &[u8],
        label: &str,
        context_u: &[u8],
        context_v: &[u8],
        key_bits: u16,
        output: &mut [u8],
    ) -> Result<usize, TpmCryptoError> {
        let key_bytes = (key_bits as usize).div_ceil(8);
        check_output_len(output, key_bytes)?;

        let (label_data, terminator) = if label.as_bytes().last() == Some(&0) {
            (label.as_bytes(), &[][..])
        } else {
            (label.as_bytes(), &[0u8][..])
        };

        let mut counter: u32 = 1;
        let md = (*self).into();
        let mut offset = 0;

        while offset < key_bytes {
            let counter_bytes = counter.to_be_bytes();
            let digest_payload = [
                &counter_bytes,
                z,
                label_data,
                terminator,
                context_u,
                context_v,
            ];

            let mut hasher = Hasher::new(md).map_err(TpmCryptoError::Crypto)?;
            for chunk in &digest_payload {
                hasher.update(chunk).map_err(TpmCryptoError::Crypto)?;
            }
            let result = hasher.finish().map_err(TpmCryptoError::Crypto)?;

            let remaining = key_bytes - offset;
            let to_take = remaining.min(result.len());
            output[offset..offset + to_take].copy_from_slice(&result[..to_take]);
            offset += to_take;

            counter += 1;
        }

        Ok(key_bytes)
    }
}

fn check_output_len(output: &[u8], expected: usize) -> Result<(), TpmCryptoError> {
    if output.len() < expected {
        return Err(TpmCryptoError::BufferTooSmall {
            expected,
            actual: output.len(),
        });
    }

    Ok(())
}
