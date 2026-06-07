// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

use tpm2_protocol::{
    basic::{
        Tpm2b as Tpm2bWire, TpmBuffer, TpmInt32, TpmList, TpmUint16, TpmUint32, TpmUint64, TpmUint8,
    },
    data::{
        Tpm2bPublic, TpmAlgId, TpmCc, TpmEccCurve, TpmHt, TpmRh, TpmSt, TpmaObject, TpmlDigest,
        TpmlPcrSelection, TpmsContext, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms,
        TpmsPcrSelect, TpmsPcrSelection, TpmsRsaParms, TpmsSchemeHash, TpmsSchemeXor,
        TpmsSignatureEcc, TpmsSignatureRsa, TpmsSymcipherParms, TpmtEccScheme, TpmtHa,
        TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme, TpmtSignature, TpmtSymDef,
        TpmuAsymScheme, TpmuHa, TpmuKdfScheme, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms,
        TpmuSignature, TpmuSymKeyBits, TpmuSymMode,
    },
    TpmError, TpmErrorValue, TpmField, TpmResult, TpmSized,
};

pub(crate) trait TpmUnmarshal: Sized {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])>;
}

trait TpmUnmarshalTagged<Tag>: Sized {
    fn unmarshal_tagged(tag: Tag, buffer: &[u8]) -> TpmResult<(Self, &[u8])>;
}

macro_rules! impl_integer_unmarshal {
    ($($ty:ty),* $(,)?) => {
        $(
            impl TpmUnmarshal for $ty {
                fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
                    let (value, remainder) = <$ty>::cast_prefix(buffer)?;
                    Ok((*value, remainder))
                }
            }
        )*
    };
}

macro_rules! impl_field_unmarshal {
    ($($ty:ty),* $(,)?) => {
        $(
            impl TpmUnmarshal for $ty {
                fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
                    <$ty as TpmField>::cast_prefix_field(buffer)
                }
            }
        )*
    };
}

impl_integer_unmarshal!(TpmUint8, TpmUint16, TpmUint32, TpmUint64, TpmInt32);
impl_field_unmarshal!(
    TpmAlgId,
    TpmCc,
    TpmEccCurve,
    TpmHt,
    TpmRh,
    TpmSt,
    TpmaObject
);

impl<const CAPACITY: usize> TpmUnmarshal for TpmBuffer<CAPACITY> {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (value, remainder) = Tpm2bWire::<CAPACITY>::cast_prefix(buffer)?;
        Ok((Self::try_from(value.payload())?, remainder))
    }
}

impl<T: Copy + TpmUnmarshal, const CAPACITY: usize> TpmUnmarshal for TpmList<T, CAPACITY> {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (count, mut cursor) = TpmUint32::unmarshal(buffer)?;
        let count = usize::try_from(count.value()).map_err(|_| {
            TpmError::IntegerTooLarge(TpmErrorValue::new(0).value(u64::from(count.value())))
        })?;
        let mut list = Self::new();

        for _ in 0..count {
            let (item, tail) = T::unmarshal(cursor)?;
            list.try_push(item)?;
            cursor = tail;
        }

        Ok((list, cursor))
    }
}

impl TpmUnmarshal for Tpm2bPublic {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (size, buffer) = TpmUint16::unmarshal(buffer)?;
        let size = usize::from(size.value());
        if buffer.len() < size {
            return Err(TpmError::UnexpectedEnd(
                TpmErrorValue::new(TpmUint16::SIZE).size(size, buffer.len()),
            ));
        }

        let (inner_buffer, remainder) = buffer.split_at(size);
        let (inner, tail) = TpmtPublic::unmarshal(inner_buffer)?;
        if !tail.is_empty() {
            return Err(TpmError::TrailingData(
                TpmErrorValue::new(size.saturating_sub(tail.len())).actual(tail.len()),
            ));
        }

        Ok((Self { inner }, remainder))
    }
}

impl TpmUnmarshal for TpmsContext {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sequence, buffer) = TpmUint64::unmarshal(buffer)?;
        let (saved_handle, buffer) = TpmUint32::unmarshal(buffer)?;
        let (hierarchy, buffer) = TpmRh::unmarshal(buffer)?;
        let (context_blob, buffer) = TpmBuffer::unmarshal(buffer)?;

        Ok((
            Self {
                sequence,
                saved_handle,
                hierarchy,
                context_blob,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (object_type, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (name_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (object_attributes, buffer) = TpmaObject::unmarshal(buffer)?;
        let (auth_policy, buffer) = TpmBuffer::unmarshal(buffer)?;
        let (parameters, buffer) = TpmuPublicParms::unmarshal_tagged(object_type, buffer)?;
        let (unique, buffer) = TpmuPublicId::unmarshal_tagged(object_type, buffer)?;

        Ok((
            Self {
                object_type,
                name_alg,
                object_attributes,
                auth_policy,
                parameters,
                unique,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuPublicParms {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (value, buffer) = TpmsKeyedhashParms::unmarshal(buffer)?;
                Ok((Self::KeyedHash(value), buffer))
            }
            TpmAlgId::SymCipher => {
                let (value, buffer) = TpmsSymcipherParms::unmarshal(buffer)?;
                Ok((Self::SymCipher(value), buffer))
            }
            TpmAlgId::Rsa => {
                let (value, buffer) = TpmsRsaParms::unmarshal(buffer)?;
                Ok((Self::Rsa(value), buffer))
            }
            TpmAlgId::Ecc => {
                let (value, buffer) = TpmsEccParms::unmarshal(buffer)?;
                Ok((Self::Ecc(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuPublicId {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (value, buffer) = TpmBuffer::unmarshal(buffer)?;
                Ok((Self::KeyedHash(value), buffer))
            }
            TpmAlgId::SymCipher => {
                let (value, buffer) = TpmBuffer::unmarshal(buffer)?;
                Ok((Self::SymCipher(value), buffer))
            }
            TpmAlgId::Rsa => {
                let (value, buffer) = TpmBuffer::unmarshal(buffer)?;
                Ok((Self::Rsa(value), buffer))
            }
            TpmAlgId::Ecc => {
                let (value, buffer) = TpmsEccPoint::unmarshal(buffer)?;
                Ok((Self::Ecc(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshal for TpmsKeyedhashParms {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmtKeyedhashScheme::unmarshal(buffer)?;
        Ok((Self { scheme }, buffer))
    }
}

impl TpmUnmarshal for TpmsSymcipherParms {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sym, buffer) = TpmtSymDef::unmarshal(buffer)?;
        Ok((Self { sym }, buffer))
    }
}

impl TpmUnmarshal for TpmsRsaParms {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (symmetric, buffer) = TpmtSymDef::unmarshal(buffer)?;
        let (scheme, buffer) = TpmtRsaScheme::unmarshal(buffer)?;
        let (key_bits, buffer) = TpmUint16::unmarshal(buffer)?;
        let (exponent, buffer) = TpmUint32::unmarshal(buffer)?;

        Ok((
            Self {
                symmetric,
                scheme,
                key_bits,
                exponent,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshal for TpmsEccParms {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (symmetric, buffer) = TpmtSymDef::unmarshal(buffer)?;
        let (scheme, buffer) = TpmtEccScheme::unmarshal(buffer)?;
        let (curve_id, buffer) = TpmEccCurve::unmarshal(buffer)?;
        let (kdf, buffer) = TpmtKdfScheme::unmarshal(buffer)?;

        Ok((
            Self {
                symmetric,
                scheme,
                curve_id,
                kdf,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshal for TpmsEccPoint {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (x, buffer) = TpmBuffer::unmarshal(buffer)?;
        let (y, buffer) = TpmBuffer::unmarshal(buffer)?;
        Ok((Self { x, y }, buffer))
    }
}

impl TpmUnmarshal for TpmsPcrSelect {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (size, buffer) = TpmUint8::unmarshal(buffer)?;
        let size = usize::from(size.value());
        if buffer.len() < size {
            return Err(TpmError::UnexpectedEnd(
                TpmErrorValue::new(TpmUint8::SIZE).size(size, buffer.len()),
            ));
        }

        let (value, buffer) = buffer.split_at(size);
        Ok((Self::try_from(value)?, buffer))
    }
}

impl TpmUnmarshal for TpmsPcrSelection {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (pcr_select, buffer) = TpmsPcrSelect::unmarshal(buffer)?;
        Ok((Self { hash, pcr_select }, buffer))
    }
}

impl TpmUnmarshal for TpmtSymDef {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (algorithm, buffer) = TpmAlgId::unmarshal(buffer)?;
        if algorithm == TpmAlgId::Null {
            return Ok((
                Self {
                    algorithm,
                    key_bits: TpmuSymKeyBits::Null,
                    mode: TpmuSymMode::Null,
                },
                buffer,
            ));
        }

        let (key_bits, buffer) = TpmuSymKeyBits::unmarshal_tagged(algorithm, buffer)?;
        let (mode, buffer) = TpmuSymMode::unmarshal_tagged(algorithm, buffer)?;

        Ok((
            Self {
                algorithm,
                key_bits,
                mode,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuSymKeyBits {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (value, buffer) = TpmUint16::unmarshal(buffer)?;
                Ok((Self::Aes(value), buffer))
            }
            TpmAlgId::Sm4 => {
                let (value, buffer) = TpmUint16::unmarshal(buffer)?;
                Ok((Self::Sm4(value), buffer))
            }
            TpmAlgId::Camellia => {
                let (value, buffer) = TpmUint16::unmarshal(buffer)?;
                Ok((Self::Camellia(value), buffer))
            }
            TpmAlgId::Xor => {
                let (value, buffer) = TpmAlgId::unmarshal(buffer)?;
                Ok((Self::Xor(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuSymMode {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (value, buffer) = TpmAlgId::unmarshal(buffer)?;
                Ok((Self::Aes(value), buffer))
            }
            TpmAlgId::Sm4 => {
                let (value, buffer) = TpmAlgId::unmarshal(buffer)?;
                Ok((Self::Sm4(value), buffer))
            }
            TpmAlgId::Camellia => {
                let (value, buffer) = TpmAlgId::unmarshal(buffer)?;
                Ok((Self::Camellia(value), buffer))
            }
            TpmAlgId::Xor => {
                let (value, buffer) = TpmAlgId::unmarshal(buffer)?;
                Ok((Self::Xor(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshal for TpmtKeyedhashScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (details, buffer) = TpmuKeyedhashScheme::unmarshal_tagged(scheme, buffer)?;
        Ok((Self { scheme, details }, buffer))
    }
}

impl TpmUnmarshal for TpmtRsaScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (details, buffer) = TpmuAsymScheme::unmarshal_tagged(scheme, buffer)?;
        Ok((Self { scheme, details }, buffer))
    }
}

impl TpmUnmarshal for TpmtEccScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (details, buffer) = TpmuAsymScheme::unmarshal_tagged(scheme, buffer)?;
        Ok((Self { scheme, details }, buffer))
    }
}

impl TpmUnmarshal for TpmtKdfScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (details, buffer) = TpmuKdfScheme::unmarshal_tagged(scheme, buffer)?;
        Ok((Self { scheme, details }, buffer))
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuAsymScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsassa
            | TpmAlgId::Rsapss
            | TpmAlgId::Ecdsa
            | TpmAlgId::Ecdaa
            | TpmAlgId::Sm2
            | TpmAlgId::Ecschnorr
            | TpmAlgId::Oaep
            | TpmAlgId::Ecdh
            | TpmAlgId::Ecmqv => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Hash(value), buffer))
            }
            TpmAlgId::Rsaes | TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuKeyedhashScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Hmac => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Hmac(value), buffer))
            }
            TpmAlgId::Xor => {
                let (value, buffer) = TpmsSchemeXor::unmarshal(buffer)?;
                Ok((Self::Xor(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuKdfScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Mgf1 => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Mgf1(value), buffer))
            }
            TpmAlgId::Kdf1Sp800_56A => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Kdf1Sp800_56a(value), buffer))
            }
            TpmAlgId::Kdf2 => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Kdf2(value), buffer))
            }
            TpmAlgId::Kdf1Sp800_108 => {
                let (value, buffer) = TpmsSchemeHash::unmarshal(buffer)?;
                Ok((Self::Kdf1Sp800_108(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshal for TpmsSchemeHash {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        Ok((Self { hash_alg }, buffer))
    }
}

impl TpmUnmarshal for TpmsSchemeXor {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (kdf, buffer) = TpmtKdfScheme::unmarshal(buffer)?;
        Ok((Self { hash_alg, kdf }, buffer))
    }
}

impl TpmUnmarshal for TpmtSignature {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sig_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (signature, buffer) = TpmuSignature::unmarshal_tagged(sig_alg, buffer)?;
        Ok((Self { sig_alg, signature }, buffer))
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuSignature {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsassa => {
                let (value, buffer) = TpmsSignatureRsa::unmarshal(buffer)?;
                Ok((Self::Rsassa(value), buffer))
            }
            TpmAlgId::Rsapss => {
                let (value, buffer) = TpmsSignatureRsa::unmarshal(buffer)?;
                Ok((Self::Rsapss(value), buffer))
            }
            TpmAlgId::Ecdsa => {
                let (value, buffer) = TpmsSignatureEcc::unmarshal(buffer)?;
                Ok((Self::Ecdsa(value), buffer))
            }
            TpmAlgId::Ecdaa => {
                let (value, buffer) = TpmsSignatureEcc::unmarshal(buffer)?;
                Ok((Self::Ecdaa(value), buffer))
            }
            TpmAlgId::Sm2 => {
                let (value, buffer) = TpmsSignatureEcc::unmarshal(buffer)?;
                Ok((Self::Sm2(value), buffer))
            }
            TpmAlgId::Ecschnorr => {
                let (value, buffer) = TpmsSignatureEcc::unmarshal(buffer)?;
                Ok((Self::Ecschnorr(value), buffer))
            }
            TpmAlgId::Hmac => {
                let (value, buffer) = TpmtHa::unmarshal(buffer)?;
                Ok((Self::Hmac(value), buffer))
            }
            TpmAlgId::Null => Ok((Self::Null, buffer)),
            _ => Err(variant_not_available(tag)),
        }
    }
}

impl TpmUnmarshal for TpmsSignatureRsa {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (sig, buffer) = TpmBuffer::unmarshal(buffer)?;
        Ok((Self { hash, sig }, buffer))
    }
}

impl TpmUnmarshal for TpmsSignatureEcc {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (signature_r, buffer) = TpmBuffer::unmarshal(buffer)?;
        let (signature_s, buffer) = TpmBuffer::unmarshal(buffer)?;
        Ok((
            Self {
                hash,
                signature_r,
                signature_s,
            },
            buffer,
        ))
    }
}

impl TpmUnmarshal for TpmtHa {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (digest, buffer) = TpmuHa::unmarshal_tagged(hash_alg, buffer)?;
        Ok((Self { hash_alg, digest }, buffer))
    }
}

impl TpmUnmarshalTagged<TpmAlgId> for TpmuHa {
    fn unmarshal_tagged(tag: TpmAlgId, buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let digest_size = match tag {
            TpmAlgId::Null => return Ok((Self::Null, buffer)),
            TpmAlgId::Sha1 => 20,
            TpmAlgId::Shake256_192 => 24,
            TpmAlgId::Sha256 | TpmAlgId::Sm3_256 | TpmAlgId::Sha3_256 | TpmAlgId::Shake256_256 => {
                32
            }
            TpmAlgId::Sha384 | TpmAlgId::Sha3_384 => 48,
            TpmAlgId::Sha512 | TpmAlgId::Sha3_512 | TpmAlgId::Shake256_512 => 64,
            _ => return Err(variant_not_available(tag)),
        };

        if buffer.len() < digest_size {
            return Err(TpmError::UnexpectedEnd(
                TpmErrorValue::new(0).size(digest_size, buffer.len()),
            ));
        }

        let (digest, buffer) = buffer.split_at(digest_size);
        Ok((Self::Digest(TpmBuffer::try_from(digest)?), buffer))
    }
}

fn variant_not_available(tag: TpmAlgId) -> TpmError {
    TpmError::VariantNotAvailable(TpmErrorValue::new(0).value(u64::from(tag.value())))
}

#[allow(dead_code)]
fn _assert_policy_list_impls() {
    fn assert_unmarshal<T: TpmUnmarshal>() {}

    assert_unmarshal::<TpmlDigest>();
    assert_unmarshal::<TpmlPcrSelection>();
}
