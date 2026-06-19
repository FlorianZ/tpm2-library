// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

use tpm2_protocol::{
    basic::{
        Tpm2b as Tpm2bWire, TpmBuffer, TpmInt32, TpmList, TpmUint16, TpmUint32, TpmUint64, TpmUint8,
    },
    data::{
        Tpm2bPublic, Tpm2bPublicWire, TpmAlgId, TpmCc, TpmEccCurve, TpmHt, TpmRh, TpmSt,
        TpmaObject, TpmlDigest, TpmlPcrSelection, TpmsContext, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsPcrSelect, TpmsPcrSelection, TpmsRsaParms, TpmsSchemeHash,
        TpmsSchemeXor, TpmsSignatureEcc, TpmsSignatureRsa, TpmsSymcipherParms, TpmtEccScheme,
        TpmtHa, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme, TpmtSignature,
        TpmtSymDef, TpmtSymDefView, TpmuAsymScheme, TpmuAsymSchemeView, TpmuHa, TpmuHaView,
        TpmuKdfScheme, TpmuKdfSchemeView, TpmuKeyedhashScheme, TpmuKeyedhashSchemeView,
        TpmuPublicId, TpmuPublicIdView, TpmuPublicParms, TpmuPublicParmsView, TpmuSignature,
        TpmuSignatureView, TpmuSymKeyBits, TpmuSymKeyBitsView, TpmuSymMode, TpmuSymModeView,
    },
    TpmField, TpmResult, TpmSized,
};

pub(crate) trait TpmUnmarshal: Sized {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])>;
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
        Ok((Self::try_from(value.data())?, remainder))
    }
}

impl<T: Copy + TpmUnmarshal, const CAPACITY: usize> TpmUnmarshal for TpmList<T, CAPACITY> {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (count, mut cursor) = TpmUint32::unmarshal(buffer)?;
        let mut list = Self::new();

        for _ in 0..count.value() {
            let (item, tail) = T::unmarshal(cursor)?;
            list.try_push(item)?;
            cursor = tail;
        }

        Ok((list, cursor))
    }
}

impl TpmUnmarshal for Tpm2bPublic {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (wire, remainder) = Tpm2bPublicWire::cast_prefix(buffer)?;
        let inner_bytes = &wire.as_bytes()[TpmUint16::SIZE..];
        let (inner, _) = TpmtPublic::unmarshal(inner_bytes)?;
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
        let (parameters, buffer) = TpmuPublicParms::cast_tagged(object_type, buffer)?;
        let parameters = tpmu_public_parms_from_view(&parameters)?;
        let (unique, buffer) = TpmuPublicId::cast_tagged(object_type, buffer)?;
        let unique = tpmu_public_id_from_view(&unique)?;

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

fn tpmu_public_parms_from_view(view: &TpmuPublicParmsView<'_>) -> TpmResult<TpmuPublicParms> {
    Ok(match view {
        TpmuPublicParmsView::KeyedHash(v) => {
            TpmuPublicParms::KeyedHash(TpmsKeyedhashParms::unmarshal(v.as_bytes())?.0)
        }
        TpmuPublicParmsView::SymCipher(v) => {
            TpmuPublicParms::SymCipher(TpmsSymcipherParms::unmarshal(v.as_bytes())?.0)
        }
        TpmuPublicParmsView::Rsa(v) => TpmuPublicParms::Rsa(TpmsRsaParms::unmarshal(v.as_bytes())?.0),
        TpmuPublicParmsView::Ecc(v) => TpmuPublicParms::Ecc(TpmsEccParms::unmarshal(v.as_bytes())?.0),
        TpmuPublicParmsView::Null => TpmuPublicParms::Null,
    })
}

fn tpmu_public_id_from_view(view: &TpmuPublicIdView<'_>) -> TpmResult<TpmuPublicId> {
    Ok(match view {
        TpmuPublicIdView::KeyedHash(v) => TpmuPublicId::KeyedHash(TpmBuffer::try_from(v.data())?),
        TpmuPublicIdView::SymCipher(v) => TpmuPublicId::SymCipher(TpmBuffer::try_from(v.data())?),
        TpmuPublicIdView::Rsa(v) => TpmuPublicId::Rsa(TpmBuffer::try_from(v.data())?),
        TpmuPublicIdView::Ecc(v) => TpmuPublicId::Ecc(TpmsEccPoint::unmarshal(v.as_bytes())?.0),
        TpmuPublicIdView::Null => TpmuPublicId::Null,
    })
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

impl TpmUnmarshal for TpmsPcrSelection {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let ((hash, pcr_select), tail) =
            <TpmsPcrSelection as TpmField>::cast_prefix_field(buffer)?;
        Ok((
            Self {
                hash,
                pcr_select: TpmsPcrSelect::try_from(pcr_select)?,
            },
            tail,
        ))
    }
}

impl TpmUnmarshal for TpmtSymDef {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (view, tail) = <TpmtSymDef as TpmField>::cast_prefix_field(buffer)?;
        let value = match view {
            TpmtSymDefView::Null => Self {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            TpmtSymDefView::Value {
                algorithm,
                key_bits,
                mode,
            } => Self {
                algorithm,
                key_bits: tpmu_sym_key_bits_from_view(&key_bits),
                mode: tpmu_sym_mode_from_view(&mode),
            },
        };
        Ok((value, tail))
    }
}

fn tpmu_sym_key_bits_from_view(view: &TpmuSymKeyBitsView<'_>) -> TpmuSymKeyBits {
    match view {
        TpmuSymKeyBitsView::Aes(v) => TpmuSymKeyBits::Aes(**v),
        TpmuSymKeyBitsView::Sm4(v) => TpmuSymKeyBits::Sm4(**v),
        TpmuSymKeyBitsView::Camellia(v) => TpmuSymKeyBits::Camellia(**v),
        TpmuSymKeyBitsView::Xor(v) => TpmuSymKeyBits::Xor(*v),
        TpmuSymKeyBitsView::Null => TpmuSymKeyBits::Null,
    }
}

fn tpmu_sym_mode_from_view(view: &TpmuSymModeView<'_>) -> TpmuSymMode {
    match view {
        TpmuSymModeView::Aes(v) => TpmuSymMode::Aes(*v),
        TpmuSymModeView::Sm4(v) => TpmuSymMode::Sm4(*v),
        TpmuSymModeView::Camellia(v) => TpmuSymMode::Camellia(*v),
        TpmuSymModeView::Xor(v) => TpmuSymMode::Xor(*v),
        TpmuSymModeView::Null => TpmuSymMode::Null,
    }
}

impl TpmUnmarshal for TpmtKeyedhashScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (view, buffer) = TpmuKeyedhashScheme::cast_tagged(scheme, buffer)?;
        let details = tpmu_keyedhash_scheme_from_view(&view)?;
        Ok((Self { scheme, details }, buffer))
    }
}

fn tpmu_keyedhash_scheme_from_view(
    view: &TpmuKeyedhashSchemeView<'_>,
) -> TpmResult<TpmuKeyedhashScheme> {
    Ok(match view {
        TpmuKeyedhashSchemeView::Hmac(v) => {
            TpmuKeyedhashScheme::Hmac(TpmsSchemeHash::unmarshal(v.as_bytes())?.0)
        }
        TpmuKeyedhashSchemeView::Xor(v) => {
            TpmuKeyedhashScheme::Xor(TpmsSchemeXor::unmarshal(v.as_bytes())?.0)
        }
        TpmuKeyedhashSchemeView::Null => TpmuKeyedhashScheme::Null,
    })
}

impl TpmUnmarshal for TpmtRsaScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (view, buffer) = TpmuAsymScheme::cast_tagged(scheme, buffer)?;
        let details = tpmu_asym_scheme_from_view(&view)?;
        Ok((Self { scheme, details }, buffer))
    }
}

impl TpmUnmarshal for TpmtEccScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (view, buffer) = TpmuAsymScheme::cast_tagged(scheme, buffer)?;
        let details = tpmu_asym_scheme_from_view(&view)?;
        Ok((Self { scheme, details }, buffer))
    }
}

fn tpmu_asym_scheme_from_view(view: &TpmuAsymSchemeView<'_>) -> TpmResult<TpmuAsymScheme> {
    Ok(match view {
        TpmuAsymSchemeView::Hash(v) => TpmuAsymScheme::Hash(TpmsSchemeHash::unmarshal(v.as_bytes())?.0),
        TpmuAsymSchemeView::Null => TpmuAsymScheme::Null,
    })
}

impl TpmUnmarshal for TpmtKdfScheme {
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (scheme, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (view, buffer) = TpmuKdfScheme::cast_tagged(scheme, buffer)?;
        let details = tpmu_kdf_scheme_from_view(&view)?;
        Ok((Self { scheme, details }, buffer))
    }
}

fn tpmu_kdf_scheme_from_view(view: &TpmuKdfSchemeView<'_>) -> TpmResult<TpmuKdfScheme> {
    Ok(match view {
        TpmuKdfSchemeView::Mgf1(v) => TpmuKdfScheme::Mgf1(TpmsSchemeHash::unmarshal(v.as_bytes())?.0),
        TpmuKdfSchemeView::Kdf1Sp800_56a(v) => {
            TpmuKdfScheme::Kdf1Sp800_56a(TpmsSchemeHash::unmarshal(v.as_bytes())?.0)
        }
        TpmuKdfSchemeView::Kdf2(v) => TpmuKdfScheme::Kdf2(TpmsSchemeHash::unmarshal(v.as_bytes())?.0),
        TpmuKdfSchemeView::Kdf1Sp800_108(v) => {
            TpmuKdfScheme::Kdf1Sp800_108(TpmsSchemeHash::unmarshal(v.as_bytes())?.0)
        }
        TpmuKdfSchemeView::Null => TpmuKdfScheme::Null,
    })
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
        let (view, buffer) = TpmuSignature::cast_tagged(sig_alg, buffer)?;
        let signature = tpmu_signature_from_view(&view)?;
        Ok((Self { sig_alg, signature }, buffer))
    }
}

fn tpmu_signature_from_view(view: &TpmuSignatureView<'_>) -> TpmResult<TpmuSignature> {
    Ok(match view {
        TpmuSignatureView::Rsassa(v) => {
            TpmuSignature::Rsassa(TpmsSignatureRsa::unmarshal(v.as_bytes())?.0)
        }
        TpmuSignatureView::Rsapss(v) => {
            TpmuSignature::Rsapss(TpmsSignatureRsa::unmarshal(v.as_bytes())?.0)
        }
        TpmuSignatureView::Ecdsa(v) => {
            TpmuSignature::Ecdsa(TpmsSignatureEcc::unmarshal(v.as_bytes())?.0)
        }
        TpmuSignatureView::Ecdaa(v) => {
            TpmuSignature::Ecdaa(TpmsSignatureEcc::unmarshal(v.as_bytes())?.0)
        }
        TpmuSignatureView::Sm2(v) => TpmuSignature::Sm2(TpmsSignatureEcc::unmarshal(v.as_bytes())?.0),
        TpmuSignatureView::Ecschnorr(v) => {
            TpmuSignature::Ecschnorr(TpmsSignatureEcc::unmarshal(v.as_bytes())?.0)
        }
        TpmuSignatureView::Hmac((hash_alg, digest)) => TpmuSignature::Hmac(TpmtHa {
            hash_alg: *hash_alg,
            digest: tpmu_ha_from_view(digest)?,
        }),
        TpmuSignatureView::Null => TpmuSignature::Null,
    })
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
        let (view, buffer) = TpmuHa::cast_tagged(hash_alg, buffer)?;
        let digest = tpmu_ha_from_view(&view)?;
        Ok((Self { hash_alg, digest }, buffer))
    }
}

fn tpmu_ha_from_view(view: &TpmuHaView<'_>) -> TpmResult<TpmuHa> {
    Ok(match view {
        TpmuHaView::Null => TpmuHa::Null,
        TpmuHaView::Digest(d) => TpmuHa::Digest(TpmBuffer::try_from(*d)?),
    })
}

#[allow(dead_code)]
fn _assert_policy_list_impls() {
    fn assert_unmarshal<T: TpmUnmarshal>() {}

    assert_unmarshal::<TpmlDigest>();
    assert_unmarshal::<TpmlPcrSelection>();
}
