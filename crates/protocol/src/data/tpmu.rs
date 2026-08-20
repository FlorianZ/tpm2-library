// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    TpmError, TpmMarshal, TpmResult, TpmSized, TpmWriter,
    basic::{TpmBuffer, TpmUint16},
    constant::{MAX_DIGEST_SIZE, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
        TpmAlgId, TpmCap, TpmHt, TpmSt, TpmlActData, TpmlAlgProperty, TpmlCc, TpmlCca,
        TpmlEccCurve, TpmlHandle, TpmlPcrSelection, TpmlTaggedPolicy, TpmlTaggedTpmProperty,
        TpmsCertifyInfo, TpmsCommandAuditInfo, TpmsCreationInfo, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsNvCertifyInfo, TpmsNvDigestCertifyInfo, TpmsNvPublic,
        TpmsNvPublicExpAttr, TpmsQuoteInfo, TpmsRsaParms, TpmsSchemeHash, TpmsSchemeHmac,
        TpmsSchemeXor, TpmsSessionAuditInfo, TpmsSignatureEcc, TpmsSignatureRsa,
        TpmsSymcipherParms, TpmsTimeAttestInfo, TpmtHa,
    },
};
use core::ops::Deref;

macro_rules! tpmu_view {
    (
        $view:ident, $union:ident, $tag_ty:ty {
            $(
                $variant:ident($field_ty:ty): $($tag:path)|+;
            )*
            $(
                @null $null_variant:ident: $($null_tag:path)|+;
            )?
        }
    ) => {
        pub enum $view<'a>
        where
            $($field_ty: crate::TpmField<'a>,)*
        {
            $(
                $variant(<$field_ty as crate::TpmField<'a>>::View),
            )*
            $(
                $null_variant,
            )?
        }

        impl $union {
            /// Casts a tag-selected union payload into a borrowed view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `tag` does not select a valid variant or
            /// `buf` does not start with a valid selected payload.
            pub fn cast_tagged<'a>(
                tag: $tag_ty,
                buf: &'a [u8],
            ) -> TpmResult<($view<'a>, &'a [u8])>
            where
                $($field_ty: crate::TpmField<'a>,)*
            {
                <Self as crate::TpmTaggedField<'a, $tag_ty>>::cast_tagged_prefix_field(tag, buf)
            }
        }

        impl<'a> crate::TpmTaggedField<'a, $tag_ty> for $union
        where
            $($field_ty: crate::TpmField<'a>,)*
        {
            type View = $view<'a>;

            fn cast_tagged_prefix_field(
                tag: $tag_ty,
                buf: &'a [u8],
            ) -> TpmResult<(Self::View, &'a [u8])> {
                #[allow(unreachable_patterns)]
                match tag {
                    $(
                        $($tag)|+ => {
                            let (value, buf) = <$field_ty as crate::TpmField>::cast_prefix_field(buf)?;
                            Ok(($view::$variant(value), buf))
                        }
                    )*
                    $(
                        $($null_tag)|+ => Ok(($view::$null_variant, buf)),
                    )?
                    _ => Err(TpmError::VariantNotAvailable { offset: 0, value: u64::from(tag.value()) }),
                }
            }
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuAsymScheme {
    Hash(TpmsSchemeHash),
    #[default]
    Null,
}

impl TpmSized for TpmuAsymScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Hash(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuAsymScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Hash(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuAsymSchemeView, TpmuAsymScheme, TpmAlgId {
    Hash(TpmsSchemeHash): TpmAlgId::Rsassa|TpmAlgId::Rsapss|TpmAlgId::Ecdsa|TpmAlgId::Ecdaa|TpmAlgId::Sm2|TpmAlgId::Ecschnorr|TpmAlgId::Oaep|TpmAlgId::Ecdh|TpmAlgId::Ecmqv;
    @null Null: TpmAlgId::Rsaes|TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TpmuCapabilities {
    Algs(TpmlAlgProperty),
    Handles(TpmlHandle),
    Pcrs(TpmlPcrSelection),
    Commands(TpmlCca),
    PpCommands(TpmlCc),
    AuditCommands(TpmlCc),
    TpmProperties(TpmlTaggedTpmProperty),
    EccCurves(TpmlEccCurve),
    AuthPolicies(TpmlTaggedPolicy),
    Act(TpmlActData),
}

impl TpmSized for TpmuCapabilities {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Algs(algs) => algs.len(),
            Self::Handles(handles) => handles.len(),
            Self::Pcrs(pcrs) => pcrs.len(),
            Self::Commands(cmds) => cmds.len(),
            Self::PpCommands(cmds) | Self::AuditCommands(cmds) => cmds.len(),
            Self::TpmProperties(props) => props.len(),
            Self::EccCurves(curves) => curves.len(),
            Self::AuthPolicies(policies) => policies.len(),
            Self::Act(act) => act.len(),
        }
    }
}

impl TpmMarshal for TpmuCapabilities {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Algs(algs) => algs.marshal(writer),
            Self::Handles(handles) => handles.marshal(writer),
            Self::Pcrs(pcrs) => pcrs.marshal(writer),
            Self::Commands(cmds) => cmds.marshal(writer),
            Self::PpCommands(cmds) | Self::AuditCommands(cmds) => cmds.marshal(writer),
            Self::TpmProperties(props) => props.marshal(writer),
            Self::EccCurves(curves) => curves.marshal(writer),
            Self::AuthPolicies(policies) => policies.marshal(writer),
            Self::Act(act) => act.marshal(writer),
        }
    }
}

tpmu_view!(TpmuCapabilitiesView, TpmuCapabilities, TpmCap {
    Algs(TpmlAlgProperty): TpmCap::Algs;
    Handles(TpmlHandle): TpmCap::Handles;
    Pcrs(TpmlPcrSelection): TpmCap::Pcrs;
    Commands(TpmlCca): TpmCap::Commands;
    PpCommands(TpmlCc): TpmCap::PpCommands;
    AuditCommands(TpmlCc): TpmCap::AuditCommands;
    TpmProperties(TpmlTaggedTpmProperty): TpmCap::TpmProperties;
    EccCurves(TpmlEccCurve): TpmCap::EccCurves;
    AuthPolicies(TpmlTaggedPolicy): TpmCap::AuthPolicies;
    Act(TpmlActData): TpmCap::Act;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuHa {
    #[default]
    Null,
    Digest(TpmBuffer<MAX_DIGEST_SIZE>),
}

impl TpmMarshal for TpmuHa {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Null => Ok(()),
            Self::Digest(d) => writer.write_bytes(d),
        }
    }
}

impl TpmSized for TpmuHa {
    const SIZE: usize = MAX_DIGEST_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Digest(d) => d.deref().len(),
        }
    }
}

pub enum TpmuHaView<'a> {
    Null,
    Digest(&'a [u8]),
}

impl TpmuHa {
    /// Casts a tag-selected digest payload into a borrowed view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when `tag` is not a digest algorithm or `buf` is
    /// too short for the selected digest size.
    pub fn cast_tagged<'a>(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(TpmuHaView<'a>, &'a [u8])> {
        <Self as crate::TpmTaggedField<'a, TpmAlgId>>::cast_tagged_prefix_field(tag, buf)
    }
}

impl<'a> crate::TpmTaggedField<'a, TpmAlgId> for TpmuHa {
    type View = TpmuHaView<'a>;

    fn cast_tagged_prefix_field(tag: TpmAlgId, buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        let digest_size = match tag {
            TpmAlgId::Null => return Ok((TpmuHaView::Null, buf)),
            TpmAlgId::Sha1 => 20,
            TpmAlgId::Shake256_192 => 24,
            TpmAlgId::Sha256 | TpmAlgId::Sm3_256 | TpmAlgId::Sha3_256 | TpmAlgId::Shake256_256 => {
                32
            }
            TpmAlgId::Sha384 | TpmAlgId::Sha3_384 => 48,
            TpmAlgId::Sha512 | TpmAlgId::Sha3_512 | TpmAlgId::Shake256_512 => 64,
            _ => {
                return Err(TpmError::VariantNotAvailable {
                    offset: 0,
                    value: u64::from(tag.value()),
                });
            }
        };

        if buf.len() < digest_size {
            return Err(TpmError::UnexpectedEnd {
                offset: 0,
                needed: digest_size,
                available: buf.len(),
            });
        }

        let (digest, buf) = buf.split_at(digest_size);
        Ok((TpmuHaView::Digest(digest), buf))
    }
}

impl Deref for TpmuHa {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Null => &[],
            Self::Digest(d) => d,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    SymCipher(Tpm2bSymKey),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
    #[default]
    Null,
}

impl TpmSized for TpmuPublicId {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash(data) => data.len(),
            Self::SymCipher(data) => data.len(),
            Self::Rsa(data) => data.len(),
            Self::Ecc(point) => point.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuPublicId {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(data) => data.marshal(writer),
            Self::SymCipher(data) => data.marshal(writer),
            Self::Rsa(data) => data.marshal(writer),
            Self::Ecc(point) => point.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuPublicIdView, TpmuPublicId, TpmAlgId {
    KeyedHash(Tpm2bDigest): TpmAlgId::KeyedHash;
    SymCipher(Tpm2bSymKey): TpmAlgId::SymCipher;
    Rsa(Tpm2bPublicKeyRsa): TpmAlgId::Rsa;
    Ecc(TpmsEccPoint): TpmAlgId::Ecc;
    @null Null: TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuPublicParms {
    KeyedHash(TpmsKeyedhashParms),
    SymCipher(TpmsSymcipherParms),
    Rsa(TpmsRsaParms),
    Ecc(TpmsEccParms),
    #[default]
    Null,
}

impl TpmSized for TpmuPublicParms {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::KeyedHash(d) => d.len(),
            Self::SymCipher(d) => d.len(),
            Self::Rsa(d) => d.len(),
            Self::Ecc(d) => d.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuPublicParms {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(d) => d.marshal(writer),
            Self::SymCipher(d) => d.marshal(writer),
            Self::Rsa(d) => d.marshal(writer),
            Self::Ecc(d) => d.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuPublicParmsView, TpmuPublicParms, TpmAlgId {
    KeyedHash(TpmsKeyedhashParms): TpmAlgId::KeyedHash;
    SymCipher(TpmsSymcipherParms): TpmAlgId::SymCipher;
    Rsa(TpmsRsaParms): TpmAlgId::Rsa;
    Ecc(TpmsEccParms): TpmAlgId::Ecc;
    @null Null: TpmAlgId::Null;
});

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuSensitiveComposite {
    Rsa(crate::data::Tpm2bPrivateKeyRsa),
    Ecc(Tpm2bEccParameter),
    Bits(Tpm2bSensitiveData),
    Sym(Tpm2bSymKey),
}

impl Default for TpmuSensitiveComposite {
    fn default() -> Self {
        Self::Rsa(crate::data::Tpm2bPrivateKeyRsa::default())
    }
}

impl TpmSized for TpmuSensitiveComposite {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Ecc(val) => val.len(),
            Self::Sym(val) => val.len(),
            Self::Rsa(val) | Self::Bits(val) => val.len(),
        }
    }
}

impl TpmMarshal for TpmuSensitiveComposite {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Ecc(val) => val.marshal(writer),
            Self::Sym(val) => val.marshal(writer),
            Self::Rsa(val) | Self::Bits(val) => val.marshal(writer),
        }
    }
}

tpmu_view!(TpmuSensitiveCompositeView, TpmuSensitiveComposite, TpmAlgId {
    Rsa(crate::data::Tpm2bPrivateKeyRsa): TpmAlgId::Rsa;
    Ecc(Tpm2bEccParameter): TpmAlgId::Ecc;
    Bits(Tpm2bSensitiveData): TpmAlgId::KeyedHash;
    Sym(Tpm2bSymKey): TpmAlgId::SymCipher;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuSymKeyBits {
    Aes(TpmUint16),
    Sm4(TpmUint16),
    Camellia(TpmUint16),
    Xor(TpmAlgId),
    #[default]
    Null,
}

impl TpmSized for TpmuSymKeyBits {
    const SIZE: usize = core::mem::size_of::<TpmUint16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.len(),
            Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuSymKeyBits {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.marshal(writer),
            Self::Xor(val) => val.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuSymKeyBitsView, TpmuSymKeyBits, TpmAlgId {
    Aes(TpmUint16): TpmAlgId::Aes;
    Sm4(TpmUint16): TpmAlgId::Sm4;
    Camellia(TpmUint16): TpmAlgId::Camellia;
    Xor(TpmAlgId): TpmAlgId::Xor;
    @null Null: TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuSymMode {
    Aes(TpmAlgId),
    Sm4(TpmAlgId),
    Camellia(TpmAlgId),
    Xor(TpmAlgId),
    #[default]
    Null,
}

impl TpmSized for TpmuSymMode {
    const SIZE: usize = core::mem::size_of::<TpmUint16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuSymMode {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => {
                val.marshal(writer)
            }
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuSymModeView, TpmuSymMode, TpmAlgId {
    Aes(TpmAlgId): TpmAlgId::Aes;
    Sm4(TpmAlgId): TpmAlgId::Sm4;
    Camellia(TpmAlgId): TpmAlgId::Camellia;
    Xor(TpmAlgId): TpmAlgId::Xor;
    @null Null: TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuSignature {
    Rsassa(TpmsSignatureRsa),
    Rsapss(TpmsSignatureRsa),
    Ecdsa(TpmsSignatureEcc),
    Ecdaa(TpmsSignatureEcc),
    Sm2(TpmsSignatureEcc),
    Ecschnorr(TpmsSignatureEcc),
    Hmac(TpmtHa),
    Null,
}

impl TpmSized for TpmuSignature {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Rsassa(s) | Self::Rsapss(s) => s.len(),
            Self::Ecdsa(s) | Self::Ecdaa(s) | Self::Sm2(s) | Self::Ecschnorr(s) => s.len(),
            Self::Hmac(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuSignature {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Rsassa(s) | Self::Rsapss(s) => s.marshal(writer),
            Self::Ecdsa(s) | Self::Ecdaa(s) | Self::Sm2(s) | Self::Ecschnorr(s) => {
                s.marshal(writer)
            }
            Self::Hmac(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuSignatureView, TpmuSignature, TpmAlgId {
    Rsassa(TpmsSignatureRsa): TpmAlgId::Rsassa;
    Rsapss(TpmsSignatureRsa): TpmAlgId::Rsapss;
    Ecdsa(TpmsSignatureEcc): TpmAlgId::Ecdsa;
    Ecdaa(TpmsSignatureEcc): TpmAlgId::Ecdaa;
    Sm2(TpmsSignatureEcc): TpmAlgId::Sm2;
    Ecschnorr(TpmsSignatureEcc): TpmAlgId::Ecschnorr;
    Hmac(TpmtHa): TpmAlgId::Hmac;
    @null Null: TpmAlgId::Null;
});

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo),
    Creation(TpmsCreationInfo),
    Quote(TpmsQuoteInfo),
    CommandAudit(TpmsCommandAuditInfo),
    SessionAudit(TpmsSessionAuditInfo),
    Time(TpmsTimeAttestInfo),
    Nv(TpmsNvCertifyInfo),
    NvDigest(TpmsNvDigestCertifyInfo),
}

impl TpmSized for TpmuAttest {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Certify(i) => i.len(),
            Self::Creation(i) => i.len(),
            Self::Quote(i) => i.len(),
            Self::CommandAudit(i) => i.len(),
            Self::SessionAudit(i) => i.len(),
            Self::Time(i) => i.len(),
            Self::Nv(i) => i.len(),
            Self::NvDigest(i) => i.len(),
        }
    }
}

impl TpmMarshal for TpmuAttest {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Certify(i) => i.marshal(writer),
            Self::Creation(i) => i.marshal(writer),
            Self::Quote(i) => i.marshal(writer),
            Self::CommandAudit(i) => i.marshal(writer),
            Self::SessionAudit(i) => i.marshal(writer),
            Self::Time(i) => i.marshal(writer),
            Self::Nv(i) => i.marshal(writer),
            Self::NvDigest(i) => i.marshal(writer),
        }
    }
}

tpmu_view!(TpmuAttestView, TpmuAttest, TpmSt {
    Certify(TpmsCertifyInfo): TpmSt::AttestCertify;
    Creation(TpmsCreationInfo): TpmSt::AttestCreation;
    Quote(TpmsQuoteInfo): TpmSt::AttestQuote;
    CommandAudit(TpmsCommandAuditInfo): TpmSt::AttestCommandAudit;
    SessionAudit(TpmsSessionAuditInfo): TpmSt::AttestSessionAudit;
    Time(TpmsTimeAttestInfo): TpmSt::AttestTime;
    Nv(TpmsNvCertifyInfo): TpmSt::AttestNv;
    NvDigest(TpmsNvDigestCertifyInfo): TpmSt::AttestNvDigest;
});

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum TpmuKeyedhashScheme {
    Hmac(TpmsSchemeHash),
    Xor(TpmsSchemeXor),
    #[default]
    Null,
}

impl TpmSized for TpmuKeyedhashScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Hmac(s) => s.len(),
            Self::Xor(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuKeyedhashScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Hmac(s) => s.marshal(writer),
            Self::Xor(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuKeyedhashSchemeView, TpmuKeyedhashScheme, TpmAlgId {
    Hmac(TpmsSchemeHash): TpmAlgId::Hmac;
    Xor(TpmsSchemeXor): TpmAlgId::Xor;
    @null Null: TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuSigScheme {
    Hash(TpmsSchemeHash),
    Hmac(TpmsSchemeHmac),
    #[default]
    Null,
}

impl TpmSized for TpmuSigScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Hash(s) | Self::Hmac(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuSigScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Hash(s) | Self::Hmac(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuSigSchemeView, TpmuSigScheme, TpmAlgId {
    Hmac(TpmsSchemeHmac): TpmAlgId::Hmac;
    Hash(TpmsSchemeHash): TpmAlgId::Rsassa|TpmAlgId::Rsapss|TpmAlgId::Ecdsa|TpmAlgId::Ecdaa|TpmAlgId::Sm2|TpmAlgId::Ecschnorr;
    @null Null: TpmAlgId::Null;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuNvPublic2 {
    NvIndex(TpmsNvPublic),
    ExternalNv(TpmsNvPublicExpAttr),
    PermanentNv(TpmsNvPublic),
}

#[allow(clippy::match_same_arms)]
impl TpmSized for TpmuNvPublic2 {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::NvIndex(s) => s.len(),
            Self::ExternalNv(s) => s.len(),
            Self::PermanentNv(s) => s.len(),
        }
    }
}

impl TpmMarshal for TpmuNvPublic2 {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::ExternalNv(s) => s.marshal(writer),
            Self::NvIndex(s) | Self::PermanentNv(s) => s.marshal(writer),
        }
    }
}

tpmu_view!(TpmuNvPublic2View, TpmuNvPublic2, TpmHt {
    NvIndex(TpmsNvPublic): TpmHt::NvIndex;
    ExternalNv(TpmsNvPublicExpAttr): TpmHt::ExternalNv;
    PermanentNv(TpmsNvPublic): TpmHt::PermanentNv;
});

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TpmuKdfScheme {
    Mgf1(TpmsSchemeHash),
    Kdf1Sp800_56a(TpmsSchemeHash),
    Kdf2(TpmsSchemeHash),
    Kdf1Sp800_108(TpmsSchemeHash),
    #[default]
    Null,
}

impl TpmSized for TpmuKdfScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Mgf1(s) | Self::Kdf1Sp800_56a(s) | Self::Kdf2(s) | Self::Kdf1Sp800_108(s) => {
                s.len()
            }
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuKdfScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Mgf1(s) | Self::Kdf1Sp800_56a(s) | Self::Kdf2(s) | Self::Kdf1Sp800_108(s) => {
                s.marshal(writer)
            }
            Self::Null => Ok(()),
        }
    }
}

tpmu_view!(TpmuKdfSchemeView, TpmuKdfScheme, TpmAlgId {
    Mgf1(TpmsSchemeHash): TpmAlgId::Mgf1;
    Kdf1Sp800_56a(TpmsSchemeHash): TpmAlgId::Kdf1Sp800_56A;
    Kdf2(TpmsSchemeHash): TpmAlgId::Kdf2;
    Kdf1Sp800_108(TpmsSchemeHash): TpmAlgId::Kdf1Sp800_108;
    @null Null: TpmAlgId::Null;
});
