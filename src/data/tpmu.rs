// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    constant::{MAX_DIGEST_SIZE, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
        TpmAlgId, TpmHt, TpmlAlgProperty, TpmlCca, TpmlEccCurve, TpmlHandle, TpmlPcrSelection,
        TpmlTaggedTpmProperty, TpmsCertifyInfo, TpmsCommandAuditInfo, TpmsCreationInfo,
        TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms, TpmsNvCertifyInfo, TpmsNvDigestCertifyInfo,
        TpmsNvPublic, TpmsNvPublicExpAttr, TpmsQuoteInfo, TpmsRsaParms, TpmsSchemeHash,
        TpmsSchemeXor, TpmsSessionAuditInfo, TpmsSignatureEcc, TpmsSignatureRsa,
        TpmsSymcipherParms, TpmsTimeAttestInfo, TpmtHa,
    },
    tpm_hash_size, TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged, TpmResult,
    TpmSized, TpmTagged, TpmWriter,
};
use core::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TpmuCapabilities {
    Algs(TpmlAlgProperty),
    Handles(TpmlHandle),
    Pcrs(TpmlPcrSelection),
    Commands(TpmlCca),
    TpmProperties(TpmlTaggedTpmProperty),
    EccCurves(TpmlEccCurve),
}

impl TpmSized for TpmuCapabilities {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Algs(algs) => algs.len(),
            Self::Handles(handles) => handles.len(),
            Self::Pcrs(pcrs) => pcrs.len(),
            Self::Commands(cmds) => cmds.len(),
            Self::TpmProperties(props) => props.len(),
            Self::EccCurves(curves) => curves.len(),
        }
    }
}

impl TpmBuild for TpmuCapabilities {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Algs(algs) => algs.build(writer),
            Self::Handles(handles) => handles.build(writer),
            Self::Pcrs(pcrs) => pcrs.build(writer),
            Self::Commands(cmds) => cmds.build(writer),
            Self::TpmProperties(props) => props.build(writer),
            Self::EccCurves(curves) => curves.build(writer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuHa {
    Null,
    Digest(TpmBuffer<MAX_DIGEST_SIZE>),
}

impl TpmTagged for TpmuHa {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmBuild for TpmuHa {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Null => Ok(()),
            Self::Digest(d) => writer.write_bytes(d),
        }
    }
}

impl TpmParseTagged for TpmuHa {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            return Ok((Self::Null, buf));
        }

        let digest_size = tpm_hash_size(&tag).ok_or(TpmErrorKind::InvalidValue)?;
        if buf.len() < digest_size {
            return Err(TpmErrorKind::Underflow);
        }

        let (digest_bytes, buf) = buf.split_at(digest_size);

        let digest = Self::Digest(TpmBuffer::try_from(digest_bytes)?);

        Ok((digest, buf))
    }
}

impl Default for TpmuHa {
    fn default() -> Self {
        Self::Null
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    SymCipher(Tpm2bSymKey),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
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

impl TpmBuild for TpmuPublicId {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(data) => data.build(writer),
            Self::SymCipher(data) => data.build(writer),
            Self::Rsa(data) => data.build(writer),
            Self::Ecc(point) => point.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl Default for TpmuPublicId {
    fn default() -> Self {
        Self::Null
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuPublicParms {
    KeyedHash(TpmsKeyedhashParms),
    SymCipher(TpmsSymcipherParms),
    Rsa(TpmsRsaParms),
    Ecc(TpmsEccParms),
    Null,
}

impl TpmTagged for TpmuPublicParms {
    type Tag = TpmAlgId;
    type Value = ();
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

impl TpmBuild for TpmuPublicParms {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::KeyedHash(d) => d.build(writer),
            Self::SymCipher(d) => d.build(writer),
            Self::Rsa(d) => d.build(writer),
            Self::Ecc(d) => d.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuPublicParms {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (details, buf) = TpmsKeyedhashParms::parse(buf)?;
                Ok((Self::KeyedHash(details), buf))
            }
            TpmAlgId::SymCipher => {
                let (details, buf) = TpmsSymcipherParms::parse(buf)?;
                Ok((Self::SymCipher(details), buf))
            }
            TpmAlgId::Rsa => {
                let (details, buf) = TpmsRsaParms::parse(buf)?;
                Ok((Self::Rsa(details), buf))
            }
            TpmAlgId::Ecc => {
                let (details, buf) = TpmsEccParms::parse(buf)?;
                Ok((Self::Ecc(details), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

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

impl TpmBuild for TpmuSensitiveComposite {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Ecc(val) => val.build(writer),
            Self::Sym(val) => val.build(writer),
            Self::Rsa(val) | Self::Bits(val) => val.build(writer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymKeyBits {
    Aes(u16),
    Sm4(u16),
    Camellia(u16),
    Xor(TpmAlgId),
    Null,
}

impl Default for TpmuSymKeyBits {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymKeyBits {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.len(),
            Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuSymKeyBits {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.build(writer),
            Self::Xor(val) => val.build(writer),
            Self::Null => Ok(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSymMode {
    Aes(TpmAlgId),
    Sm4(TpmAlgId),
    Camellia(TpmAlgId),
    Xor(TpmAlgId),
    Null,
}

impl Default for TpmuSymMode {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmSized for TpmuSymMode {
    const SIZE: usize = core::mem::size_of::<u16>();
    fn len(&self) -> usize {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => val.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuSymMode {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) | Self::Xor(val) => {
                val.build(writer)
            }
            Self::Null => Ok(()),
        }
    }
}

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

impl TpmTagged for TpmuSignature {
    type Tag = TpmAlgId;
    type Value = ();
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

impl TpmBuild for TpmuSignature {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Rsassa(s) | Self::Rsapss(s) => s.build(writer),
            Self::Ecdsa(s) | Self::Ecdaa(s) | Self::Sm2(s) | Self::Ecschnorr(s) => s.build(writer),
            Self::Hmac(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuSignature {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsassa => {
                let (val, buf) = TpmsSignatureRsa::parse(buf)?;
                Ok((Self::Rsassa(val), buf))
            }
            TpmAlgId::Rsapss => {
                let (val, buf) = TpmsSignatureRsa::parse(buf)?;
                Ok((Self::Rsapss(val), buf))
            }
            TpmAlgId::Ecdsa => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecdsa(val), buf))
            }
            TpmAlgId::Ecdaa => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecdaa(val), buf))
            }
            TpmAlgId::Sm2 => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Sm2(val), buf))
            }
            TpmAlgId::Ecschnorr => {
                let (val, buf) = TpmsSignatureEcc::parse(buf)?;
                Ok((Self::Ecschnorr(val), buf))
            }
            TpmAlgId::Hmac => {
                let (val, buf) = TpmtHa::parse(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

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

impl TpmBuild for TpmuAttest {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Certify(i) => i.build(writer),
            Self::Creation(i) => i.build(writer),
            Self::Quote(i) => i.build(writer),
            Self::CommandAudit(i) => i.build(writer),
            Self::SessionAudit(i) => i.build(writer),
            Self::Time(i) => i.build(writer),
            Self::Nv(i) => i.build(writer),
            Self::NvDigest(i) => i.build(writer),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum TpmuKeyedhashScheme {
    Hmac(TpmsSchemeHash),
    Xor(TpmsSchemeXor),
    #[default]
    Null,
}

impl TpmTagged for TpmuKeyedhashScheme {
    type Tag = TpmAlgId;
    type Value = ();
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

impl TpmBuild for TpmuKeyedhashScheme {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Hmac(s) => s.build(writer),
            Self::Xor(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuKeyedhashScheme {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Hmac => {
                let (val, buf) = TpmsSchemeHash::parse(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmsSchemeXor::parse(buf)?;
                Ok((Self::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSigScheme {
    Any(TpmsSchemeHash),
    Null,
}

impl Default for TpmuSigScheme {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmTagged for TpmuSigScheme {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuSigScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        match self {
            Self::Any(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmBuild for TpmuSigScheme {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Any(s) => s.build(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmParseTagged for TpmuSigScheme {
    fn parse_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            Ok((Self::Null, buf))
        } else {
            let (val, buf) = TpmsSchemeHash::parse(buf)?;
            Ok((Self::Any(val), buf))
        }
    }
}

pub type TpmuAsymScheme = TpmuSigScheme;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuNvPublic2 {
    NvIndex(TpmsNvPublic),
    ExternalNv(TpmsNvPublicExpAttr),
    PermanentNv(TpmsNvPublic),
}

impl TpmTagged for TpmuNvPublic2 {
    type Tag = TpmHt;
    type Value = ();
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

impl TpmBuild for TpmuNvPublic2 {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::ExternalNv(s) => s.build(writer),
            Self::NvIndex(s) | Self::PermanentNv(s) => s.build(writer),
        }
    }
}

impl TpmParseTagged for TpmuNvPublic2 {
    fn parse_tagged(tag: TpmHt, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmHt::NvIndex => {
                let (val, buf) = TpmsNvPublic::parse(buf)?;
                Ok((Self::NvIndex(val), buf))
            }
            TpmHt::ExternalNv => {
                let (val, buf) = TpmsNvPublicExpAttr::parse(buf)?;
                Ok((Self::ExternalNv(val), buf))
            }
            TpmHt::PermanentNv => {
                let (val, buf) = TpmsNvPublic::parse(buf)?;
                Ok((Self::PermanentNv(val), buf))
            }
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}
