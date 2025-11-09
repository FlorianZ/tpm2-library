// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    basic::TpmBuffer,
    constant::{MAX_DIGEST_SIZE, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
        TpmAlgId, TpmCap, TpmHt, TpmSt, TpmlAlgProperty, TpmlCca, TpmlEccCurve, TpmlHandle,
        TpmlPcrSelection, TpmlTaggedTpmProperty, TpmsCertifyInfo, TpmsCommandAuditInfo,
        TpmsCreationInfo, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms, TpmsNvCertifyInfo,
        TpmsNvDigestCertifyInfo, TpmsNvPublic, TpmsNvPublicExpAttr, TpmsQuoteInfo, TpmsRsaParms,
        TpmsSchemeHash, TpmsSchemeHmac, TpmsSchemeXor, TpmsSessionAuditInfo, TpmsSignatureEcc,
        TpmsSignatureRsa, TpmsSymcipherParms, TpmsTimeAttestInfo, TpmtHa,
    },
    TpmMarshal, TpmProtocolError, TpmResult, TpmSized, TpmTagged, TpmUnmarshal, TpmUnmarshalTagged,
    TpmWriter,
};
use core::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuAsymScheme {
    Any(TpmsSchemeHash),
    Null,
}

impl Default for TpmuAsymScheme {
    fn default() -> Self {
        Self::Null
    }
}

impl TpmTagged for TpmuAsymScheme {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuAsymScheme {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
    fn len(&self) -> usize {
        match self {
            Self::Any(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuAsymScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Any(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmUnmarshalTagged for TpmuAsymScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            Ok((Self::Null, buf))
        } else {
            let (val, buf) = TpmsSchemeHash::unmarshal(buf)?;
            Ok((Self::Any(val), buf))
        }
    }
}

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

impl TpmTagged for TpmuCapabilities {
    type Tag = TpmCap;
    type Value = ();
}

impl TpmSized for TpmuCapabilities {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmMarshal for TpmuCapabilities {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Algs(algs) => algs.marshal(writer),
            Self::Handles(handles) => handles.marshal(writer),
            Self::Pcrs(pcrs) => pcrs.marshal(writer),
            Self::Commands(cmds) => cmds.marshal(writer),
            Self::TpmProperties(props) => props.marshal(writer),
            Self::EccCurves(curves) => curves.marshal(writer),
        }
    }
}

impl TpmUnmarshalTagged for TpmuCapabilities {
    fn unmarshal_tagged(tag: TpmCap, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmCap::Algs => {
                let (algs, buf) = TpmlAlgProperty::unmarshal(buf)?;
                Ok((TpmuCapabilities::Algs(algs), buf))
            }
            TpmCap::Handles => {
                let (handles, buf) = TpmlHandle::unmarshal(buf)?;
                Ok((TpmuCapabilities::Handles(handles), buf))
            }
            TpmCap::Pcrs => {
                let (pcrs, buf) = TpmlPcrSelection::unmarshal(buf)?;
                Ok((TpmuCapabilities::Pcrs(pcrs), buf))
            }
            TpmCap::Commands => {
                let (cmds, buf) = TpmlCca::unmarshal(buf)?;
                Ok((TpmuCapabilities::Commands(cmds), buf))
            }
            TpmCap::TpmProperties => {
                let (props, buf) = TpmlTaggedTpmProperty::unmarshal(buf)?;
                Ok((TpmuCapabilities::TpmProperties(props), buf))
            }
            TpmCap::EccCurves => {
                let (curves, buf) = TpmlEccCurve::unmarshal(buf)?;
                Ok((TpmuCapabilities::EccCurves(curves), buf))
            }
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

impl TpmMarshal for TpmuHa {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Null => Ok(()),
            Self::Digest(d) => writer.write_bytes(d),
        }
    }
}

impl TpmUnmarshalTagged for TpmuHa {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let digest_size = match tag {
            TpmAlgId::Null => return Ok((Self::Null, buf)),
            TpmAlgId::Sha1 => 20,
            TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => 32,
            TpmAlgId::Sha384 => 48,
            TpmAlgId::Sha512 => 64,
            _ => return Err(TpmProtocolError::InvalidVariant),
        };

        if buf.len() < digest_size {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        let (digest_bytes, buf) = buf.split_at(digest_size);

        let digest = Self::Digest(
            TpmBuffer::try_from(digest_bytes).map_err(|_| TpmProtocolError::OperationFailed)?,
        );

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

impl TpmTagged for TpmuPublicId {
    type Tag = TpmAlgId;
    type Value = ();
}

impl TpmSized for TpmuPublicId {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuPublicId {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (val, rest) = Tpm2bDigest::unmarshal(buf)?;
                Ok((TpmuPublicId::KeyedHash(val), rest))
            }
            TpmAlgId::SymCipher => {
                let (val, rest) = Tpm2bSymKey::unmarshal(buf)?;
                Ok((TpmuPublicId::SymCipher(val), rest))
            }
            TpmAlgId::Rsa => {
                let (val, rest) = Tpm2bPublicKeyRsa::unmarshal(buf)?;
                Ok((TpmuPublicId::Rsa(val), rest))
            }
            TpmAlgId::Ecc => {
                let (point, rest) = TpmsEccPoint::unmarshal(buf)?;
                Ok((TpmuPublicId::Ecc(point), rest))
            }
            TpmAlgId::Null => Ok((TpmuPublicId::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuPublicParms {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::KeyedHash => {
                let (details, buf) = TpmsKeyedhashParms::unmarshal(buf)?;
                Ok((Self::KeyedHash(details), buf))
            }
            TpmAlgId::SymCipher => {
                let (details, buf) = TpmsSymcipherParms::unmarshal(buf)?;
                Ok((Self::SymCipher(details), buf))
            }
            TpmAlgId::Rsa => {
                let (details, buf) = TpmsRsaParms::unmarshal(buf)?;
                Ok((Self::Rsa(details), buf))
            }
            TpmAlgId::Ecc => {
                let (details, buf) = TpmsEccParms::unmarshal(buf)?;
                Ok((Self::Ecc(details), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
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

impl TpmTagged for TpmuSensitiveComposite {
    type Tag = TpmAlgId;
    type Value = ();
}

impl Default for TpmuSensitiveComposite {
    fn default() -> Self {
        Self::Rsa(crate::data::Tpm2bPrivateKeyRsa::default())
    }
}

impl TpmSized for TpmuSensitiveComposite {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuSensitiveComposite {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsa => {
                let (val, buf) = crate::data::Tpm2bPrivateKeyRsa::unmarshal(buf)?;
                Ok((TpmuSensitiveComposite::Rsa(val), buf))
            }
            TpmAlgId::Ecc => {
                let (val, buf) = Tpm2bEccParameter::unmarshal(buf)?;
                Ok((TpmuSensitiveComposite::Ecc(val), buf))
            }
            TpmAlgId::KeyedHash => {
                let (val, buf) = Tpm2bSensitiveData::unmarshal(buf)?;
                Ok((TpmuSensitiveComposite::Bits(val), buf))
            }
            TpmAlgId::SymCipher => {
                let (val, buf) = Tpm2bSymKey::unmarshal(buf)?;
                Ok((TpmuSensitiveComposite::Sym(val), buf))
            }
            _ => Err(TpmProtocolError::InvalidVariant),
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

impl TpmTagged for TpmuSymKeyBits {
    type Tag = TpmAlgId;
    type Value = ();
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

impl TpmMarshal for TpmuSymKeyBits {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Aes(val) | Self::Sm4(val) | Self::Camellia(val) => val.marshal(writer),
            Self::Xor(val) => val.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmUnmarshalTagged for TpmuSymKeyBits {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = u16::unmarshal(buf)?;
                Ok((TpmuSymKeyBits::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = u16::unmarshal(buf)?;
                Ok((TpmuSymKeyBits::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = u16::unmarshal(buf)?;
                Ok((TpmuSymKeyBits::Camellia(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                Ok((TpmuSymKeyBits::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((TpmuSymKeyBits::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
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

impl TpmTagged for TpmuSymMode {
    type Tag = TpmAlgId;
    type Value = ();
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

impl TpmUnmarshalTagged for TpmuSymMode {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Aes => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                Ok((TpmuSymMode::Aes(val), buf))
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                Ok((TpmuSymMode::Sm4(val), buf))
            }
            TpmAlgId::Camellia => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                Ok((TpmuSymMode::Camellia(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                Ok((TpmuSymMode::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((TpmuSymMode::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuSignature {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Rsassa => {
                let (val, buf) = TpmsSignatureRsa::unmarshal(buf)?;
                Ok((Self::Rsassa(val), buf))
            }
            TpmAlgId::Rsapss => {
                let (val, buf) = TpmsSignatureRsa::unmarshal(buf)?;
                Ok((Self::Rsapss(val), buf))
            }
            TpmAlgId::Ecdsa => {
                let (val, buf) = TpmsSignatureEcc::unmarshal(buf)?;
                Ok((Self::Ecdsa(val), buf))
            }
            TpmAlgId::Ecdaa => {
                let (val, buf) = TpmsSignatureEcc::unmarshal(buf)?;
                Ok((Self::Ecdaa(val), buf))
            }
            TpmAlgId::Sm2 => {
                let (val, buf) = TpmsSignatureEcc::unmarshal(buf)?;
                Ok((Self::Sm2(val), buf))
            }
            TpmAlgId::Ecschnorr => {
                let (val, buf) = TpmsSignatureEcc::unmarshal(buf)?;
                Ok((Self::Ecschnorr(val), buf))
            }
            TpmAlgId::Hmac => {
                let (val, buf) = TpmtHa::unmarshal(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
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

impl TpmTagged for TpmuAttest {
    type Tag = TpmSt;
    type Value = ();
}

impl TpmSized for TpmuAttest {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuAttest {
    fn unmarshal_tagged(tag: TpmSt, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmSt::AttestCertify => {
                let (val, buf) = TpmsCertifyInfo::unmarshal(buf)?;
                Ok((TpmuAttest::Certify(val), buf))
            }
            TpmSt::AttestCreation => {
                let (val, buf) = TpmsCreationInfo::unmarshal(buf)?;
                Ok((TpmuAttest::Creation(val), buf))
            }
            TpmSt::AttestQuote => {
                let (val, buf) = TpmsQuoteInfo::unmarshal(buf)?;
                Ok((TpmuAttest::Quote(val), buf))
            }
            TpmSt::AttestCommandAudit => {
                let (val, buf) = TpmsCommandAuditInfo::unmarshal(buf)?;
                Ok((TpmuAttest::CommandAudit(val), buf))
            }
            TpmSt::AttestSessionAudit => {
                let (val, buf) = TpmsSessionAuditInfo::unmarshal(buf)?;
                Ok((TpmuAttest::SessionAudit(val), buf))
            }
            TpmSt::AttestTime => {
                let (val, buf) = TpmsTimeAttestInfo::unmarshal(buf)?;
                Ok((TpmuAttest::Time(val), buf))
            }
            TpmSt::AttestNv => {
                let (val, buf) = TpmsNvCertifyInfo::unmarshal(buf)?;
                Ok((TpmuAttest::Nv(val), buf))
            }
            TpmSt::AttestNvDigest => {
                let (val, buf) = TpmsNvDigestCertifyInfo::unmarshal(buf)?;
                Ok((TpmuAttest::NvDigest(val), buf))
            }
            _ => Err(TpmProtocolError::InvalidVariant),
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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuKeyedhashScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmAlgId::Hmac => {
                let (val, buf) = TpmsSchemeHash::unmarshal(buf)?;
                Ok((Self::Hmac(val), buf))
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmsSchemeXor::unmarshal(buf)?;
                Ok((Self::Xor(val), buf))
            }
            TpmAlgId::Null => Ok((Self::Null, buf)),
            _ => Err(TpmProtocolError::InvalidVariant),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TpmuSigScheme {
    Any(TpmsSchemeHash),
    Hmac(TpmsSchemeHmac),
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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
    fn len(&self) -> usize {
        match self {
            Self::Any(s) | Self::Hmac(s) => s.len(),
            Self::Null => 0,
        }
    }
}

impl TpmMarshal for TpmuSigScheme {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        match self {
            Self::Any(s) | Self::Hmac(s) => s.marshal(writer),
            Self::Null => Ok(()),
        }
    }
}

impl TpmUnmarshalTagged for TpmuSigScheme {
    fn unmarshal_tagged(tag: TpmAlgId, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        if tag == TpmAlgId::Null {
            Ok((Self::Null, buf))
        } else {
            let (val, buf) = TpmsSchemeHash::unmarshal(buf)?;
            Ok((Self::Any(val), buf))
        }
    }
}

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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
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

impl TpmUnmarshalTagged for TpmuNvPublic2 {
    fn unmarshal_tagged(tag: TpmHt, buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        match tag {
            TpmHt::NvIndex => {
                let (val, buf) = TpmsNvPublic::unmarshal(buf)?;
                Ok((Self::NvIndex(val), buf))
            }
            TpmHt::ExternalNv => {
                let (val, buf) = TpmsNvPublicExpAttr::unmarshal(buf)?;
                Ok((Self::ExternalNv(val), buf))
            }
            TpmHt::PermanentNv => {
                let (val, buf) = TpmsNvPublic::unmarshal(buf)?;
                Ok((Self::PermanentNv(val), buf))
            }
            _ => Err(TpmProtocolError::InvalidVariant),
        }
    }
}
