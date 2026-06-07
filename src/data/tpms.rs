// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    TpmError, TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, TpmUnmarshalTagged, TpmWriter,
    basic::{TpmHandle, TpmUint8, TpmUint16, TpmUint32, TpmUint64},
    constant::{TPM_GENERATED_VALUE, TPM_PCR_SELECT_MAX},
    data::{
        Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bMaxNvBuffer, Tpm2bName,
        Tpm2bNonce, Tpm2bSensitiveData, TpmAlgId, TpmAt, TpmCap, TpmEccCurve, TpmPt, TpmRh, TpmSt,
        TpmaAlgorithm, TpmaLocality, TpmaNv, TpmaNvExp, TpmaSession, TpmiAlgHash, TpmiRhNvExpIndex,
        TpmiYesNo, TpmlPcrSelection, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme,
        TpmtRsaScheme, TpmtSymDefObject, TpmuAttest, TpmuCapabilities,
    },
    tpm_struct,
};
use core::{
    convert::TryFrom,
    fmt::{Debug, Formatter},
    mem::size_of,
    ops::Deref,
};

/// A fixed-capacity list for a PCR selection bitmap.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsPcrSelect {
    size: TpmUint8,
    data: [u8; TPM_PCR_SELECT_MAX as usize],
}

impl TpmsPcrSelect {
    /// Creates a new, empty `TpmsPcrSelect`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: TpmUint8::new(0),
            data: [0; TPM_PCR_SELECT_MAX as usize],
        }
    }
}

impl Default for TpmsPcrSelect {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for TpmsPcrSelect {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[..u8::from(self.size) as usize]
    }
}

impl TryFrom<&[u8]> for TpmsPcrSelect {
    type Error = TpmError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() > TPM_PCR_SELECT_MAX as usize {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(TPM_PCR_SELECT_MAX as usize, slice.len()),
            ));
        }
        let mut pcr_select = Self::new();
        let len_u8 = u8::try_from(slice.len()).map_err(|_| {
            TpmError::IntegerTooLarge(crate::TpmErrorValue::new(0).value_usize(slice.len()))
        })?;
        pcr_select.size = TpmUint8::from(len_u8);
        pcr_select.data[..slice.len()].copy_from_slice(slice);
        Ok(pcr_select)
    }
}

impl Debug for TpmsPcrSelect {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "TpmsPcrSelect(")?;
        for byte in self.iter() {
            write!(f, "{byte:02X}")?;
        }
        write!(f, ")")
    }
}

impl TpmSized for TpmsPcrSelect {
    const SIZE: usize = size_of::<TpmUint8>() + TPM_PCR_SELECT_MAX as usize;

    fn len(&self) -> usize {
        size_of::<TpmUint8>() + u8::from(self.size) as usize
    }
}

impl TpmMarshal for TpmsPcrSelect {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.size.marshal(writer)?;
        writer.write_bytes(self)
    }
}

impl TpmUnmarshal for TpmsPcrSelect {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (size, remainder) = TpmUint8::unmarshal(buf)?;
        let raw = u8::from(size);

        if raw > TPM_PCR_SELECT_MAX {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(TPM_PCR_SELECT_MAX as usize, raw as usize),
            ));
        }
        if remainder.len() < raw as usize {
            return Err(TpmError::UnexpectedEnd(
                crate::TpmErrorValue::new(size_of::<TpmUint8>())
                    .size(raw as usize, remainder.len()),
            ));
        }

        let (pcr_bytes, final_remainder) = remainder.split_at(raw as usize);
        let pcr_select = Self::try_from(pcr_bytes)?;
        Ok((pcr_select, final_remainder))
    }
}

impl<'a> crate::TpmField<'a> for TpmsPcrSelect {
    type View = &'a [u8];

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        let (size, remainder) = <TpmUint8 as crate::TpmCast>::cast_prefix(buf)?;
        let size = size.get() as usize;

        if size > TPM_PCR_SELECT_MAX as usize {
            return Err(TpmError::TooManyItems(
                crate::TpmErrorValue::new(0).limit(TPM_PCR_SELECT_MAX as usize, size),
            ));
        }

        if remainder.len() < size {
            return Err(TpmError::UnexpectedEnd(
                crate::TpmErrorValue::new(size_of::<TpmUint8>()).size(size, remainder.len()),
            ));
        }

        let (pcr_select, remainder) = remainder.split_at(size);
        Ok((pcr_select, remainder))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsAcOutputWire,
    pub struct TpmsAcOutput {
        pub tag: TpmAt,
        pub data: TpmUint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsAlgPropertyWire,
    pub struct TpmsAlgProperty {
        pub alg: TpmAlgId,
        pub alg_properties: TpmaAlgorithm,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsAuthCommandWire,
    pub struct TpmsAuthCommand {
        pub session_handle: TpmHandle,
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsAuthResponseWire,
    pub struct TpmsAuthResponse {
        pub nonce: Tpm2bNonce,
        pub session_attributes: TpmaSession,
        pub hmac: Tpm2bAuth,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsCapabilityData {
    pub capability: TpmCap,
    pub data: TpmuCapabilities,
}

impl TpmSized for TpmsCapabilityData {
    const SIZE: usize = size_of::<TpmUint32>() + TpmuCapabilities::SIZE;
    fn len(&self) -> usize {
        self.capability.len() + self.data.len()
    }
}

impl TpmMarshal for TpmsCapabilityData {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.capability.marshal(writer)?;
        self.data.marshal(writer)
    }
}

impl TpmUnmarshal for TpmsCapabilityData {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (capability, buf) = TpmCap::unmarshal(buf)?;
        let (data, buf) = TpmuCapabilities::unmarshal_tagged(capability, buf)?;
        Ok((Self { capability, data }, buf))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsClockInfoWire,
    pub struct TpmsClockInfo {
        pub clock: TpmUint64,
        pub reset_count: TpmUint32,
        pub restart_count: TpmUint32,
        pub safe: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    wire: TpmsContextWire,
    pub struct TpmsContext {
        pub sequence: TpmUint64,
        pub saved_handle: TpmHandle,
        pub hierarchy: TpmRh,
        pub context_blob: Tpm2b,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsCreationDataWire,
    pub struct TpmsCreationData {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
        pub locality: TpmaLocality,
        pub parent_name_alg: TpmAlgId,
        pub parent_name: Tpm2bName,
        pub parent_qualified_name: Tpm2bName,
        pub outside_info: Tpm2bData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsEccPointWire,
    pub struct TpmsEccPoint {
        pub x: Tpm2bEccParameter,
        pub y: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    wire: TpmsEmptyWire,
    pub struct TpmsEmpty {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsKeyedhashParmsWire,
    pub struct TpmsKeyedhashParms {
        pub scheme: TpmtKeyedhashScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsNvPublicWire,
    pub struct TpmsNvPublic {
        pub nv_index: TpmHandle,
        pub name_alg: TpmAlgId,
        pub attributes: TpmaNv,
        pub auth_policy: Tpm2bDigest,
        pub data_size: TpmUint16,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsNvPublicExpAttrWire,
    pub struct TpmsNvPublicExpAttr {
        pub nv_index: TpmiRhNvExpIndex,
        pub name_alg: TpmAlgId,
        pub attributes: TpmaNvExp,
        pub auth_policy: Tpm2bDigest,
        pub data_size: TpmUint16,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub pcr_select: TpmsPcrSelect,
}

impl TpmSized for TpmsPcrSelection {
    const SIZE: usize = TpmAlgId::SIZE + 1 + TPM_PCR_SELECT_MAX as usize;

    fn len(&self) -> usize {
        self.hash.len() + self.pcr_select.len()
    }
}

impl TpmMarshal for TpmsPcrSelection {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.hash.marshal(writer)?;
        self.pcr_select.marshal(writer)
    }
}

impl TpmUnmarshal for TpmsPcrSelection {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (hash, buf) = TpmAlgId::unmarshal(buf)?;
        let (pcr_select, buf) = TpmsPcrSelect::unmarshal(buf)?;
        Ok((Self { hash, pcr_select }, buf))
    }
}

impl<'a> crate::TpmField<'a> for TpmsPcrSelection {
    type View = (TpmAlgId, &'a [u8]);

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        let (hash, buf) = <TpmAlgId as crate::TpmField>::cast_prefix_field(buf)?;
        let (pcr_select, buf) = <TpmsPcrSelect as crate::TpmField>::cast_prefix_field(buf)?;

        Ok(((hash, pcr_select), buf))
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    wire: TpmsSensitiveCreateWire,
    pub struct TpmsSensitiveCreate {
        pub user_auth: Tpm2bAuth,
        pub data: Tpm2bSensitiveData,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsIdObjectWire,
    pub struct TpmsIdObject {
        pub integrity_hmac: Tpm2bDigest,
        pub enc_identity: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsSymcipherParmsWire,
    pub struct TpmsSymcipherParms {
        pub sym: TpmtSymDefObject,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    wire: TpmsTaggedPropertyWire,
    pub struct TpmsTaggedProperty {
        pub property: TpmPt,
        pub value: TpmUint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsTimeInfoWire,
    pub struct TpmsTimeInfo {
        pub time: TpmUint64,
        pub clock_info: TpmsClockInfo,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsSignatureRsaWire,
    pub struct TpmsSignatureRsa {
        pub hash: TpmAlgId,
        pub sig: crate::data::Tpm2bPublicKeyRsa,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsSignatureEccWire,
    pub struct TpmsSignatureEcc {
        pub hash: TpmAlgId,
        pub signature_r: Tpm2bEccParameter,
        pub signature_s: Tpm2bEccParameter,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsTimeAttestInfoWire,
    pub struct TpmsTimeAttestInfo {
        pub time: TpmsTimeInfo,
        pub firmware_version: TpmUint64,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsCertifyInfoWire,
    pub struct TpmsCertifyInfo {
        pub name: Tpm2bName,
        pub qualified_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsQuoteInfoWire,
    pub struct TpmsQuoteInfo {
        pub pcr_select: TpmlPcrSelection,
        pub pcr_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsCommandAuditInfoWire,
    pub struct TpmsCommandAuditInfo {
        pub audit_counter: TpmUint64,
        pub digest_alg: TpmAlgId,
        pub audit_digest: Tpm2bDigest,
        pub command_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
    wire: TpmsSessionAuditInfoWire,
    pub struct TpmsSessionAuditInfo {
        pub exclusive_session: TpmiYesNo,
        pub session_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsCreationInfoWire,
    pub struct TpmsCreationInfo {
        pub object_name: Tpm2bName,
        pub creation_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsNvCertifyInfoWire,
    pub struct TpmsNvCertifyInfo {
        pub index_name: Tpm2bName,
        pub offset: TpmUint16,
        pub nv_contents: Tpm2bMaxNvBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    wire: TpmsNvDigestCertifyInfoWire,
    pub struct TpmsNvDigestCertifyInfo {
        pub index_name: Tpm2bName,
        pub nv_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsAlgorithmDetailEccWire,
    pub struct TpmsAlgorithmDetailEcc {
        pub curve_id: TpmEccCurve,
        pub key_size: TpmUint16,
        pub kdf: TpmtKdfScheme,
        pub sign: TpmtEccScheme,
        pub p: Tpm2bEccParameter,
        pub a: Tpm2bEccParameter,
        pub b: Tpm2bEccParameter,
        pub gx: Tpm2bEccParameter,
        pub gy: Tpm2bEccParameter,
        pub n: Tpm2bEccParameter,
        pub h: Tpm2bEccParameter,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmsAttest {
    pub attest_type: TpmSt,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: TpmUint64,
    pub attested: TpmuAttest,
}

impl TpmSized for TpmsAttest {
    const SIZE: usize = size_of::<TpmUint32>()
        + TpmSt::SIZE
        + Tpm2bName::SIZE
        + Tpm2bData::SIZE
        + TpmsClockInfo::SIZE
        + size_of::<TpmUint64>()
        + TpmuAttest::SIZE;
    fn len(&self) -> usize {
        size_of::<TpmUint32>()
            + self.attest_type.len()
            + self.qualified_signer.len()
            + self.extra_data.len()
            + self.clock_info.len()
            + size_of::<TpmUint64>()
            + self.attested.len()
    }
}

impl TpmMarshal for TpmsAttest {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        crate::basic::TpmUint32::from(TPM_GENERATED_VALUE).marshal(writer)?;
        self.attest_type.marshal(writer)?;
        self.qualified_signer.marshal(writer)?;
        self.extra_data.marshal(writer)?;
        self.clock_info.marshal(writer)?;
        self.firmware_version.marshal(writer)?;
        self.attested.marshal(writer)
    }
}

impl TpmUnmarshal for TpmsAttest {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (magic, buf) = crate::basic::TpmUint32::unmarshal(buf)?;
        if u32::from(magic) != TPM_GENERATED_VALUE {
            return Err(TpmError::InvalidMagicNumber(
                crate::TpmErrorValue::new(0).value(u64::from(u32::from(magic))),
            ));
        }
        let (attest_type, buf) = TpmSt::unmarshal(buf)?;
        let (qualified_signer, buf) = Tpm2bName::unmarshal(buf)?;
        let (extra_data, buf) = Tpm2bData::unmarshal(buf)?;
        let (clock_info, buf) = TpmsClockInfo::unmarshal(buf)?;
        let (firmware_version, buf) = TpmUint64::unmarshal(buf)?;
        let (attested, buf) = TpmuAttest::unmarshal_tagged(attest_type, buf)?;

        Ok((
            Self {
                attest_type,
                qualified_signer,
                extra_data,
                clock_info,
                firmware_version,
                attested,
            },
            buf,
        ))
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsSchemeHashWire,
    pub struct TpmsSchemeHash {
        pub hash_alg: TpmiAlgHash,
    }
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsSchemeXorWire,
    pub struct TpmsSchemeXor {
        pub hash_alg: TpmiAlgHash,
        pub kdf: TpmtKdfScheme,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsRsaParmsWire,
    pub struct TpmsRsaParms {
        pub symmetric: TpmtSymDefObject,
        pub scheme: TpmtRsaScheme,
        pub key_bits: TpmUint16,
        pub exponent: TpmUint32,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmsEccParmsWire,
    pub struct TpmsEccParms {
        pub symmetric: TpmtSymDefObject,
        pub scheme: TpmtEccScheme,
        pub curve_id: TpmEccCurve,
        pub kdf: TpmtKdfScheme,
    }
}
