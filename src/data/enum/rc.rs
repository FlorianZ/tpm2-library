// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[allow(unused_imports)]
use crate::{tpm_enum, TpmDiscriminant, TpmError, TpmUnmarshal};
use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

pub const TPM_RC_VER1: u32 = 0x0100;
pub const TPM_RC_FMT1: u32 = 0x0080;
pub const TPM_RC_WARN: u32 = 0x0900;
pub const TPM_RC_P_BIT: u32 = 1 << 6;
pub const TPM_RC_N_SHIFT: u32 = 8;
pub const TPM_RC_FMT1_ERROR_MASK: u32 = 0x003F;

const MAX_HANDLE_INDEX: u8 = 7;
const SESSION_INDEX_OFFSET: u8 = 8;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmRcIndex {
    Parameter(u8),
    Handle(u8),
    Session(u8),
}

impl Display for TpmRcIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parameter(i) => write!(f, "parameter[{i}]"),
            Self::Handle(i) => write!(f, "handle[{i}]"),
            Self::Session(i) => write!(f, "session[{i}]"),
        }
    }
}

tpm_enum! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum TpmRcBase(u32) {
        (Success, 0x0000, "TPM_RC_SUCCESS"),
        (BadTag, 0x001E, "TPM_RC_BAD_TAG"),
        (Initialize, TPM_RC_VER1, "TPM_RC_INITIALIZE"),
        (Failure, TPM_RC_VER1 | 0x001, "TPM_RC_FAILURE"),
        (Sequence, TPM_RC_VER1 | 0x003, "TPM_RC_SEQUENCE"),
        (Private, TPM_RC_VER1 | 0x00B, "TPM_RC_PRIVATE"),
        (Hmac, TPM_RC_VER1 | 0x019, "TPM_RC_HMAC"),
        (Disabled, TPM_RC_VER1 | 0x020, "TPM_RC_DISABLED"),
        (Exclusive, TPM_RC_VER1 | 0x021, "TPM_RC_EXCLUSIVE"),
        (AuthType, TPM_RC_VER1 | 0x024, "TPM_RC_AUTH_TYPE"),
        (AuthMissing, TPM_RC_VER1 | 0x025, "TPM_RC_AUTH_MISSING"),
        (Policy, TPM_RC_VER1 | 0x026, "TPM_RC_POLICY"),
        (Pcr, TPM_RC_VER1 | 0x027, "TPM_RC_PCR"),
        (PcrChanged, TPM_RC_VER1 | 0x028, "TPM_RC_PCR_CHANGED"),
        (Upgrade, TPM_RC_VER1 | 0x02D, "TPM_RC_UPGRADE"),
        (TooManyContexts, TPM_RC_VER1 | 0x02E, "TPM_RC_TOO_MANY_CONTEXTS"),
        (AuthUnavailable, TPM_RC_VER1 | 0x02F, "TPM_RC_AUTH_UNAVAILABLE"),
        (Reboot, TPM_RC_VER1 | 0x030, "TPM_RC_REBOOT"),
        (Unbalanced, TPM_RC_VER1 | 0x031, "TPM_RC_UNBALANCED"),
        (CommandSize, TPM_RC_VER1 | 0x042, "TPM_RC_COMMAND_SIZE"),
        (CommandCode, TPM_RC_VER1 | 0x043, "TPM_RC_COMMAND_CODE"),
        (AuthSize, TPM_RC_VER1 | 0x044, "TPM_RC_AUTHSIZE"),
        (AuthContext, TPM_RC_VER1 | 0x045, "TPM_RC_AUTH_CONTEXT"),
        (NvRange, TPM_RC_VER1 | 0x046, "TPM_RC_NV_RANGE"),
        (NvSize, TPM_RC_VER1 | 0x047, "TPM_RC_NV_SIZE"),
        (NvLocked, TPM_RC_VER1 | 0x048, "TPM_RC_NV_LOCKED"),
        (NvAuthorization, TPM_RC_VER1 | 0x049, "TPM_RC_NV_AUTHORIZATION"),
        (NvUninitialized, TPM_RC_VER1 | 0x04A, "TPM_RC_NV_UNINITIALIZED"),
        (NvSpace, TPM_RC_VER1 | 0x04B, "TPM_RC_NV_SPACE"),
        (NvDefined, TPM_RC_VER1 | 0x04C, "TPM_RC_NV_DEFINED"),
        (BadContext, TPM_RC_VER1 | 0x050, "TPM_RC_BAD_CONTEXT"),
        (CpHash, TPM_RC_VER1 | 0x051, "TPM_RC_CPHASH"),
        (Parent, TPM_RC_VER1 | 0x052, "TPM_RC_PARENT"),
        (NeedsTest, TPM_RC_VER1 | 0x053, "TPM_RC_NEEDS_TEST"),
        (NoResult, TPM_RC_VER1 | 0x054, "TPM_RC_NO_RESULT"),
        (Sensitive, TPM_RC_VER1 | 0x055, "TPM_RC_SENSITIVE"),
        (ReadOnly, TPM_RC_VER1 | 0x056, "TPM_RC_READ_ONLY"),
        (Asymmetric, TPM_RC_FMT1 | 0x001, "TPM_RC_ASYMMETRIC"),
        (Attributes, TPM_RC_FMT1 | 0x002, "TPM_RC_ATTRIBUTES"),
        (Hash, TPM_RC_FMT1 | 0x003, "TPM_RC_HASH"),
        (Value, TPM_RC_FMT1 | 0x004, "TPM_RC_VALUE"),
        (Hierarchy, TPM_RC_FMT1 | 0x005, "TPM_RC_HIERARCHY"),
        (KeySize, TPM_RC_FMT1 | 0x007, "TPM_RC_KEY_SIZE"),
        (Mgf, TPM_RC_FMT1 | 0x008, "TPM_RC_MGF"),
        (Mode, TPM_RC_FMT1 | 0x009, "TPM_RC_MODE"),
        (Type, TPM_RC_FMT1 | 0x00A, "TPM_RC_TYPE"),
        (Handle, TPM_RC_FMT1 | 0x00B, "TPM_RC_HANDLE"),
        (Kdf, TPM_RC_FMT1 | 0x00C, "TPM_RC_KDF"),
        (Range, TPM_RC_FMT1 | 0x00D, "TPM_RC_RANGE"),
        (AuthFail, TPM_RC_FMT1 | 0x00E, "TPM_RC_AUTH_FAIL"),
        (Nonce, TPM_RC_FMT1 | 0x00F, "TPM_RC_NONCE"),
        (Pp, TPM_RC_FMT1 | 0x010, "TPM_RC_PP"),
        (Scheme, TPM_RC_FMT1 | 0x012, "TPM_RC_SCHEME"),
        (Size, TPM_RC_FMT1 | 0x015, "TPM_RC_SIZE"),
        (Symmetric, TPM_RC_FMT1 | 0x016, "TPM_RC_SYMMETRIC"),
        (Tag, TPM_RC_FMT1 | 0x017, "TPM_RC_TAG"),
        (Selector, TPM_RC_FMT1 | 0x018, "TPM_RC_SELECTOR"),
        (Insufficient, TPM_RC_FMT1 | 0x01A, "TPM_RC_INSUFFICIENT"),
        (Signature, TPM_RC_FMT1 | 0x01B, "TPM_RC_SIGNATURE"),
        (Key, TPM_RC_FMT1 | 0x01C, "TPM_RC_KEY"),
        (PolicyFail, TPM_RC_FMT1 | 0x01D, "TPM_RC_POLICY_FAIL"),
        (Integrity, TPM_RC_FMT1 | 0x01F, "TPM_RC_INTEGRITY"),
        (Ticket, TPM_RC_FMT1 | 0x020, "TPM_RC_TICKET"),
        (ReservedBits, TPM_RC_FMT1 | 0x021, "TPM_RC_RESERVED_BITS"),
        (BadAuth, TPM_RC_FMT1 | 0x022, "TPM_RC_BAD_AUTH"),
        (Expired, TPM_RC_FMT1 | 0x023, "TPM_RC_EXPIRED"),
        (PolicyCc, TPM_RC_FMT1 | 0x024, "TPM_RC_POLICY_CC"),
        (Binding, TPM_RC_FMT1 | 0x025, "TPM_RC_BINDING"),
        (Curve, TPM_RC_FMT1 | 0x026, "TPM_RC_CURVE"),
        (EccPoint, TPM_RC_FMT1 | 0x027, "TPM_RC_ECC_POINT"),
        (FwLimited, TPM_RC_FMT1 | 0x028, "TPM_RC_FW_LIMITED"),
        (SvnLimited, TPM_RC_FMT1 | 0x029, "TPM_RC_SVN_LIMITED"),
        (Channel, TPM_RC_FMT1 | 0x030, "TPM_RC_CHANNEL"),
        (ChannelKey, TPM_RC_FMT1 | 0x031, "TPM_RC_CHANNEL_KEY"),
        (ContextGap, TPM_RC_WARN | 0x001, "TPM_RC_CONTEXT_GAP"),
        (ObjectMemory, TPM_RC_WARN | 0x002, "TPM_RC_OBJECT_MEMORY"),
        (SessionMemory, TPM_RC_WARN | 0x003, "TPM_RC_SESSION_MEMORY"),
        (Memory, TPM_RC_WARN | 0x004, "TPM_RC_MEMORY"),
        (SessionHandles, TPM_RC_WARN | 0x005, "TPM_RC_SESSION_HANDLES"),
        (ObjectHandles, TPM_RC_WARN | 0x006, "TPM_RC_OBJECT_HANDLES"),
        (Locality, TPM_RC_WARN | 0x007, "TPM_RC_LOCALITY"),
        (Yielded, TPM_RC_WARN | 0x008, "TPM_RC_YIELDED"),
        (Canceled, TPM_RC_WARN | 0x009, "TPM_RC_CANCELED"),
        (Testing, TPM_RC_WARN | 0x00A, "TPM_RC_TESTING"),
        (ReferenceH0, TPM_RC_WARN | 0x010, "TPM_RC_REFERENCE_H0"),
        (ReferenceH1, TPM_RC_WARN | 0x011, "TPM_RC_REFERENCE_H1"),
        (ReferenceH2, TPM_RC_WARN | 0x012, "TPM_RC_REFERENCE_H2"),
        (ReferenceH3, TPM_RC_WARN | 0x013, "TPM_RC_REFERENCE_H3"),
        (ReferenceH4, TPM_RC_WARN | 0x014, "TPM_RC_REFERENCE_H4"),
        (ReferenceH5, TPM_RC_WARN | 0x015, "TPM_RC_REFERENCE_H5"),
        (ReferenceH6, TPM_RC_WARN | 0x016, "TPM_RC_REFERENCE_H6"),
        (ReferenceS0, TPM_RC_WARN | 0x018, "TPM_RC_REFERENCE_S0"),
        (ReferenceS1, TPM_RC_WARN | 0x019, "TPM_RC_REFERENCE_S1"),
        (ReferenceS2, TPM_RC_WARN | 0x01A, "TPM_RC_REFERENCE_S2"),
        (ReferenceS3, TPM_RC_WARN | 0x01B, "TPM_RC_REFERENCE_S3"),
        (ReferenceS4, TPM_RC_WARN | 0x01C, "TPM_RC_REFERENCE_S4"),
        (ReferenceS5, TPM_RC_WARN | 0x01D, "TPM_RC_REFERENCE_S5"),
        (ReferenceS6, TPM_RC_WARN | 0x01E, "TPM_RC_REFERENCE_S6"),
        (NvRate, TPM_RC_WARN | 0x020, "TPM_RC_NV_RATE"),
        (Lockout, TPM_RC_WARN | 0x021, "TPM_RC_LOCKOUT"),
        (Retry, TPM_RC_WARN | 0x022, "TPM_RC_RETRY"),
        (NvUnavailable, TPM_RC_WARN | 0x023, "TPM_RC_NV_UNAVAILABLE"),
        (NotUsed, 0xFFFF_FFFF, "TPM_RC_NOT_USED"),
    }
}

/// A TPM 2.0 response code with a Format 1 structure.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TpmRcFmt1 {
    pub base: TpmRcBase,
    pub index: Option<TpmRcIndex>,
}

/// A TPM 2.0 response code.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TpmRc {
    Fmt0(TpmRcBase),
    Fmt1(TpmRcFmt1),
    Warn(TpmRcBase),
}

impl TpmRc {
    /// Returns the raw `u32` value of the response code.
    #[must_use]
    pub fn value(self) -> u32 {
        match self {
            Self::Fmt0(base) | Self::Warn(base) => base as u32,
            Self::Fmt1(fmt1) => {
                let mut value = fmt1.base as u32;
                if let Some(index) = fmt1.index {
                    let (is_parameter, num) = match index {
                        TpmRcIndex::Parameter(n) => (true, n),
                        TpmRcIndex::Handle(n) => (false, n),
                        TpmRcIndex::Session(n) => (false, n + SESSION_INDEX_OFFSET),
                    };

                    if is_parameter {
                        value |= TPM_RC_P_BIT;
                    }
                    value |= u32::from(num) << TPM_RC_N_SHIFT;
                }
                value
            }
        }
    }

    /// Returns the underlying `TpmRcBase` for any `TpmRc` variant.
    #[must_use]
    pub fn base(&self) -> TpmRcBase {
        match self {
            TpmRc::Fmt0(base) | TpmRc::Warn(base) => *base,
            TpmRc::Fmt1(fmt1) => fmt1.base,
        }
    }
}

impl crate::TpmSized for TpmRc {
    const SIZE: usize = core::mem::size_of::<u32>();
    fn len(&self) -> usize {
        Self::SIZE
    }
}

impl crate::TpmMarshal for TpmRc {
    fn marshal(&self, writer: &mut crate::TpmWriter) -> crate::TpmResult<()> {
        self.value().marshal(writer)
    }
}

impl crate::TpmUnmarshal for TpmRc {
    fn unmarshal(buf: &[u8]) -> crate::TpmResult<(Self, &[u8])> {
        let (val, remainder) = u32::unmarshal(buf)?;
        let rc = Self::try_from(val)?;
        Ok((rc, remainder))
    }
}

impl TryFrom<u32> for TpmRc {
    type Error = TpmError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let base_code = if (value & TPM_RC_FMT1) != 0 {
            TPM_RC_FMT1 | (value & TPM_RC_FMT1_ERROR_MASK)
        } else {
            value
        };

        let base = TpmRcBase::try_from(base_code).map_err(|()| {
            TpmError::InvalidDiscriminant(
                "TpmRcBase",
                TpmDiscriminant::Unsigned(u64::from(base_code)),
            )
        })?;

        if (value & TPM_RC_WARN) == TPM_RC_WARN {
            Ok(Self::Warn(base))
        } else if (value & TPM_RC_FMT1) != 0 {
            let is_parameter = (value & TPM_RC_P_BIT) != 0;
            let n = ((value >> TPM_RC_N_SHIFT) & 0b1111) as u8;

            let index = match (is_parameter, n) {
                (_, 0) => None,
                (true, num) => Some(TpmRcIndex::Parameter(num)),
                (false, num @ 1..=MAX_HANDLE_INDEX) => Some(TpmRcIndex::Handle(num)),
                (false, num) => Some(TpmRcIndex::Session(num - SESSION_INDEX_OFFSET)),
            };
            Ok(Self::Fmt1(TpmRcFmt1 { base, index }))
        } else {
            Ok(Self::Fmt0(base))
        }
    }
}

impl From<TpmRcBase> for TpmRc {
    fn from(base: TpmRcBase) -> Self {
        Self::Fmt0(base)
    }
}

impl Display for TpmRc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fmt0(base) | Self::Warn(base) => write!(f, "{base}"),
            Self::Fmt1(fmt1) => {
                if let Some(index) = fmt1.index {
                    write!(f, "[{}, {}]", fmt1.base, index)
                } else {
                    write!(f, "{}", fmt1.base)
                }
            }
        }
    }
}
