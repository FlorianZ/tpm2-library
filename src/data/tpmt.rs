// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey,
    TpmAlgId, TpmHt, TpmRh, TpmSt, TpmaObject, TpmsEccPoint, TpmuHa, TpmuKeyedhashScheme,
    TpmuNvPublic2, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite, TpmuSigScheme,
    TpmuSymKeyBits, TpmuSymMode,
};
use crate::{
    constant::TPM_MAX_COMMAND_SIZE, tpm_struct, TpmMarshal, TpmProtocolError, TpmResult, TpmSized,
    TpmUnmarshal, TpmUnmarshalTagged, TpmWriter,
};

macro_rules! tpm_struct_tagged {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident {
            pub $tag_field:ident: $tag_ty:ty,
            pub $value_field:ident: $value_ty:ty,
        }
    ) => {
        $(#[$outer])*
        $vis struct $name {
            pub $tag_field: $tag_ty,
            pub $value_field: $value_ty,
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = <$tag_ty>::SIZE + <$value_ty>::SIZE;
            fn len(&self) -> usize {
                $crate::TpmSized::len(&self.$tag_field) + $crate::TpmSized::len(&self.$value_field)
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmMarshal::marshal(&self.$tag_field, writer)?;
                $crate::TpmMarshal::marshal(&self.$value_field, writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let ($tag_field, buf) = <$tag_ty>::unmarshal(buf)?;
                let ($value_field, buf) =
                    <$value_ty as $crate::TpmUnmarshalTagged>::unmarshal_tagged($tag_field, buf)?;
                Ok((
                    Self {
                        $tag_field,
                        $value_field,
                    },
                    buf,
                ))
            }
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpmtPublic {
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmuPublicParms,
    pub unique: TpmuPublicId,
}

impl TpmSized for TpmtPublic {
    const SIZE: usize = TPM_MAX_COMMAND_SIZE as usize;
    fn len(&self) -> usize {
        self.object_type.len()
            + self.name_alg.len()
            + self.object_attributes.len()
            + self.auth_policy.len()
            + self.parameters.len()
            + self.unique.len()
    }
}

impl TpmMarshal for TpmtPublic {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.object_type.marshal(writer)?;
        self.name_alg.marshal(writer)?;
        self.object_attributes.marshal(writer)?;
        self.auth_policy.marshal(writer)?;
        self.parameters.marshal(writer)?;
        self.unique.marshal(writer)
    }
}

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (object_type, buf) = TpmAlgId::unmarshal(buf)?;
        let (name_alg, buf) = TpmAlgId::unmarshal(buf)?;
        let (object_attributes, buf) = TpmaObject::unmarshal(buf)?;
        let (auth_policy, buf) = Tpm2bDigest::unmarshal(buf)?;
        let (parameters, buf) = TpmuPublicParms::unmarshal_tagged(object_type, buf)?;
        let (unique, buf) = match object_type {
            TpmAlgId::KeyedHash => {
                let (val, rest) = Tpm2bDigest::unmarshal(buf)?;
                (TpmuPublicId::KeyedHash(val), rest)
            }
            TpmAlgId::SymCipher => {
                let (val, rest) = Tpm2bSymKey::unmarshal(buf)?;
                (TpmuPublicId::SymCipher(val), rest)
            }
            TpmAlgId::Rsa => {
                let (val, rest) = Tpm2bPublicKeyRsa::unmarshal(buf)?;
                (TpmuPublicId::Rsa(val), rest)
            }
            TpmAlgId::Ecc => {
                let (point, rest) = TpmsEccPoint::unmarshal(buf)?;
                (TpmuPublicId::Ecc(point), rest)
            }
            TpmAlgId::Null => (TpmuPublicId::Null, buf),
            _ => return Err(TpmProtocolError::MalformedValue),
        };
        let public_area = Self {
            object_type,
            name_alg,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        };
        Ok((public_area, buf))
    }
}

impl Default for TpmtPublic {
    fn default() -> Self {
        Self {
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Null,
            object_attributes: TpmaObject::empty(),
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::Null,
            unique: TpmuPublicId::Null,
        }
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtPublicParms {
        pub object_type: TpmAlgId,
        pub parameters: TpmuPublicParms,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtKdfScheme {
        pub scheme: TpmAlgId,
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtRsaDecrypt {
        pub scheme: TpmAlgId,
        pub details: crate::data::tpmu::TpmuAsymScheme,
    }
}

impl Default for TpmtRsaDecrypt {
    fn default() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            details: crate::data::tpmu::TpmuAsymScheme::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct TpmtSensitive {
    pub sensitive_type: TpmAlgId,
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}

impl TpmSized for TpmtSensitive {
    const SIZE: usize =
        TpmAlgId::SIZE + Tpm2bAuth::SIZE + Tpm2bDigest::SIZE + TpmuSensitiveComposite::SIZE;
    fn len(&self) -> usize {
        self.sensitive_type.len()
            + self.auth_value.len()
            + self.seed_value.len()
            + self.sensitive.len()
    }
}

impl TpmMarshal for TpmtSensitive {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.sensitive_type.marshal(writer)?;
        self.auth_value.marshal(writer)?;
        self.seed_value.marshal(writer)?;
        self.sensitive.marshal(writer)
    }
}

impl TpmUnmarshal for TpmtSensitive {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sensitive_type, buf) = TpmAlgId::unmarshal(buf)?;
        let (auth_value, buf) = Tpm2bAuth::unmarshal(buf)?;
        let (seed_value, buf) = Tpm2bDigest::unmarshal(buf)?;
        let (sensitive, buf) = match sensitive_type {
            TpmAlgId::Rsa => {
                let (val, buf) = crate::data::Tpm2bPrivateKeyRsa::unmarshal(buf)?;
                (TpmuSensitiveComposite::Rsa(val), buf)
            }
            TpmAlgId::Ecc => {
                let (val, buf) = Tpm2bEccParameter::unmarshal(buf)?;
                (TpmuSensitiveComposite::Ecc(val), buf)
            }
            TpmAlgId::KeyedHash => {
                let (val, buf) = Tpm2bSensitiveData::unmarshal(buf)?;
                (TpmuSensitiveComposite::Bits(val), buf)
            }
            TpmAlgId::SymCipher => {
                let (val, buf) = Tpm2bSymKey::unmarshal(buf)?;
                (TpmuSensitiveComposite::Sym(val), buf)
            }
            _ => return Err(TpmProtocolError::MalformedValue),
        };
        Ok((
            Self {
                sensitive_type,
                auth_value,
                seed_value,
                sensitive,
            },
            buf,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct TpmtSymDef {
    pub algorithm: TpmAlgId,
    pub key_bits: TpmuSymKeyBits,
    pub mode: TpmuSymMode,
}

impl TpmSized for TpmtSymDef {
    const SIZE: usize = TpmAlgId::SIZE + TpmuSymKeyBits::SIZE + TpmAlgId::SIZE;
    fn len(&self) -> usize {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.len()
        } else {
            self.algorithm.len() + self.key_bits.len() + self.mode.len()
        }
    }
}

impl TpmMarshal for TpmtSymDef {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.algorithm.marshal(writer)?;
        if self.algorithm != TpmAlgId::Null {
            self.key_bits.marshal(writer)?;
            self.mode.marshal(writer)?;
        }
        Ok(())
    }
}

impl TpmUnmarshal for TpmtSymDef {
    fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (algorithm, buf) = TpmAlgId::unmarshal(buf)?;
        if algorithm == TpmAlgId::Null {
            return Ok((
                Self {
                    algorithm,
                    key_bits: TpmuSymKeyBits::Null,
                    mode: TpmuSymMode::Null,
                },
                buf,
            ));
        }
        let (key_bits, buf) = match algorithm {
            TpmAlgId::Aes => {
                let (val, buf) = u16::unmarshal(buf)?;
                (TpmuSymKeyBits::Aes(val), buf)
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = u16::unmarshal(buf)?;
                (TpmuSymKeyBits::Sm4(val), buf)
            }
            TpmAlgId::Camellia => {
                let (val, buf) = u16::unmarshal(buf)?;
                (TpmuSymKeyBits::Camellia(val), buf)
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                (TpmuSymKeyBits::Xor(val), buf)
            }
            TpmAlgId::Null => (TpmuSymKeyBits::Null, buf),
            _ => return Err(TpmProtocolError::MalformedValue),
        };
        let (mode, buf) = match algorithm {
            TpmAlgId::Aes => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                (TpmuSymMode::Aes(val), buf)
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                (TpmuSymMode::Sm4(val), buf)
            }
            TpmAlgId::Camellia => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                (TpmuSymMode::Camellia(val), buf)
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::unmarshal(buf)?;
                (TpmuSymMode::Xor(val), buf)
            }
            TpmAlgId::Null => (TpmuSymMode::Null, buf),
            _ => return Err(TpmProtocolError::MalformedValue),
        };
        Ok((
            Self {
                algorithm,
                key_bits,
                mode,
            },
            buf,
        ))
    }
}

pub type TpmtSymDefObject = TpmtSymDef;

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtNvPublic2 {
        pub handle_type: TpmHt,
        pub public_area: TpmuNvPublic2,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Default)]
    pub struct TpmtTkCreation {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkVerified {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkAuth {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtTkHashcheck {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtHa {
        pub hash_alg: TpmAlgId,
        pub digest: TpmuHa,
    }
}

impl Default for TpmtHa {
    fn default() -> Self {
        Self {
            hash_alg: TpmAlgId::Null,
            digest: TpmuHa::default(),
        }
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TpmtSignature {
        pub sig_alg: TpmAlgId,
        pub signature: crate::data::tpmu::TpmuSignature,
    }
}

tpm_struct_tagged! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtKeyedhashScheme {
        pub scheme: TpmAlgId,
        pub details: TpmuKeyedhashScheme,
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtSigScheme {
        pub scheme: TpmAlgId,
        pub details: TpmuSigScheme,
    }
}

impl Default for TpmtSigScheme {
    fn default() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            details: TpmuSigScheme::default(),
        }
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtRsaScheme {
        pub scheme: TpmAlgId,
        pub details: crate::data::tpmu::TpmuAsymScheme,
    }
}

impl Default for TpmtRsaScheme {
    fn default() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            details: crate::data::tpmu::TpmuAsymScheme::default(),
        }
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtEccScheme {
        pub scheme: TpmAlgId,
        pub details: crate::data::tpmu::TpmuAsymScheme,
    }
}

impl Default for TpmtEccScheme {
    fn default() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            details: crate::data::tpmu::TpmuAsymScheme::default(),
        }
    }
}
