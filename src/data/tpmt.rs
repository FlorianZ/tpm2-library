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
    constant::TPM_MAX_COMMAND_SIZE, tpm_struct, TpmBuild, TpmErrorKind, TpmParse, TpmParseTagged,
    TpmResult, TpmSized, TpmWriter,
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

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&self.$tag_field, writer)?;
                $crate::TpmBuild::build(&self.$value_field, writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let ($tag_field, buf) = <$tag_ty>::parse(buf)?;
                let ($value_field, buf) =
                    <$value_ty as $crate::TpmParseTagged>::parse_tagged($tag_field, buf)?;
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
    const SIZE: usize = TPM_MAX_COMMAND_SIZE;
    fn len(&self) -> usize {
        self.object_type.len()
            + self.name_alg.len()
            + self.object_attributes.len()
            + self.auth_policy.len()
            + self.parameters.len()
            + self.unique.len()
    }
}

impl TpmBuild for TpmtPublic {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.object_type.build(writer)?;
        self.name_alg.build(writer)?;
        self.object_attributes.build(writer)?;
        self.auth_policy.build(writer)?;
        self.parameters.build(writer)?;
        self.unique.build(writer)
    }
}

impl TpmParse for TpmtPublic {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (object_type, buf) = TpmAlgId::parse(buf)?;
        let (name_alg, buf) = TpmAlgId::parse(buf)?;
        let (object_attributes, buf) = TpmaObject::parse(buf)?;
        let (auth_policy, buf) = Tpm2bDigest::parse(buf)?;
        let (parameters, buf) = TpmuPublicParms::parse_tagged(object_type, buf)?;
        let (unique, buf) = match object_type {
            TpmAlgId::KeyedHash => {
                let (val, rest) = Tpm2bDigest::parse(buf)?;
                (TpmuPublicId::KeyedHash(val), rest)
            }
            TpmAlgId::SymCipher => {
                let (val, rest) = Tpm2bSymKey::parse(buf)?;
                (TpmuPublicId::SymCipher(val), rest)
            }
            TpmAlgId::Rsa => {
                let (val, rest) = Tpm2bPublicKeyRsa::parse(buf)?;
                (TpmuPublicId::Rsa(val), rest)
            }
            TpmAlgId::Ecc => {
                let (point, rest) = TpmsEccPoint::parse(buf)?;
                (TpmuPublicId::Ecc(point), rest)
            }
            TpmAlgId::Null => (TpmuPublicId::Null, buf),
            _ => return Err(TpmErrorKind::InvalidValue),
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
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TpmtPublicParms {
        pub object_type: TpmAlgId,
        pub parameters: TpmuPublicParms,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    pub struct TpmtScheme {
        pub scheme: TpmAlgId,
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
            details: crate::data::tpmu::TpmuAsymScheme::Null,
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

impl TpmtSensitive {
    /// Constructs a `TpmtSensitive` from a given key algorithm and raw private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a `TpmErrorKind::InvalidValue` if the key algorithm is not supported for this operation.
    pub fn from_private_bytes(
        key_alg: TpmAlgId,
        private_bytes: &[u8],
    ) -> Result<Self, TpmErrorKind> {
        let sensitive = match key_alg {
            TpmAlgId::Rsa => TpmuSensitiveComposite::Rsa(
                crate::data::Tpm2bPrivateKeyRsa::try_from(private_bytes)?,
            ),
            TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(crate::data::Tpm2bEccParameter::try_from(
                private_bytes,
            )?),
            TpmAlgId::KeyedHash => TpmuSensitiveComposite::Bits(
                crate::data::Tpm2bSensitiveData::try_from(private_bytes)?,
            ),
            TpmAlgId::SymCipher => {
                TpmuSensitiveComposite::Sym(crate::data::Tpm2bSymKey::try_from(private_bytes)?)
            }
            _ => return Err(TpmErrorKind::InvalidValue),
        };
        Ok(Self {
            sensitive_type: key_alg,
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive,
        })
    }
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

impl TpmBuild for TpmtSensitive {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.sensitive_type.build(writer)?;
        self.auth_value.build(writer)?;
        self.seed_value.build(writer)?;
        self.sensitive.build(writer)
    }
}

impl TpmParse for TpmtSensitive {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sensitive_type, buf) = TpmAlgId::parse(buf)?;
        let (auth_value, buf) = Tpm2bAuth::parse(buf)?;
        let (seed_value, buf) = Tpm2bDigest::parse(buf)?;
        let (sensitive, buf) = match sensitive_type {
            TpmAlgId::Rsa => {
                let (val, buf) = crate::data::Tpm2bPrivateKeyRsa::parse(buf)?;
                (TpmuSensitiveComposite::Rsa(val), buf)
            }
            TpmAlgId::Ecc => {
                let (val, buf) = Tpm2bEccParameter::parse(buf)?;
                (TpmuSensitiveComposite::Ecc(val), buf)
            }
            TpmAlgId::KeyedHash => {
                let (val, buf) = Tpm2bSensitiveData::parse(buf)?;
                (TpmuSensitiveComposite::Bits(val), buf)
            }
            TpmAlgId::SymCipher => {
                let (val, buf) = Tpm2bSymKey::parse(buf)?;
                (TpmuSensitiveComposite::Sym(val), buf)
            }
            _ => return Err(TpmErrorKind::InvalidValue),
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

impl TpmBuild for TpmtSymDef {
    fn build(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        self.algorithm.build(writer)?;
        if self.algorithm != TpmAlgId::Null {
            self.key_bits.build(writer)?;
            self.mode.build(writer)?;
        }
        Ok(())
    }
}

impl TpmParse for TpmtSymDef {
    fn parse(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (algorithm, buf) = TpmAlgId::parse(buf)?;
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
                let (val, buf) = u16::parse(buf)?;
                (TpmuSymKeyBits::Aes(val), buf)
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = u16::parse(buf)?;
                (TpmuSymKeyBits::Sm4(val), buf)
            }
            TpmAlgId::Camellia => {
                let (val, buf) = u16::parse(buf)?;
                (TpmuSymKeyBits::Camellia(val), buf)
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                (TpmuSymKeyBits::Xor(val), buf)
            }
            TpmAlgId::Null => (TpmuSymKeyBits::Null, buf),
            _ => return Err(TpmErrorKind::InvalidValue),
        };
        let (mode, buf) = match algorithm {
            TpmAlgId::Aes => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                (TpmuSymMode::Aes(val), buf)
            }
            TpmAlgId::Sm4 => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                (TpmuSymMode::Sm4(val), buf)
            }
            TpmAlgId::Camellia => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                (TpmuSymMode::Camellia(val), buf)
            }
            TpmAlgId::Xor => {
                let (val, buf) = TpmAlgId::parse(buf)?;
                (TpmuSymMode::Xor(val), buf)
            }
            TpmAlgId::Null => (TpmuSymMode::Null, buf),
            _ => return Err(TpmErrorKind::InvalidValue),
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
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
