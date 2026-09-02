// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmHt, TpmRh, TpmSt, TpmaObject, TpmuHa, TpmuKdfScheme,
    TpmuKeyedhashScheme, TpmuNvPublic2, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite,
    TpmuSigScheme, TpmuSymKeyBits, TpmuSymMode,
};
use crate::{
    TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, TpmUnmarshalTagged, TpmWriter,
    constant::TPM_MAX_COMMAND_SIZE, tpm_struct,
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

        impl<'a> $crate::TpmField<'a> for $name
        where
            $tag_ty: $crate::TpmField<'a, View = $tag_ty>,
            $value_ty: $crate::TpmTaggedField<'a, $tag_ty>,
        {
            type View = (
                $tag_ty,
                <$value_ty as $crate::TpmTaggedField<'a, $tag_ty>>::View,
            );

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                let ($tag_field, buf) = <$tag_ty as $crate::TpmField>::cast_prefix_field(buf)?;
                let ($value_field, buf) =
                    <$value_ty as $crate::TpmTaggedField<'a, $tag_ty>>::cast_tagged_prefix_field(
                        $tag_field,
                        buf,
                    )?;

                Ok((($tag_field, $value_field), buf))
            }
        }

        impl $crate::TpmUnmarshal for $name
        where
            $tag_ty: $crate::TpmUnmarshal,
            $value_ty: $crate::TpmUnmarshalTagged<$tag_ty>,
        {
            fn unmarshal(buffer: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let ($tag_field, rest) = <$tag_ty as $crate::TpmUnmarshal>::unmarshal(buffer)?;
                let offset = buffer.len() - rest.len();
                let ($value_field, buffer) =
                    <$value_ty as $crate::TpmUnmarshalTagged<$tag_ty>>::unmarshal_tagged(
                        $tag_field,
                        rest,
                    )
                    .map_err(|e| e.rebase(offset))?;

                Ok((Self { $tag_field, $value_field }, buffer))
            }
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
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
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (object_type, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (name_alg, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (object_attributes, buffer) = TpmaObject::unmarshal(buffer)?;
        let (auth_policy, buffer) = Tpm2bDigest::unmarshal(buffer)?;
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

/// Borrowed view of a [`TpmtPublic`] wire structure.
pub struct TpmtPublicView<'a> {
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub object_attributes: TpmaObject,
    pub auth_policy: <Tpm2bDigest as crate::TpmField<'a>>::View,
    pub parameters: <TpmuPublicParms as crate::TpmTaggedField<'a, TpmAlgId>>::View,
    pub unique: <TpmuPublicId as crate::TpmTaggedField<'a, TpmAlgId>>::View,
}

impl<'a> crate::TpmField<'a> for TpmtPublic {
    type View = TpmtPublicView<'a>;

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        let (object_type, buf) = <TpmAlgId as crate::TpmField>::cast_prefix_field(buf)?;
        let (name_alg, buf) = <TpmAlgId as crate::TpmField>::cast_prefix_field(buf)?;
        let (object_attributes, buf) = <TpmaObject as crate::TpmField>::cast_prefix_field(buf)?;
        let (auth_policy, buf) = <Tpm2bDigest as crate::TpmField>::cast_prefix_field(buf)?;
        let (parameters, buf) =
            <TpmuPublicParms as crate::TpmTaggedField<'a, TpmAlgId>>::cast_tagged_prefix_field(
                object_type,
                buf,
            )?;
        let (unique, buf) =
            <TpmuPublicId as crate::TpmTaggedField<'a, TpmAlgId>>::cast_tagged_prefix_field(
                object_type,
                buf,
            )?;

        Ok((
            TpmtPublicView {
                object_type,
                name_alg,
                object_attributes,
                auth_policy,
                parameters,
                unique,
            },
            buf,
        ))
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtPublicParms {
        pub object_type: TpmAlgId,
        pub parameters: TpmuPublicParms,
    }
}

tpm_struct_tagged! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct TpmtKdfScheme {
        pub scheme: TpmAlgId,
        pub details: TpmuKdfScheme,
    }
}

impl Default for TpmtKdfScheme {
    fn default() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            details: TpmuKdfScheme::Null,
        }
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
    fn unmarshal(buffer: &[u8]) -> TpmResult<(Self, &[u8])> {
        let (sensitive_type, buffer) = TpmAlgId::unmarshal(buffer)?;
        let (auth_value, buffer) = Tpm2bAuth::unmarshal(buffer)?;
        let (seed_value, buffer) = Tpm2bDigest::unmarshal(buffer)?;
        let (sensitive, buffer) = TpmuSensitiveComposite::unmarshal_tagged(sensitive_type, buffer)?;

        Ok((
            Self {
                sensitive_type,
                auth_value,
                seed_value,
                sensitive,
            },
            buffer,
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

pub enum TpmtSymDefView<'a> {
    Null,
    Value {
        algorithm: TpmAlgId,
        key_bits: <TpmuSymKeyBits as crate::TpmTaggedField<'a, TpmAlgId>>::View,
        mode: <TpmuSymMode as crate::TpmTaggedField<'a, TpmAlgId>>::View,
    },
}

impl<'a> crate::TpmField<'a> for TpmtSymDef {
    type View = TpmtSymDefView<'a>;

    fn cast_prefix_field(buf: &'a [u8]) -> TpmResult<(Self::View, &'a [u8])> {
        let (algorithm, buf) = <TpmAlgId as crate::TpmField>::cast_prefix_field(buf)?;

        if algorithm == TpmAlgId::Null {
            return Ok((TpmtSymDefView::Null, buf));
        }

        let (key_bits, buf) =
            <TpmuSymKeyBits as crate::TpmTaggedField<'a, TpmAlgId>>::cast_tagged_prefix_field(
                algorithm, buf,
            )?;
        let (mode, buf) =
            <TpmuSymMode as crate::TpmTaggedField<'a, TpmAlgId>>::cast_tagged_prefix_field(
                algorithm, buf,
            )?;

        Ok((
            TpmtSymDefView::Value {
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
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmtTkCreationWire,
    pub struct TpmtTkCreation {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmtTkVerifiedWire,
    pub struct TpmtTkVerified {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmtTkAuthWire,
    pub struct TpmtTkAuth {
        pub tag: TpmSt,
        pub hierarchy: TpmRh,
        pub digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    wire: TpmtTkHashcheckWire,
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
