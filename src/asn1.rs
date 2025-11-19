// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmKeyError;
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use tpm2_protocol::{constant::TPM_MAX_COMMAND_SIZE, TpmMarshal, TpmWriter};

pub const OID_LOADABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 3]));
pub const OID_IMPORTABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 4]));
pub const OID_SEALED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 5]));

pub(crate) fn tpm_marshal_array(objs: &[&dyn TpmMarshal]) -> Result<Vec<u8>, TpmKeyError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        for obj in objs {
            obj.marshal(&mut writer).map_err(TpmKeyError::Marshal)?;
        }
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// A single policy command step, directly compatible with ASN.1.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub(crate) struct TpmKeyCommandAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub command_code: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub command_policy: OctetString,
}

/// A policy branch (`authPolicy` case) in ASN.1.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub(crate) struct TpmAuthPolicyAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub name: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Vec<TpmKeyCommandAsn1>,
}

/// A TPM key struct directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub(crate) struct TpmKeyAsn1 {
    pub key_type: ObjectIdentifier,
    #[rasn(tag(explicit(context, 0)))]
    pub empty_auth: Option<bool>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Option<Vec<TpmKeyCommandAsn1>>,
    #[rasn(tag(explicit(context, 2)))]
    pub secret: Option<OctetString>,
    #[rasn(tag(explicit(context, 3)))]
    pub auth_policy: Option<Vec<TpmAuthPolicyAsn1>>,
    #[rasn(tag(explicit(context, 4)))]
    pub description: Option<Utf8String>,
    #[rasn(tag(explicit(context, 5)))]
    pub rsa_parent: Option<bool>,
    #[rasn(tag(explicit(context, 6)))]
    pub parent_pubkey: Option<OctetString>,
    pub parent: u32,
    pub pubkey: OctetString,
    pub privkey: OctetString,
}
