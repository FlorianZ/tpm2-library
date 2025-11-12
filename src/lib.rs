//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! A reader and writer for the [TPM 2.0
//! Key](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) ASN.1
//! files.
//!
//! The format has been extended with an optional `parentPubkey` field,
//! containing `Tpm2bPublic` of the parent key.
//!
//! ## Policy command bodies
//!
//! Only the parameter area for each policy command is stored. This includes
//! neither TPM framing (tag/length/sessions) nor handle areas.
//!
//! ## Policy commands with zero parameters
//!
//! The policy commands having no parameters must have their bodies empty.
//!
//! These commands are:
//!
//! * `TPM2_PolicyAuthValue`
//! * `TPM2_PolicyPassword`
//! * `TPM2_PolicyGetDigest`
//! * `TPM2_PolicyRestart`
//! * `TPM2_PolicyPhysicalPresence`
//!
//! ## `TPM2_PolicyAuthorize`
//!
//! The command body for `TPM2_PolicyAuthorize` has `TPM2B_PUBLIC`,
//! `TPM2B_DIGEST` and `TPMT_SIGNATURE` serialized in sequence.
//!
//! ## `TPM2_PolicySecret`
//!
//! The command body for `TPM2_PolicyAuthorize` has `TPM_HANDLE`, `TPM2B_NAME`
//! and `TPM2B_DIGEST` serialized in sequence.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

mod error;

pub use crate::error::*;

use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Encode,
};
use rasn::{Decoder, Encoder};

use std::convert::TryFrom;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmtSignature},
    TpmHandle, TpmMarshal, TpmProtocolError, TpmUnmarshal, TpmWriter,
};

/// Serialize a type implementing `TpmMarshal` into `Vec<u8>`.
///
/// # Errors
///
/// Returns [`TpmProtocolError`](tpm2_protocol::TpmProtocolError) when the
/// value cannot be marshalled into the underlying TPM buffer.
fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmProtocolError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.marshal(&mut writer)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

pub const OID_LOADABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 4]));
pub const OID_IMPORTABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 6]));
pub const OID_SEALED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 5]));

/// A single policy command step, directly compatible with ASN.1.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
struct TpmPolicyCommandAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub command_code: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub command_policy: OctetString,
}

/// A policy branch (`authPolicy` case) in ASN.1.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
struct TpmAuthPolicyAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub name: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Vec<TpmPolicyCommandAsn1>,
}

/// A TPM key struct directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
struct TpmKeyAsn1 {
    pub key_type: ObjectIdentifier,
    #[rasn(tag(explicit(context, 0)))]
    pub empty_auth: Option<bool>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Option<Vec<TpmPolicyCommandAsn1>>,
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

/// A policy command (runtime representation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPolicyCommand {
    cc: TpmCc,
    body: Vec<u8>,
}

impl TpmPolicyCommand {
    /// Create a command from raw `(cc, body)` while validating basic rules.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when `cc` is not valid.
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when `body` violates
    /// command-specific constraints (e.g., a zero-parameter command with data).
    pub fn from_raw(cc: TpmCc, body: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let body = body.into();
        validate_policy_command(cc, &body)?;
        Ok(Self { cc, body })
    }

    /// Create a zero-parameter command with an empty body.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when `cc` is not one of
    /// the zero-parameter commands.
    pub fn zero(cc: TpmCc) -> Result<Self, Error> {
        if ZERO_PARAM_CMDS.contains(&cc) {
            Ok(Self {
                cc,
                body: Vec::new(),
            })
        } else {
            Err(Error::InvalidDer)
        }
    }

    /// Returns the command code.
    #[must_use]
    pub fn code(&self) -> TpmCc {
        self.cc
    }

    /// Returns the raw body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A policy branch (used for `auth_policy` list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyPolicy {
    name: Option<String>,
    body: Vec<TpmPolicyCommand>,
}

/// High-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKey {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
    pub parent_handle: TpmHandle,
    pub parent_public: Option<Tpm2bPublic>,
    pub key_type: TpmAlgId,
    pub empty_auth: Option<bool>,
    pub policy: Option<TpmKeyPolicy>,
    pub auth_policy: Option<Vec<TpmKeyPolicy>>,
    pub secret: Option<Vec<u8>>,
    pub description: Option<String>,
}

fn key_type_to_oid_for_encode(
    key_type: TpmAlgId,
    has_secret: bool,
) -> Result<ObjectIdentifier, Error> {
    match key_type {
        TpmAlgId::Rsa | TpmAlgId::Ecc => {
            if has_secret {
                Ok(OID_IMPORTABLE_KEY.clone())
            } else {
                Ok(OID_LOADABLE_KEY.clone())
            }
        }
        TpmAlgId::KeyedHash => Ok(OID_SEALED_DATA.clone()),
        _ => Err(Error::InvalidKeyType),
    }
}

impl TpmKey {
    #[must_use]
    pub fn public(&self) -> &Tpm2bPublic {
        &self.public
    }

    #[must_use]
    pub fn private(&self) -> &Tpm2bPrivate {
        &self.private
    }

    #[must_use]
    pub fn parent_handle(&self) -> TpmHandle {
        self.parent_handle
    }

    #[must_use]
    pub fn parent_public(&self) -> Option<&Tpm2bPublic> {
        self.parent_public.as_ref()
    }

    /// Serialize this key into DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 encoding fails.
    /// Returns [`OperationFailed`](crate::Error::OperationFailed) when TPM
    /// structures cannot be marshalled to bytes.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let asn1 = self.to_asn1()?;
        rasn::der::encode(&asn1).map_err(|_| Error::InvalidDer)
    }

    /// Parse a key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 decoding or
    /// embedded layout checks fail.
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when a policy item uses
    /// an unknown TPM command code.
    /// Returns [`MissingSecret`](crate::Error::MissingSecret) when OID indicates
    /// an *Importable Key* but `secret` is absent.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let asn1: TpmKeyAsn1 = rasn::der::decode(der_bytes).map_err(|_| Error::InvalidDer)?;
        Self::from_asn1(asn1)
    }

    fn to_asn1(&self) -> Result<TpmKeyAsn1, Error> {
        let rsa_parent = self
            .parent_public
            .as_ref()
            .map(|pp| pp.inner.object_type == TpmAlgId::Rsa);

        let parent_pubkey_bytes = if let Some(parent_public) = &self.parent_public {
            Some(OctetString::copy_from_slice(
                &write_object(parent_public).map_err(|_| Error::OperationFailed)?,
            ))
        } else {
            None
        };

        let key_type_oid = key_type_to_oid_for_encode(self.key_type, self.secret.is_some())?;

        let policy_asn1 = if let Some(policy) = &self.policy {
            let cmds = policy
                .body
                .iter()
                .map(|c| TpmPolicyCommandAsn1 {
                    command_code: c.cc as u32,
                    command_policy: OctetString::copy_from_slice(&c.body),
                })
                .collect::<Vec<_>>();
            Some(cmds)
        } else {
            None
        };

        let auth_policy_asn1 = if let Some(list) = &self.auth_policy {
            let branches = list
                .iter()
                .map(|p| TpmAuthPolicyAsn1 {
                    name: p.name.as_deref().map(Utf8String::from),
                    policy: p
                        .body
                        .iter()
                        .map(|c| TpmPolicyCommandAsn1 {
                            command_code: c.cc as u32,
                            command_policy: OctetString::copy_from_slice(&c.body),
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            Some(branches)
        } else {
            None
        };

        Ok(TpmKeyAsn1 {
            key_type: key_type_oid,
            empty_auth: self.empty_auth,
            policy: policy_asn1,
            secret: self
                .secret
                .as_ref()
                .map(|v| OctetString::copy_from_slice(v)),
            auth_policy: auth_policy_asn1,
            description: self.description.as_deref().map(Utf8String::from),
            rsa_parent,
            parent_pubkey: parent_pubkey_bytes,
            parent: self.parent_handle.0,
            pubkey: OctetString::copy_from_slice(
                &write_object(&self.public).map_err(|_| Error::OperationFailed)?,
            ),
            privkey: OctetString::copy_from_slice(
                &write_object(&self.private).map_err(|_| Error::OperationFailed)?,
            ),
        })
    }

    fn from_asn1(asn1: TpmKeyAsn1) -> Result<Self, Error> {
        let (public, _) = Tpm2bPublic::unmarshal(&asn1.pubkey).map_err(|_| Error::InvalidDer)?;
        let (private, _) = Tpm2bPrivate::unmarshal(&asn1.privkey).map_err(|_| Error::InvalidDer)?;
        let parent_public = if let Some(parent_bytes) = &asn1.parent_pubkey {
            let (parent_pub, _) =
                Tpm2bPublic::unmarshal(parent_bytes).map_err(|_| Error::InvalidDer)?;
            Some(parent_pub)
        } else {
            None
        };

        let is_importable_oid = asn1.key_type == OID_IMPORTABLE_KEY;
        if is_importable_oid && asn1.secret.is_none() {
            return Err(Error::MissingSecret);
        }

        let policy = if let Some(cmds) = asn1.policy {
            let mut v = Vec::with_capacity(cmds.len());
            for cmd in cmds {
                let cc = TpmCc::try_from(cmd.command_code)
                    .map_err(|()| Error::InvalidCc(cmd.command_code))?;
                let body = cmd.command_policy.as_ref().to_vec();
                validate_policy_command(cc, &body)?;
                v.push(TpmPolicyCommand { cc, body });
            }
            Some(TpmKeyPolicy {
                name: None,
                body: v,
            })
        } else {
            None
        };

        let auth_policy = if let Some(branches) = asn1.auth_policy {
            let mut v = Vec::with_capacity(branches.len());
            for b in branches {
                let mut cmds = Vec::with_capacity(b.policy.len());
                for cmd in b.policy {
                    let cc = TpmCc::try_from(cmd.command_code)
                        .map_err(|()| Error::InvalidCc(cmd.command_code))?;
                    let body = cmd.command_policy.as_ref().to_vec();
                    validate_policy_command(cc, &body)?;
                    cmds.push(TpmPolicyCommand { cc, body });
                }
                v.push(TpmKeyPolicy {
                    name: b.name,
                    body: cmds,
                });
            }
            Some(v)
        } else {
            None
        };

        let key_type = public.inner.object_type;

        Ok(Self {
            public,
            private,
            parent_handle: TpmHandle(asn1.parent),
            parent_public,
            key_type,
            empty_auth: asn1.empty_auth,
            policy,
            auth_policy,
            secret: asn1.secret.as_ref().map(|o| o.as_ref().to_vec()),
            description: asn1.description,
        })
    }
}

impl TryFrom<&[u8]> for TpmKey {
    type Error = Error;

    /// Parse a key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer)
    /// Returns [`InvalidCc`](crate::Error::InvalidCc)
    /// Returns [`MissingSecret`](crate::Error::MissingSecret)
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_der(value)
    }
}

const ZERO_PARAM_CMDS: &[TpmCc] = &[
    TpmCc::PolicyAuthValue,
    TpmCc::PolicyPassword,
    TpmCc::PolicyGetDigest,
    TpmCc::PolicyRestart,
    TpmCc::PolicyPhysicalPresence,
];

fn validate_policy_command(cc: TpmCc, body: &[u8]) -> Result<(), Error> {
    if ZERO_PARAM_CMDS.contains(&cc) {
        if !body.is_empty() {
            return Err(Error::InvalidDer);
        }
        return Ok(());
    }

    match cc {
        TpmCc::PolicyAuthorize => validate_policy_authorize(body),
        TpmCc::PolicySecret => validate_policy_secret(body),
        _ => Ok(()),
    }
}

fn validate_policy_authorize(body: &[u8]) -> Result<(), Error> {
    let (.., rest) = Tpm2bPublic::unmarshal(body).map_err(|_| Error::InvalidDer)?;
    let (.., rest) = Tpm2bDigest::unmarshal(rest).map_err(|_| Error::InvalidDer)?;
    let (.., rest) = TpmtSignature::unmarshal(rest).map_err(|_| Error::InvalidDer)?;
    if !rest.is_empty() {
        return Err(Error::InvalidDer);
    }
    Ok(())
}

fn validate_policy_secret(body: &[u8]) -> Result<(), Error> {
    let (.., rest) = TpmHandle::unmarshal(body).map_err(|_| Error::InvalidDer)?;
    let (.., rest) = Tpm2bName::unmarshal(rest).map_err(|_| Error::InvalidDer)?;
    let (.., rest) = Tpm2bDigest::unmarshal(rest).map_err(|_| Error::InvalidDer)?;
    if !rest.is_empty() {
        return Err(Error::InvalidDer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(TpmCc::PolicyAuthValue)]
    #[case(TpmCc::PolicyPassword)]
    #[case(TpmCc::PolicyGetDigest)]
    #[case(TpmCc::PolicyRestart)]
    #[case(TpmCc::PolicyPhysicalPresence)]
    fn zero_param_empty_ok(#[case] cc: TpmCc) {
        assert!(validate_policy_command(cc, &[]).is_ok());
        assert!(TpmPolicyCommand::zero(cc).is_ok());
    }

    #[rstest]
    #[case(TpmCc::PolicyAuthValue)]
    #[case(TpmCc::PolicyPassword)]
    #[case(TpmCc::PolicyGetDigest)]
    #[case(TpmCc::PolicyRestart)]
    #[case(TpmCc::PolicyPhysicalPresence)]
    fn zero_param_non_empty_err(#[case] cc: TpmCc) {
        assert!(matches!(
            validate_policy_command(cc, &[0x00]),
            Err(Error::InvalidDer)
        ));
        assert!(TpmPolicyCommand::from_raw(cc, vec![0]).is_err());
    }

    #[test]
    fn policy_secret_minimal_ok() {
        let body = [0u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(validate_policy_command(TpmCc::PolicySecret, &body).is_ok());
    }

    #[test]
    fn policy_secret_truncated_err() {
        let body = [0u8, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            validate_policy_command(TpmCc::PolicySecret, &body),
            Err(Error::InvalidDer)
        ));
    }

    #[test]
    fn policy_authorize_empty_err() {
        assert!(matches!(
            validate_policy_command(TpmCc::PolicyAuthorize, &[]),
            Err(Error::InvalidDer)
        ));
    }

    #[test]
    fn invalid_cc_is_rejected_on_load() {
        let pub_bytes = write_object(&Tpm2bPublic::default()).unwrap();
        let priv_bytes = write_object(&Tpm2bPrivate::default()).unwrap();

        let bad_cmd = TpmPolicyCommandAsn1 {
            command_code: 0xFFFF_FF00,
            command_policy: OctetString::copy_from_slice(&[]),
        };

        let asn1 = TpmKeyAsn1 {
            key_type: OID_LOADABLE_KEY.clone(),
            empty_auth: Some(false),
            policy: Some(vec![bad_cmd]),
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent_pubkey: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKey::from_der(&der);
        match res {
            Err(Error::InvalidCc(0xFFFF_FF00)) => {}
            other => panic!("expected InvalidCc, got: {other:?}"),
        }
    }

    #[test]
    fn importable_without_secret_fails() {
        let pub_bytes = write_object(&Tpm2bPublic::default()).unwrap();
        let priv_bytes = write_object(&Tpm2bPrivate::default()).unwrap();

        let asn1 = TpmKeyAsn1 {
            key_type: OID_IMPORTABLE_KEY.clone(),
            empty_auth: None,
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent_pubkey: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKey::from_der(&der);
        assert!(matches!(res, Err(Error::MissingSecret)));
    }
}
