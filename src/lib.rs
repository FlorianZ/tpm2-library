// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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
//! For the time being, conversion is not supported in either direction and will
//! return [`InvalidPolicy`](crate::TpmKeyError::InvalidPolicy).
//!
//! ## `TPM2_PolicySecret`
//!
//! The command body for `TPM2_PolicySecret` has `TPM_HANDLE`, `TPM2B_NAME` and
//! `TPM2B_DIGEST` serialized in sequence.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

mod asn1;
mod error;
mod policy;

pub use error::*;
pub use policy::*;

use crate::asn1::{TpmAuthPolicyAsn1, TpmKeyAsn1, TpmKeyCommandAsn1, tpm_marshal_array};
use pem::{EncodeConfig, LineEnding, Pem};
use rasn::types::{OctetString, Utf8String};

pub const OID_LOADABLE_KEY: rasn::prelude::ObjectIdentifier =
    rasn::prelude::ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
        2, 23, 133, 10, 1, 3,
    ]));
pub const OID_IMPORTABLE_KEY: rasn::prelude::ObjectIdentifier =
    rasn::prelude::ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
        2, 23, 133, 10, 1, 4,
    ]));
pub const OID_SEALED_DATA: rasn::prelude::ObjectIdentifier =
    rasn::prelude::ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
        2, 23, 133, 10, 1, 5,
    ]));

use std::convert::TryFrom;
use tpm2_protocol::{
    TpmError, TpmErrorValue,
    basic::{TpmHandle, TpmUint32},
    constant::{MAX_PRIVATE_SIZE, TPM_MAX_COMMAND_SIZE},
    data::{Tpm2bPrivate, Tpm2bPublic, TpmAlgId},
};

/// The type of the TPM key as defined by the OID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmKeyType {
    /// `id-loadablekey`: Key to be loaded with `TPM2_Load`.
    Loadable,
    /// `id-importablekey`: Key to be loaded with `TPM2_Import`.
    Importable,
    /// `id-sealedkey`: Data to be extracted with `TPM2_Unseal`.
    SealedData,
}

/// High-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyFile {
    kind: TpmKeyType,
    empty_auth: bool,
    policy: Vec<TpmKeyPolicyCommand>,
    secret: Vec<u8>,
    auth_policy: Option<Vec<TpmKeyAuthPolicy>>,
    description: Option<String>,
    public: Vec<u8>,
    private: Vec<u8>,
    public_alg: TpmAlgId,
    parent: TpmHandle,
    rsa_parent: bool,
}

fn tpm_take(buf: &[u8], n: usize) -> tpm2_protocol::TpmResult<(&[u8], &[u8])> {
    if buf.len() < n {
        Err(TpmError::UnexpectedEnd(
            TpmErrorValue::new(0).size(n, buf.len()),
        ))
    } else {
        Ok(buf.split_at(n))
    }
}

fn tpm_u16(buf: &[u8]) -> tpm2_protocol::TpmResult<(u16, &[u8])> {
    let (bytes, tail) = tpm_take(buf, 2)?;
    Ok((u16::from_be_bytes([bytes[0], bytes[1]]), tail))
}

fn tpm_alg(buf: &[u8]) -> tpm2_protocol::TpmResult<(TpmAlgId, &[u8])> {
    let (raw, tail) = tpm_u16(buf)?;
    Ok((TpmAlgId::try_from(raw)?, tail))
}

fn tpm2b_payload(buf: &[u8], capacity: usize) -> tpm2_protocol::TpmResult<&[u8]> {
    let (size, tail) = tpm_u16(buf)?;
    let size = usize::from(size);

    if size > capacity {
        return Err(TpmError::TooManyBytes(
            TpmErrorValue::new(0).limit(capacity, size),
        ));
    }

    let (payload, tail) = tpm_take(tail, size)?;
    if !tail.is_empty() {
        return Err(TpmError::TrailingData(
            TpmErrorValue::new(buf.len() - tail.len()).actual(tail.len()),
        ));
    }

    Ok(payload)
}

fn tpm_public_alg(buf: &[u8]) -> tpm2_protocol::TpmResult<TpmAlgId> {
    let payload = tpm2b_payload(buf, TPM_MAX_COMMAND_SIZE)?;
    let (alg, _) = tpm_alg(payload)?;
    Ok(alg)
}

fn tpm_private(buf: &[u8]) -> tpm2_protocol::TpmResult<()> {
    let _ = tpm2b_payload(buf, MAX_PRIVATE_SIZE)?;
    Ok(())
}

impl Default for TpmKeyFile {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmKeyFile {
    #[must_use]
    pub fn new() -> Self {
        let public = Tpm2bPublic::default();
        TpmKeyFile {
            kind: TpmKeyType::Loadable,
            empty_auth: false,
            policy: Vec::new(),
            secret: Vec::new(),
            auth_policy: None,
            description: None,
            public_alg: public.inner.object_type,
            public: tpm_marshal_array(&[&public]).unwrap_or_default(),
            private: tpm_marshal_array(&[&Tpm2bPrivate::default()]).unwrap_or_default(),
            parent: TpmHandle::from(0),
            rsa_parent: false,
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: TpmKeyType) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn with_public(mut self, public: Tpm2bPublic) -> Self {
        self.public_alg = public.inner.object_type;
        self.public = tpm_marshal_array(&[&public]).unwrap_or_default();
        self
    }

    #[must_use]
    pub fn with_private(mut self, private: Tpm2bPrivate) -> Self {
        self.private = tpm_marshal_array(&[&private]).unwrap_or_default();
        self
    }

    /// Set the public key from a `TPM2B_PUBLIC` wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`Unmarshal`](TpmKeyError::Unmarshal) when `public` is not a
    /// valid `TPM2B_PUBLIC` envelope or its object type is invalid.
    pub fn with_public_bytes(mut self, public: &[u8]) -> Result<Self, TpmKeyError> {
        self.public_alg = tpm_public_alg(public).map_err(TpmKeyError::Unmarshal)?;
        self.public.clear();
        self.public.extend_from_slice(public);
        Ok(self)
    }

    /// Set the private key from a `TPM2B_PRIVATE` wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`Unmarshal`](TpmKeyError::Unmarshal) when `private` is not a
    /// valid `TPM2B_PRIVATE` envelope.
    pub fn with_private_bytes(mut self, private: &[u8]) -> Result<Self, TpmKeyError> {
        tpm_private(private).map_err(TpmKeyError::Unmarshal)?;
        self.private.clear();
        self.private.extend_from_slice(private);
        Ok(self)
    }

    #[must_use]
    pub fn with_empty_auth(mut self, empty_auth: bool) -> Self {
        self.empty_auth = empty_auth;
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: &[TpmKeyPolicyCommand]) -> Self {
        policy.clone_into(&mut self.policy);
        self
    }

    #[must_use]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        secret.clone_into(&mut self.secret);
        self
    }

    #[must_use]
    pub fn with_auth_policy(mut self, auth_policy: Vec<TpmKeyAuthPolicy>) -> Self {
        self.auth_policy = if auth_policy.is_empty() {
            None
        } else {
            Some(auth_policy)
        };
        self
    }

    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = if description.is_empty() {
            None
        } else {
            Some(description)
        };
        self
    }

    #[must_use]
    pub fn with_parent(mut self, parent: TpmHandle) -> Self {
        self.parent = parent;
        self
    }

    #[must_use]
    pub fn with_rsa_parent(mut self, rsa_parent: bool) -> Self {
        self.rsa_parent = rsa_parent;
        self
    }

    #[must_use]
    pub fn kind(&self) -> TpmKeyType {
        self.kind
    }

    #[must_use]
    pub fn empty_auth(&self) -> bool {
        self.empty_auth
    }

    #[must_use]
    pub fn policy(&self) -> &Vec<TpmKeyPolicyCommand> {
        &self.policy
    }

    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    #[must_use]
    pub fn auth_policy(&self) -> &Option<Vec<TpmKeyAuthPolicy>> {
        &self.auth_policy
    }

    #[must_use]
    pub fn description(&self) -> &Option<String> {
        &self.description
    }

    #[must_use]
    pub fn rsa_parent(&self) -> bool {
        self.rsa_parent
    }

    #[must_use]
    pub fn parent(&self) -> TpmHandle {
        self.parent
    }

    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    #[must_use]
    pub fn private(&self) -> &[u8] {
        &self.private
    }

    #[must_use]
    pub const fn public_alg(&self) -> TpmAlgId {
        self.public_alg
    }

    /// Serialize this key into PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAsn1`](crate::Error::InvalidDer) when ASN.1 encoding fails.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when `key_type`
    /// is not `Rsa`, `Ecc`, or `KeyedHash`.
    /// Returns [`Marshal`](crate::TpmKeyError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn to_pem(&self) -> Result<String, TpmKeyError> {
        let der = self.to_der()?;
        let pem = Pem::new("TSS2 PRIVATE KEY", der);
        let cfg = EncodeConfig::new().set_line_ending(LineEnding::LF);
        Ok(pem::encode_config(&pem, cfg))
    }

    /// Parse a key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPem`](crate::Error::InvalidPem) when PEM parsing fails.
    /// Returns [`InvalidPemTag`](crate::Error::InvalidPemTag) when the PEM tag
    /// is not `TSS2 PRIVATE KEY`.
    /// Returns [`InvalidAsn1`](crate::Error::InvalidDer) when ASN.1 decoding or
    /// embedded layout checks fail.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when the OID
    /// and inner public key type mismatch.
    /// Returns [`InvalidDerTag`](crate::Error::InvalidDerTag) when the ASN.1
    /// OID is not a recognized TPM key type.
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when a policy
    /// command body is invalid.
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when a policy item uses
    /// an unknown TPM command code.
    /// Returns [`MissingSecret`](crate::Error::MissingSecret) when OID indicates
    /// an *Importable Key* but `secret` is absent.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        let pem = pem::parse(pem_bytes).map_err(TpmKeyError::PemDecodingFailed)?;
        if pem.tag() == "TSS2 PRIVATE KEY" {
            Self::from_der(pem.contents())
        } else {
            Err(TpmKeyError::InvalidPemTag(pem.tag().to_string()))
        }
    }

    /// Serialize this key into DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAsn1`](crate::Error::InvalidDer) when ASN.1 encoding fails.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when `key_type`
    /// is not `Rsa`, `Ecc`, or `KeyedHash`.
    /// Returns [`Marshal`](crate::TpmKeyError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        let asn1 = self.to_asn1();
        rasn::der::encode(&asn1).map_err(TpmKeyError::Asn1EncodingFailed)
    }

    /// Parse a key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAsn1`](crate::Error::InvalidDer) when ASN.1 decoding or
    /// embedded layout checks fail.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when the OID
    /// and inner public key type mismatch.
    /// Returns [`InvalidDerTag`](crate::Error::InvalidDerTag) when the ASN.1
    /// OID is not a recognized TPM key type.
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when a policy
    /// command body is invalid.
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when a policy item uses
    /// an unknown TPM command code.
    /// Returns [`MissingSecret`](crate::Error::MissingSecret) when OID indicates
    /// an *Importable Key* but `secret` is absent.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        let asn1: TpmKeyAsn1 =
            rasn::der::decode(der_bytes).map_err(TpmKeyError::Asn1DecodingFailed)?;
        Self::from_asn1(asn1)
    }

    fn to_asn1(&self) -> TpmKeyAsn1 {
        let policy = if self.policy.is_empty() {
            None
        } else {
            Some(self.policy.iter().map(TpmKeyCommandAsn1::from).collect())
        };

        let auth_policy_asn1 = self
            .auth_policy
            .as_ref()
            .map(|list| list.iter().map(TpmAuthPolicyAsn1::from).collect::<Vec<_>>());

        let oid = match self.kind {
            TpmKeyType::Loadable => OID_LOADABLE_KEY.clone(),
            TpmKeyType::Importable => OID_IMPORTABLE_KEY.clone(),
            TpmKeyType::SealedData => OID_SEALED_DATA.clone(),
        };

        let empty_auth = if self.empty_auth { Some(true) } else { None };
        let rsa_parent = if self.rsa_parent { Some(true) } else { None };
        let secret = if self.secret.is_empty() {
            None
        } else {
            Some(OctetString::copy_from_slice(&self.secret))
        };

        TpmKeyAsn1 {
            key_type: oid,
            empty_auth,
            policy,
            secret,
            auth_policy: auth_policy_asn1,
            description: self.description.as_deref().map(Utf8String::from),
            rsa_parent,
            parent: self.parent.into(),
            pubkey: OctetString::copy_from_slice(&self.public),
            privkey: OctetString::copy_from_slice(&self.private),
        }
    }

    fn from_asn1(asn1: TpmKeyAsn1) -> Result<Self, TpmKeyError> {
        let public_alg = tpm_public_alg(&asn1.pubkey).map_err(TpmKeyError::Unmarshal)?;
        tpm_private(&asn1.privkey).map_err(TpmKeyError::Unmarshal)?;

        let kind = if asn1.key_type == OID_LOADABLE_KEY {
            if public_alg != TpmAlgId::Rsa
                && public_alg != TpmAlgId::Ecc
                && public_alg != TpmAlgId::KeyedHash
            {
                return Err(TpmKeyError::InvalidLoadable(public_alg));
            }
            TpmKeyType::Loadable
        } else if asn1.key_type == OID_IMPORTABLE_KEY {
            if public_alg != TpmAlgId::Rsa
                && public_alg != TpmAlgId::Ecc
                && public_alg != TpmAlgId::KeyedHash
            {
                return Err(TpmKeyError::InvalidImportable(public_alg));
            }
            TpmKeyType::Importable
        } else if asn1.key_type == OID_SEALED_DATA {
            if public_alg != TpmAlgId::KeyedHash {
                return Err(TpmKeyError::InvalidSealed(public_alg));
            }
            TpmKeyType::SealedData
        } else {
            return Err(TpmKeyError::InvalidOid(asn1.key_type));
        };

        if kind == TpmKeyType::Importable && asn1.secret.is_none() {
            return Err(TpmKeyError::MissingSecret);
        }

        let mut policy = Vec::new();
        for command in asn1.policy.unwrap_or_default() {
            policy.push(TpmKeyPolicyCommand::try_from(command)?);
        }

        let auth_policy = asn1
            .auth_policy
            .map(|branches| {
                branches
                    .into_iter()
                    .map(TpmKeyAuthPolicy::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let empty_auth = asn1.empty_auth.unwrap_or_default();
        let rsa_parent = asn1.rsa_parent.unwrap_or_default();
        let secret = asn1.secret.unwrap_or_default().to_vec();

        Ok(Self {
            kind,
            public: asn1.pubkey.to_vec(),
            private: asn1.privkey.to_vec(),
            public_alg,
            parent: TpmUint32::new(asn1.parent),
            empty_auth,
            policy,
            auth_policy,
            secret,
            description: asn1.description,
            rsa_parent,
        })
    }
}

impl TryFrom<TpmAuthPolicyAsn1> for TpmKeyAuthPolicy {
    type Error = TpmKeyError;

    fn try_from(val: TpmAuthPolicyAsn1) -> Result<Self, Self::Error> {
        let cmds = val
            .policy
            .into_iter()
            .map(TpmKeyPolicyCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TpmKeyAuthPolicy::new(val.name, cmds))
    }
}

impl TryFrom<Vec<TpmKeyCommandAsn1>> for TpmKeyAuthPolicy {
    type Error = TpmKeyError;

    fn try_from(cmds: Vec<TpmKeyCommandAsn1>) -> Result<Self, Self::Error> {
        let cmds = cmds
            .into_iter()
            .map(TpmKeyPolicyCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TpmKeyAuthPolicy::new(None, cmds))
    }
}

impl From<&TpmKeyAuthPolicy> for TpmAuthPolicyAsn1 {
    fn from(p: &TpmKeyAuthPolicy) -> Self {
        Self {
            name: p.name().as_deref().map(Utf8String::from),
            policy: p.policy().iter().map(TpmKeyCommandAsn1::from).collect(),
        }
    }
}

impl From<&TpmKeyAuthPolicy> for Vec<TpmKeyCommandAsn1> {
    fn from(p: &TpmKeyAuthPolicy) -> Self {
        p.policy().iter().map(TpmKeyCommandAsn1::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::{
        TpmMarshal, TpmWriter,
        constant::TPM_MAX_COMMAND_SIZE,
        data::{
            Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmCc, TpmsRsaParms, TpmtPublic, TpmtSensitive,
            TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite,
        },
    };

    fn minimal_rsa_key_components() -> (Vec<u8>, Vec<u8>, TpmAlgId) {
        let tpm_public = TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: TpmAlgId::Sha256,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms::default()),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
            ..Default::default()
        };
        let public = Tpm2bPublic::from(tpm_public);
        let public = crate::asn1::tpm_marshal_array(&[&public]).unwrap();

        let tpm_sensitive = TpmtSensitive {
            sensitive_type: TpmAlgId::Rsa,
            sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::default()),
            ..Default::default()
        };

        let mut sensitive_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut sensitive_bytes);
            tpm_sensitive.marshal(&mut writer).unwrap();
            writer.len()
        };

        let private = Tpm2bPrivate::try_from(&sensitive_bytes[..len]).unwrap();
        let private = crate::asn1::tpm_marshal_array(&[&private]).unwrap();

        (public, private, TpmAlgId::Rsa)
    }

    #[test]
    fn invalid_cc_is_rejected_on_load() {
        let (pub_bytes, priv_bytes, _) = minimal_rsa_key_components();

        let bad_cmd = TpmKeyCommandAsn1 {
            command_code: TpmCc::SelfTest as u32,
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
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKeyFile::from_der(&der);

        match res {
            Err(TpmKeyError::InvalidCc(val)) => assert_eq!(val, TpmCc::SelfTest as u32),
            other => panic!("expected InvalidCc, got: {other:?}"),
        }
    }

    #[test]
    fn unknown_cc_is_rejected() {
        let (pub_bytes, priv_bytes, _) = minimal_rsa_key_components();

        let invalid_cc_val = 0xFFFF_FFFFu32;
        let bad_cmd = TpmKeyCommandAsn1 {
            command_code: invalid_cc_val,
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
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKeyFile::from_der(&der);

        match res {
            Err(TpmKeyError::InvalidCc(val)) => assert_eq!(val, invalid_cc_val),
            other => panic!("expected InvalidCc, got: {other:?}"),
        }
    }

    #[test]
    fn importable_without_secret_fails() {
        let (pub_bytes, priv_bytes, _) = minimal_rsa_key_components();

        let asn1 = TpmKeyAsn1 {
            key_type: OID_IMPORTABLE_KEY.clone(),
            empty_auth: None,
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKeyFile::from_der(&der);
        assert!(matches!(res, Err(TpmKeyError::MissingSecret)));
    }

    #[test]
    fn malformed_public_is_rejected() {
        let (_, priv_bytes, _) = minimal_rsa_key_components();
        let asn1 = TpmKeyAsn1 {
            key_type: OID_LOADABLE_KEY.clone(),
            empty_auth: None,
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&[0]),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        assert!(matches!(
            TpmKeyFile::from_der(&der),
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

    #[test]
    fn public_with_trailing_data_is_rejected() {
        let (_, priv_bytes, _) = minimal_rsa_key_components();
        let asn1 = TpmKeyAsn1 {
            key_type: OID_LOADABLE_KEY.clone(),
            empty_auth: None,
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&[0, 2, 0, 1, 0]),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        assert!(matches!(
            TpmKeyFile::from_der(&der),
            Err(TpmKeyError::Unmarshal(TpmError::TrailingData(_)))
        ));
    }

    #[test]
    fn malformed_private_is_rejected() {
        let (pub_bytes, _, _) = minimal_rsa_key_components();
        let asn1 = TpmKeyAsn1 {
            key_type: OID_LOADABLE_KEY.clone(),
            empty_auth: None,
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&[0, 2, 0]),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        assert!(matches!(
            TpmKeyFile::from_der(&der),
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

    fn minimal_key() -> TpmKeyFile {
        let (public, private, public_alg) = minimal_rsa_key_components();

        TpmKeyFile {
            kind: TpmKeyType::Loadable,
            public,
            private,
            public_alg,
            parent: TpmUint32::new(0),
            empty_auth: false,
            policy: Vec::new(),
            auth_policy: None,
            secret: Vec::new(),
            description: None,
            rsa_parent: false,
        }
    }

    #[test]
    fn pem_roundtrip_ok() {
        let key_a = minimal_key();
        let pem = key_a.to_pem().unwrap();
        let key_b = TpmKeyFile::from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn to_pem_guards_ok() {
        let key = minimal_key();
        let pem = key.to_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN TSS2 PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END TSS2 PRIVATE KEY-----\n"));
    }

    #[test]
    fn from_pem_invalid_tag_err() {
        let bad_pem = "-----BEGIN RSA PRIVATE KEY-----\nMQ==\n-----END RSA PRIVATE KEY-----\n";
        let res = TpmKeyFile::from_pem(bad_pem.as_bytes());
        assert!(matches!(res, Err(TpmKeyError::InvalidPemTag(tag)) if tag == "RSA PRIVATE KEY"));
    }

    #[test]
    fn from_pem_malformed_data_err() {
        let bad_pem = "not pem data at all";
        let res = TpmKeyFile::from_pem(bad_pem.as_bytes());
        assert!(matches!(res, Err(TpmKeyError::PemDecodingFailed(_))));
    }

    #[test]
    fn test_empty_auth_encoding() {
        let mut key = minimal_key();

        key.empty_auth = true;
        let asn1_true = key.to_asn1();
        assert_eq!(asn1_true.empty_auth, Some(true));

        key.empty_auth = false;
        let asn1_false = key.to_asn1();
        assert!(asn1_false.empty_auth.is_none());

        key.empty_auth = false;
        let asn1_none = key.to_asn1();
        assert!(asn1_none.empty_auth.is_none());
    }

    #[test]
    fn sealed_data_roundtrip() {
        use tpm2_protocol::data::{
            Tpm2bDigest, Tpm2bSensitiveData, TpmsKeyedhashParms, TpmuPublicId, TpmuPublicParms,
            TpmuSensitiveComposite,
        };

        let tpm_public = TpmtPublic {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms::default()),
            unique: TpmuPublicId::KeyedHash(Tpm2bDigest::default()),
            ..Default::default()
        };
        let public = Tpm2bPublic::from(tpm_public);
        let public = crate::asn1::tpm_marshal_array(&[&public]).unwrap();

        let tpm_sensitive = TpmtSensitive {
            sensitive_type: TpmAlgId::KeyedHash,
            sensitive: TpmuSensitiveComposite::Bits(Tpm2bSensitiveData::default()),
            ..Default::default()
        };

        let mut sensitive_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut sensitive_bytes);
            tpm_sensitive.marshal(&mut writer).unwrap();
            writer.len()
        };
        let private = Tpm2bPrivate::try_from(&sensitive_bytes[..len]).unwrap();
        let private = crate::asn1::tpm_marshal_array(&[&private]).unwrap();

        let key = TpmKeyFile {
            kind: TpmKeyType::SealedData,
            public,
            private,
            public_alg: TpmAlgId::KeyedHash,
            parent: TpmUint32::new(0),
            empty_auth: false,
            policy: Vec::new(),
            auth_policy: None,
            secret: Vec::new(),
            description: None,
            rsa_parent: false,
        };

        let der = key.to_der().unwrap();
        let restored = TpmKeyFile::from_der(&der).unwrap();

        assert_eq!(restored.kind, TpmKeyType::SealedData);
        assert_eq!(restored.public, key.public);
    }
}
