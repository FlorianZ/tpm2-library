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
//! For the time being, onversion is not supported in either direction and will
//! return [`InvalidPolicy`](crate::TpmKeyError::InvalidPolicy).
//!
//! ## `TPM2_PolicySecret`
//!
//! The command body for `TPM2_PolicySecret` has `TPM_HANDLE`, `TPM2B_NAME` and
//! `TPM2B_DIGEST` serialized in sequence.
//!
//! [`VtpmPolicyCommand::to_command`](tpm2_vtpm::VtpmPolicyCommand::to_command) is implemented for `TPM2_PolicySecret` as
//! folllows:
//!
//! * `objectHandleHint`: copied to command's `authHandle`.
//! * `objectName`: discarded.
//! * `policyRef`: copied to command's `policyRef`.
//!
//! [`tpm_key_command_from_command`](crate::vtpm_policy_command_from) does a similar "lossy" conversion:
//!
//! * `objectHandleHint`: copied from command's `authHandle`.
//! * `objectName`: set to empty `TPM2B_NAME`.
//! * `policyRef`: copied from command's `policyRef`.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

mod asn1;
mod command;
mod error;

pub use error::*;
pub use tpm2_vtpm::{vtpm_policy_command_from, VtpmPolicyCommand};

use crate::asn1::{tpm_marshal_array, TpmAuthPolicyAsn1, TpmKeyAsn1, TpmKeyCommandAsn1};
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
    data::{Tpm2bPrivate, Tpm2bPublic, TpmAlgId},
    TpmHandle, TpmUnmarshal,
};

/// A policy branch (used for `auth_policy` list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyPolicy {
    pub name: Option<String>,
    pub policy: Vec<Box<dyn VtpmPolicyCommand>>,
}

/// High-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKey {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
    pub parent_handle: TpmHandle,
    pub parent_public: Option<Tpm2bPublic>,
    pub empty_auth: Option<bool>,
    pub policy: Option<TpmKeyPolicy>,
    pub auth_policy: Option<Vec<TpmKeyPolicy>>,
    pub secret: Option<Vec<u8>>,
    pub description: Option<String>,
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

    /// Serialize this key into PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAsn1`](crate::Error::InvalidDer) when ASN.1 encoding fails.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when `key_type`
    /// is not `Rsa`, `Ecc`, or `KeyedHash`.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
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
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        let asn1 = self.to_asn1()?;
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

    fn to_asn1(&self) -> Result<TpmKeyAsn1, TpmKeyError> {
        let rsa_parent = self
            .parent_public
            .as_ref()
            .map(|pp| pp.inner.object_type == TpmAlgId::Rsa);

        let parent_pubkey_bytes = if let Some(parent_public) = &self.parent_public {
            Some(OctetString::copy_from_slice(&tpm_marshal_array(&[
                parent_public,
            ])?))
        } else {
            None
        };

        let policy_asn1 = self.policy.as_ref().map(Vec::<TpmKeyCommandAsn1>::from);

        let auth_policy_asn1 = self
            .auth_policy
            .as_ref()
            .map(|list| list.iter().map(TpmAuthPolicyAsn1::from).collect::<Vec<_>>());

        let oid = if self.secret.is_none() {
            OID_LOADABLE_KEY.clone()
        } else {
            OID_IMPORTABLE_KEY.clone()
        };

        Ok(TpmKeyAsn1 {
            key_type: oid,
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
            pubkey: OctetString::copy_from_slice(&tpm_marshal_array(&[&self.public])?),
            privkey: OctetString::copy_from_slice(&tpm_marshal_array(&[&self.private])?),
        })
    }

    fn from_asn1(asn1: TpmKeyAsn1) -> Result<Self, TpmKeyError> {
        let (public, _) = Tpm2bPublic::unmarshal(&asn1.pubkey).map_err(TpmKeyError::Unmarshal)?;
        let (private, _) =
            Tpm2bPrivate::unmarshal(&asn1.privkey).map_err(TpmKeyError::Unmarshal)?;
        let parent_public = if let Some(parent_bytes) = &asn1.parent_pubkey {
            let (parent_pub, _) =
                Tpm2bPublic::unmarshal(parent_bytes).map_err(TpmKeyError::Unmarshal)?;
            Some(parent_pub)
        } else {
            None
        };

        let key_type = public.inner.object_type;

        if asn1.key_type == OID_LOADABLE_KEY {
            if !(key_type == TpmAlgId::Rsa || key_type == TpmAlgId::Ecc) {
                return Err(TpmKeyError::InvalidLoadable(key_type));
            }
        } else if asn1.key_type == OID_IMPORTABLE_KEY {
            if !(key_type == TpmAlgId::Rsa || key_type == TpmAlgId::Ecc) {
                return Err(TpmKeyError::InvalidImportable(key_type));
            }
        } else if asn1.key_type == OID_SEALED_DATA {
            if key_type != TpmAlgId::KeyedHash {
                return Err(TpmKeyError::InvalidSealed(key_type));
            }
        } else {
            return Err(TpmKeyError::InvalidOid(asn1.key_type));
        }

        let is_importable_oid = asn1.key_type == OID_IMPORTABLE_KEY;
        if is_importable_oid && asn1.secret.is_none() {
            return Err(TpmKeyError::MissingSecret);
        }

        let policy = asn1.policy.map(TpmKeyPolicy::try_from).transpose()?;

        let auth_policy = asn1
            .auth_policy
            .map(|branches| {
                branches
                    .into_iter()
                    .map(TpmKeyPolicy::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(Self {
            public,
            private,
            parent_handle: TpmHandle(asn1.parent),
            parent_public,
            empty_auth: asn1.empty_auth,
            policy,
            auth_policy,
            secret: asn1.secret.as_ref().map(|o| o.as_ref().to_vec()),
            description: asn1.description,
        })
    }
}

impl TryFrom<TpmAuthPolicyAsn1> for TpmKeyPolicy {
    type Error = TpmKeyError;

    fn try_from(val: TpmAuthPolicyAsn1) -> Result<Self, Self::Error> {
        let cmds = val
            .policy
            .into_iter()
            .map(Box::<dyn VtpmPolicyCommand>::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: val.name,
            policy: cmds,
        })
    }
}

impl TryFrom<Vec<TpmKeyCommandAsn1>> for TpmKeyPolicy {
    type Error = TpmKeyError;

    fn try_from(cmds: Vec<TpmKeyCommandAsn1>) -> Result<Self, Self::Error> {
        let cmds = cmds
            .into_iter()
            .map(Box::<dyn VtpmPolicyCommand>::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: None,
            policy: cmds,
        })
    }
}

impl From<&TpmKeyPolicy> for TpmAuthPolicyAsn1 {
    fn from(p: &TpmKeyPolicy) -> Self {
        Self {
            name: p.name.as_deref().map(Utf8String::from),
            policy: p
                .policy
                .iter()
                .map(|cmd| TpmKeyCommandAsn1::from(cmd.as_ref()))
                .collect(),
        }
    }
}

impl From<&TpmKeyPolicy> for Vec<TpmKeyCommandAsn1> {
    fn from(p: &TpmKeyPolicy) -> Self {
        p.policy
            .iter()
            .map(|cmd| TpmKeyCommandAsn1::from(cmd.as_ref()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_protocol::{
        constant::TPM_MAX_COMMAND_SIZE,
        data::{
            Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmCc, TpmsRsaParms, TpmtPublic, TpmtSensitive,
            TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite,
        },
        TpmMarshal, TpmWriter,
    };

    fn minimal_rsa_key_components() -> (Tpm2bPublic, Tpm2bPrivate) {
        let tpm_public = TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: TpmAlgId::Sha256,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms::default()),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
            ..Default::default()
        };
        let public = Tpm2bPublic::from(tpm_public);

        let tpm_sensitive = TpmtSensitive {
            sensitive_type: TpmAlgId::Rsa,
            sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::default()),
            ..Default::default()
        };

        let mut sensitive_bytes = [0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut sensitive_bytes);
            tpm_sensitive.marshal(&mut writer).unwrap();
            writer.len()
        };

        let private = Tpm2bPrivate::try_from(&sensitive_bytes[..len]).unwrap();

        (public, private)
    }

    #[test]
    fn invalid_cc_is_rejected_on_load() {
        let (public, private) = minimal_rsa_key_components();
        let pub_bytes = crate::asn1::tpm_marshal_array(&[&public]).unwrap();
        let priv_bytes = crate::asn1::tpm_marshal_array(&[&private]).unwrap();

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
            parent_pubkey: None,
            parent: 0,
            pubkey: OctetString::copy_from_slice(&pub_bytes),
            privkey: OctetString::copy_from_slice(&priv_bytes),
        };

        let der = rasn::der::encode(&asn1).unwrap();
        let res = TpmKey::from_der(&der);
        match res {
            Err(TpmKeyError::Vtpm(tpm2_vtpm::VtpmError::InvalidCc(TpmCc::SelfTest))) => {}
            other => panic!("expected InvalidCc, got: {other:?}"),
        }
    }

    #[test]
    fn importable_without_secret_fails() {
        let (public, private) = minimal_rsa_key_components();
        let pub_bytes = crate::asn1::tpm_marshal_array(&[&public]).unwrap();
        let priv_bytes = crate::asn1::tpm_marshal_array(&[&private]).unwrap();

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
        assert!(matches!(res, Err(TpmKeyError::MissingSecret)));
    }

    fn minimal_key() -> TpmKey {
        let (public, private) = minimal_rsa_key_components();

        TpmKey {
            public,
            private,
            parent_handle: TpmHandle(0),
            parent_public: None,
            empty_auth: None,
            policy: None,
            auth_policy: None,
            secret: None,
            description: None,
        }
    }

    #[test]
    fn pem_roundtrip_ok() {
        let key_a = minimal_key();
        let pem = key_a.to_pem().unwrap();
        let key_b = TpmKey::from_pem(pem.as_bytes()).unwrap();
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
        let res = TpmKey::from_pem(bad_pem.as_bytes());
        assert!(matches!(res, Err(TpmKeyError::InvalidPemTag(tag)) if tag == "RSA PRIVATE KEY"));
    }

    #[test]
    fn from_pem_malformed_data_err() {
        let bad_pem = "not pem data at all";
        let res = TpmKey::from_pem(bad_pem.as_bytes());
        assert!(matches!(res, Err(TpmKeyError::PemDecodingFailed(_))));
    }
}
