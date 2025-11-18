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
//! return `Error::InvalidPolicy`.
//!
//! ## `TPM2_PolicySecret`
//!
//! The command body for `TPM2_PolicySecret` has `TPM_HANDLE`, `TPM2B_NAME` and
//! `TPM2B_DIGEST` serialized in sequence.
//!
//! `TpmPolicyCommand::to_command` is implemented for `TPM2_PolicySecret` as
//! folllows:
//!
//!    * `objectHandleHint`: copied to command's `authHandle`.
//!    * `objectName`: discarded.
//!    * `policyRef`: copied to command's `policyRef`.
//!
//! `TpmPolicyCommand::from_command` does a similar "lossy" conversion:
//!
//!    * `objectHandleHint`: copied from command's `authHandle`.
//!    * `objectName`: set to empty `TPM2B_NAME`.
//!    * `policyRef`: copied from command's `policyRef`.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

mod error;

pub use crate::error::*;

use pem::{EncodeConfig, LineEnding, Pem};
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Encode,
};
use rasn::{Decoder, Encoder};

use std::convert::TryFrom;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmlDigest,
        TpmlPcrSelection, TpmtSignature,
    },
    frame::{
        TpmCommand, TpmFrame, TpmPolicyAuthValueCommand, TpmPolicyGetDigestCommand,
        TpmPolicyOrCommand, TpmPolicyPasswordCommand, TpmPolicyPcrCommand,
        TpmPolicyPhysicalPresenceCommand, TpmPolicyRestartCommand, TpmPolicySecretCommand,
    },
    TpmHandle, TpmMarshal, TpmUnmarshal, TpmWriter,
};

/// Serialize a sequence of objects implementing `TpmMarshal` into `Vec<u8>`.
///
/// # Errors
///
/// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
/// marshalled into the underlying TPM buffer.
fn tpm_marshal_array(objs: &[&dyn TpmMarshal]) -> Result<Vec<u8>, TpmKeyError> {
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

const POLICY_SESSION: TpmHandle = TpmHandle(0);

const OID_LOADABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 3]));
const OID_IMPORTABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 4]));
const OID_SEALED_DATA: ObjectIdentifier =
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
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when `body` violates
    /// command-specific constraints (e.g., a zero-parameter command with data).
    pub fn from_raw(cc: TpmCc, body: impl Into<Vec<u8>>) -> Result<Self, TpmKeyError> {
        let body = body.into();
        validate_policy_command(cc, &body)?;
        Ok(Self { cc, body })
    }

    /// Create a zero-parameter command with an empty body.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when `cc` is not
    /// one of the zero-parameter commands.
    pub fn zero(cc: TpmCc) -> Result<Self, TpmKeyError> {
        if ZERO_PARAM_CMDS.contains(&cc) {
            Ok(Self {
                cc,
                body: Vec::new(),
            })
        } else {
            Err(TpmKeyError::InvalidPolicy)
        }
    }

    /// Creates a new `TPM2_PolicyAuthorize` command.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn authorize(
        key_sign: &Tpm2bPublic,
        policy_ref: &Tpm2bDigest,
        policy_signature: &TpmtSignature,
    ) -> Result<Self, TpmKeyError> {
        let body = tpm_marshal_array(&[key_sign, policy_ref, policy_signature])?;
        Ok(Self {
            cc: TpmCc::PolicyAuthorize,
            body,
        })
    }

    /// Creates a new `TPM2_PolicySecret` command.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn secret(
        object_handle_hint: TpmHandle,
        object_name: &Tpm2bName,
        policy_ref: &Tpm2bDigest,
    ) -> Result<Self, TpmKeyError> {
        let body = tpm_marshal_array(&[&object_handle_hint, object_name, policy_ref])?;
        Ok(Self {
            cc: TpmCc::PolicySecret,
            body,
        })
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

    /// Converts this policy step into a typed TPM command and an empty auth list.
    ///
    /// The resulting command uses a fixed policy session handle (`TPM_HANDLE(0)`)
    /// because the ASN.1 representation does not carry handle data.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when the body
    /// cannot be decoded as the parameter area for `cc`, or when the
    /// representation is intentionally not supported (e.g. `PolicyAuthorize`).
    ///
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when `cc` has no mapping
    /// to a TPM command in this crate.
    pub fn to_command(&self) -> Result<TpmCommand, TpmKeyError> {
        let command = match self.cc {
            TpmCc::PolicyPcr => self.to_policy_pcr_command()?,
            TpmCc::PolicyOr => self.to_policy_or_command()?,
            TpmCc::PolicySecret => self.to_policy_secret_command()?,
            TpmCc::PolicyAuthorize => return Err(TpmKeyError::InvalidPolicy),
            cc if ZERO_PARAM_CMDS.contains(&cc) => self.to_policy_zero_command()?,
            other => return Err(TpmKeyError::InvalidCc(other as u32)),
        };
        Ok(command)
    }

    /// Constructs a `TpmPolicyCommand` from a typed TPM policy command.
    ///
    /// The authorization area is ignored because the `CommandPolicy`
    /// representation does not store it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy) when the command
    /// is not representable as a `CommandPolicy` step without additional
    /// context.
    /// Returns [`InvalidCc`](crate::Error::InvalidCc) when the command code is
    /// not supported by this conversion.
    pub fn from_command(cmd: &TpmCommand, object_name: &Tpm2bName) -> Result<Self, TpmKeyError> {
        match cmd {
            TpmCommand::PolicyPcr(ref inner) => Self::from_policy_pcr_command(inner),
            TpmCommand::PolicyOr(inner) => Self::from_policy_or_command(inner),
            TpmCommand::PolicySecret(inner) => Self::from_policy_secret(inner, object_name),
            TpmCommand::PolicyAuthValue(_)
            | TpmCommand::PolicyPassword(_)
            | TpmCommand::PolicyGetDigest(_)
            | TpmCommand::PolicyRestart(_)
            | TpmCommand::PolicyPhysicalPresence(_) => Ok(Self::from_policy_zero_command(cmd.cc())),
            _ => Err(TpmKeyError::InvalidCc(cmd.cc() as u32)),
        }
    }

    fn to_policy_zero_command(&self) -> Result<TpmCommand, TpmKeyError> {
        if !self.body.is_empty() {
            return Err(TpmKeyError::InvalidPolicy);
        }

        match self.cc {
            TpmCc::PolicyAuthValue => Ok(TpmCommand::PolicyAuthValue(TpmPolicyAuthValueCommand {
                policy_session: POLICY_SESSION,
            })),
            TpmCc::PolicyPassword => Ok(TpmCommand::PolicyPassword(TpmPolicyPasswordCommand {
                policy_session: POLICY_SESSION,
            })),
            TpmCc::PolicyGetDigest => Ok(TpmCommand::PolicyGetDigest(TpmPolicyGetDigestCommand {
                policy_session: POLICY_SESSION,
            })),
            TpmCc::PolicyRestart => Ok(TpmCommand::PolicyRestart(TpmPolicyRestartCommand {
                session_handle: POLICY_SESSION,
            })),
            TpmCc::PolicyPhysicalPresence => Ok(TpmCommand::PolicyPhysicalPresence(
                TpmPolicyPhysicalPresenceCommand {
                    policy_session: POLICY_SESSION,
                },
            )),
            _ => Err(TpmKeyError::InvalidCc(self.cc as u32)),
        }
    }

    fn from_policy_zero_command(cc: TpmCc) -> Self {
        Self {
            cc,
            body: Vec::new(),
        }
    }

    fn to_policy_pcr_command(&self) -> Result<TpmCommand, TpmKeyError> {
        let (pcr_digest, rest) =
            Tpm2bDigest::unmarshal(self.body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
        let (pcrs, rest) = TpmlPcrSelection::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
        if !rest.is_empty() {
            return Err(TpmKeyError::InvalidPolicy);
        }

        let inner = TpmPolicyPcrCommand {
            policy_session: POLICY_SESSION,
            pcr_digest,
            pcrs,
        };

        Ok(TpmCommand::PolicyPcr(inner))
    }

    fn from_policy_pcr_command(inner: &TpmPolicyPcrCommand) -> Result<Self, TpmKeyError> {
        let buf = tpm_marshal_array(&[&inner.pcr_digest, &inner.pcrs])?;

        Ok(Self {
            cc: TpmCc::PolicyPcr,
            body: buf,
        })
    }

    fn to_policy_or_command(&self) -> Result<TpmCommand, TpmKeyError> {
        let (p_hash_list, rest) =
            TpmlDigest::unmarshal(self.body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
        if !rest.is_empty() {
            return Err(TpmKeyError::InvalidPolicy);
        }

        let inner = TpmPolicyOrCommand {
            policy_session: POLICY_SESSION,
            p_hash_list,
        };

        Ok(TpmCommand::PolicyOr(inner))
    }

    fn from_policy_or_command(inner: &TpmPolicyOrCommand) -> Result<Self, TpmKeyError> {
        let buf = tpm_marshal_array(&[&inner.p_hash_list])?;

        Ok(Self {
            cc: TpmCc::PolicyOr,
            body: buf,
        })
    }

    fn to_policy_secret_command(&self) -> Result<TpmCommand, TpmKeyError> {
        let (auth_handle, rest) =
            TpmHandle::unmarshal(self.body.as_slice()).map_err(TpmKeyError::Unmarshal)?;
        let (_, rest) = Tpm2bName::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
        let (policy_ref, rest) = Tpm2bDigest::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
        if !rest.is_empty() {
            return Err(TpmKeyError::InvalidPolicy);
        }

        let inner = TpmPolicySecretCommand {
            auth_handle,
            policy_session: POLICY_SESSION,
            nonce_tpm: Tpm2bDigest::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref,
            expiration: 0,
        };

        Ok(TpmCommand::PolicySecret(inner))
    }

    /// Constructs a `PolicySecret` policy step from a typed command and the
    /// object's name.
    ///
    /// This helper is more expressive than [`from_command`](Self::from_command)
    /// for `PolicySecret` because the TPM command itself does not carry the
    /// `TPM2B_NAME` required by the RFC encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    fn from_policy_secret(
        inner: &TpmPolicySecretCommand,
        object_name: &Tpm2bName,
    ) -> Result<Self, TpmKeyError> {
        let buf = tpm_marshal_array(&[&inner.auth_handle, object_name, &inner.policy_ref])?;

        Ok(Self {
            cc: TpmCc::PolicySecret,
            body: buf,
        })
    }
}

/// A policy branch (used for `auth_policy` list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPolicy {
    pub name: Option<String>,
    pub policy: Vec<TpmPolicyCommand>,
}

/// List of typed TPM commands corresponding to a policy sequence.
pub type TpmCommandList = Vec<TpmCommand>;

/// High-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKey {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
    pub parent_handle: TpmHandle,
    pub parent_public: Option<Tpm2bPublic>,
    pub empty_auth: Option<bool>,
    pub policy: Option<TpmPolicy>,
    pub auth_policy: Option<Vec<TpmPolicy>>,
    pub secret: Option<Vec<u8>>,
    pub description: Option<String>,
}

fn key_type_to_oid_for_encode(
    key_type: TpmAlgId,
    has_secret: bool,
) -> Result<ObjectIdentifier, TpmKeyError> {
    match key_type {
        TpmAlgId::Rsa | TpmAlgId::Ecc => {
            if has_secret {
                Ok(OID_IMPORTABLE_KEY.clone())
            } else {
                Ok(OID_LOADABLE_KEY.clone())
            }
        }
        TpmAlgId::KeyedHash => Ok(OID_SEALED_DATA.clone()),
        _ => Err(TpmKeyError::InvalidKeyType),
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

    /// Serialize this key into PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 encoding fails.
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
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 decoding or
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
        let pem = pem::parse(pem_bytes)?;
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
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 encoding fails.
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType) when `key_type`
    /// is not `Rsa`, `Ecc`, or `KeyedHash`.
    /// Returns [`Marshal`](crate::VtpmError::Marshal) when the value cannot be
    /// marshalled into the underlying TPM buffer.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        let asn1 = self.to_asn1()?;
        rasn::der::encode(&asn1).map_err(|_| TpmKeyError::InvalidDer)
    }

    /// Parse a key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer) when ASN.1 decoding or
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
        let asn1: TpmKeyAsn1 = rasn::der::decode(der_bytes).map_err(|_| TpmKeyError::InvalidDer)?;
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

        let key_type_oid =
            key_type_to_oid_for_encode(self.public.inner.object_type, self.secret.is_some())?;

        let policy_asn1 = self.policy.as_ref().map(Vec::<TpmPolicyCommandAsn1>::from);

        let auth_policy_asn1 = self
            .auth_policy
            .as_ref()
            .map(|list| list.iter().map(TpmAuthPolicyAsn1::from).collect::<Vec<_>>());

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

        if asn1.key_type == OID_LOADABLE_KEY || asn1.key_type == OID_IMPORTABLE_KEY {
            if !(key_type == TpmAlgId::Rsa || key_type == TpmAlgId::Ecc) {
                return Err(TpmKeyError::InvalidKeyType);
            }
        } else if asn1.key_type == OID_SEALED_DATA {
            if key_type != TpmAlgId::KeyedHash {
                return Err(TpmKeyError::InvalidKeyType);
            }
        } else {
            return Err(TpmKeyError::InvalidDerTag(asn1.key_type.to_string()));
        }

        let is_importable_oid = asn1.key_type == OID_IMPORTABLE_KEY;
        if is_importable_oid && asn1.secret.is_none() {
            return Err(TpmKeyError::MissingSecret);
        }

        let policy = asn1.policy.map(TpmPolicy::try_from).transpose()?;

        let auth_policy = asn1
            .auth_policy
            .map(|branches| {
                branches
                    .into_iter()
                    .map(TpmPolicy::try_from)
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

impl TryFrom<&[u8]> for TpmKey {
    type Error = TpmKeyError;

    /// Parse a key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDer`](crate::Error::InvalidDer)
    /// Returns [`InvalidKeyType`](crate::Error::InvalidKeyType)
    /// Returns [`InvalidDerTag`](crate::Error::InvalidDerTag)
    /// Returns [`InvalidPolicy`](crate::Error::InvalidPolicy)
    /// Returns [`InvalidCc`](crate::Error::InvalidCc)
    /// Returns [`MissingSecret`](crate::Error::MissingSecret)
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_der(value)
    }
}

impl TryFrom<TpmPolicyCommandAsn1> for TpmPolicyCommand {
    type Error = TpmKeyError;

    fn try_from(val: TpmPolicyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code)
            .map_err(|_| TpmKeyError::InvalidCc(val.command_code))?;
        let body = val.command_policy.as_ref().to_vec();
        validate_policy_command(cc, &body)?;
        Ok(Self { cc, body })
    }
}

impl TryFrom<TpmAuthPolicyAsn1> for TpmPolicy {
    type Error = TpmKeyError;

    fn try_from(val: TpmAuthPolicyAsn1) -> Result<Self, Self::Error> {
        let cmds = val
            .policy
            .into_iter()
            .map(TpmPolicyCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: val.name,
            policy: cmds,
        })
    }
}

impl TryFrom<Vec<TpmPolicyCommandAsn1>> for TpmPolicy {
    type Error = TpmKeyError;

    fn try_from(cmds: Vec<TpmPolicyCommandAsn1>) -> Result<Self, Self::Error> {
        let cmds = cmds
            .into_iter()
            .map(TpmPolicyCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: None,
            policy: cmds,
        })
    }
}

impl From<&TpmPolicyCommand> for TpmPolicyCommandAsn1 {
    fn from(c: &TpmPolicyCommand) -> Self {
        Self {
            command_code: c.cc as u32,
            command_policy: OctetString::copy_from_slice(&c.body),
        }
    }
}

impl From<&TpmPolicy> for TpmAuthPolicyAsn1 {
    fn from(p: &TpmPolicy) -> Self {
        Self {
            name: p.name.as_deref().map(Utf8String::from),
            policy: p.policy.iter().map(TpmPolicyCommandAsn1::from).collect(),
        }
    }
}

impl From<&TpmPolicy> for Vec<TpmPolicyCommandAsn1> {
    fn from(p: &TpmPolicy) -> Self {
        p.policy.iter().map(TpmPolicyCommandAsn1::from).collect()
    }
}

const ZERO_PARAM_CMDS: &[TpmCc] = &[
    TpmCc::PolicyAuthValue,
    TpmCc::PolicyPassword,
    TpmCc::PolicyGetDigest,
    TpmCc::PolicyRestart,
    TpmCc::PolicyPhysicalPresence,
];

fn validate_policy_command(cc: TpmCc, body: &[u8]) -> Result<(), TpmKeyError> {
    if ZERO_PARAM_CMDS.contains(&cc) {
        if !body.is_empty() {
            return Err(TpmKeyError::InvalidPolicy);
        }
        return Ok(());
    }

    match cc {
        TpmCc::PolicyAuthorize => validate_policy_authorize(body),
        TpmCc::PolicySecret => validate_policy_secret(body),
        TpmCc::PolicyPcr => validate_policy_pcr(body),
        TpmCc::PolicyOr => validate_policy_or(body),
        _ => Ok(()),
    }
}

fn validate_policy_authorize(body: &[u8]) -> Result<(), TpmKeyError> {
    let (.., rest) = Tpm2bPublic::unmarshal(body).map_err(TpmKeyError::Unmarshal)?;
    let (.., rest) = Tpm2bDigest::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
    let (.., rest) = TpmtSignature::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
    if !rest.is_empty() {
        return Err(TpmKeyError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_secret(body: &[u8]) -> Result<(), TpmKeyError> {
    let (.., rest) = TpmHandle::unmarshal(body).map_err(TpmKeyError::Unmarshal)?;
    let (.., rest) = Tpm2bName::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
    let (.., rest) = Tpm2bDigest::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
    if !rest.is_empty() {
        return Err(TpmKeyError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_pcr(body: &[u8]) -> Result<(), TpmKeyError> {
    let (.., rest) = Tpm2bDigest::unmarshal(body).map_err(TpmKeyError::Unmarshal)?;
    let (.., rest) = TpmlPcrSelection::unmarshal(rest).map_err(TpmKeyError::Unmarshal)?;
    if !rest.is_empty() {
        return Err(TpmKeyError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_or(body: &[u8]) -> Result<(), TpmKeyError> {
    let (.., rest) = TpmlDigest::unmarshal(body).map_err(TpmKeyError::Unmarshal)?;
    if !rest.is_empty() {
        return Err(TpmKeyError::InvalidPolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tpm2_protocol::data::{
        Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmlDigest, TpmlPcrSelection, TpmsRsaParms,
        TpmtPublic, TpmtSensitive, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite,
        TpmuSignature,
    };

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
            Err(TpmKeyError::InvalidPolicy)
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
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

    #[test]
    fn policy_authorize_empty_err() {
        assert!(matches!(
            validate_policy_command(TpmCc::PolicyAuthorize, &[]),
            Err(TpmKeyError::Unmarshal(_))
        ));
    }

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
        let pub_bytes = tpm_marshal_array(&[&public]).unwrap();
        let priv_bytes = tpm_marshal_array(&[&private]).unwrap();

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
            Err(TpmKeyError::InvalidCc(0xFFFF_FF00)) => {}
            other => panic!("expected InvalidCc, got: {other:?}"),
        }
    }

    #[test]
    fn importable_without_secret_fails() {
        let (public, private) = minimal_rsa_key_components();
        let pub_bytes = tpm_marshal_array(&[&public]).unwrap();
        let priv_bytes = tpm_marshal_array(&[&private]).unwrap();

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
        assert!(matches!(res, Err(TpmKeyError::InvalidPem(_))));
    }

    #[test]
    fn policy_command_authorize_constructor_ok() {
        let cmd = TpmPolicyCommand::authorize(
            &Tpm2bPublic::default(),
            &Tpm2bDigest::default(),
            &TpmtSignature {
                sig_alg: TpmAlgId::Null,
                signature: TpmuSignature::Null,
            },
        )
        .unwrap();

        assert_eq!(cmd.code(), TpmCc::PolicyAuthorize);
        assert!(validate_policy_authorize(cmd.body()).is_ok());
    }

    #[test]
    fn policy_command_secret_constructor_ok() {
        let cmd =
            TpmPolicyCommand::secret(TpmHandle(0), &Tpm2bName::default(), &Tpm2bDigest::default())
                .unwrap();

        assert_eq!(cmd.code(), TpmCc::PolicySecret);
        assert!(validate_policy_secret(cmd.body()).is_ok());
    }

    #[rstest]
    #[case(TpmCc::PolicyAuthValue)]
    #[case(TpmCc::PolicyPassword)]
    #[case(TpmCc::PolicyGetDigest)]
    #[case(TpmCc::PolicyRestart)]
    #[case(TpmCc::PolicyPhysicalPresence)]
    fn policy_zero_param_to_and_from_command_roundtrip(#[case] cc: TpmCc) {
        let step = TpmPolicyCommand::zero(cc).unwrap();
        let cmd = step.to_command().unwrap();

        assert_eq!(cmd.cc(), cc);

        match &cmd {
            TpmCommand::PolicyAuthValue(c) => assert_eq!(c.policy_session, POLICY_SESSION),
            TpmCommand::PolicyPassword(c) => assert_eq!(c.policy_session, POLICY_SESSION),
            TpmCommand::PolicyGetDigest(c) => assert_eq!(c.policy_session, POLICY_SESSION),
            TpmCommand::PolicyRestart(c) => assert_eq!(c.session_handle, POLICY_SESSION),
            TpmCommand::PolicyPhysicalPresence(c) => assert_eq!(c.policy_session, POLICY_SESSION),
            _ => panic!("Unexpected command variant in zero-param test"),
        }

        let back = TpmPolicyCommand::from_command(&cmd, &Tpm2bName::default()).unwrap();
        assert_eq!(back.code(), cc);
        assert!(back.body().is_empty());
    }

    #[test]
    fn policy_pcr_to_and_from_command_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            Tpm2bDigest::default().marshal(&mut writer).unwrap();
            TpmlPcrSelection::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = TpmPolicyCommand::from_raw(TpmCc::PolicyPcr, body).unwrap();
        let cmd = step.to_command().unwrap();

        match cmd {
            TpmCommand::PolicyPcr(inner) => {
                assert_eq!(inner.policy_session, POLICY_SESSION);
                let back = TpmPolicyCommand::from_command(&cmd, &Tpm2bName::default()).unwrap();
                assert_eq!(back, step);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn policy_or_to_and_from_command_roundtrip() {
        let mut body = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut body);
            TpmlDigest::default().marshal(&mut writer).unwrap();
            writer.len()
        };
        body.truncate(len);

        let step = TpmPolicyCommand::from_raw(TpmCc::PolicyOr, body).unwrap();
        let cmd = step.to_command().unwrap();

        match cmd {
            TpmCommand::PolicyOr(inner) => {
                assert_eq!(inner.policy_session, POLICY_SESSION);
                let back = TpmPolicyCommand::from_command(&cmd, &Tpm2bName::default()).unwrap();
                assert_eq!(back, step);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn policy_secret_to_command_uses_fixed_session() -> Result<(), TpmKeyError> {
        let step = TpmPolicyCommand::secret(
            TpmHandle(0x8100_0000),
            &Tpm2bName::default(),
            &Tpm2bDigest::default(),
        )?;

        let cmd = step.to_command()?;

        match cmd {
            TpmCommand::PolicySecret(inner) => {
                assert_eq!(inner.auth_handle, TpmHandle(0x8100_0000));
                assert_eq!(inner.policy_session, POLICY_SESSION);
                assert_eq!(inner.expiration, 0);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn policy_secret_from_command_requires_name() {
        let cmd = TpmPolicySecretCommand {
            auth_handle: TpmHandle(0x8100_0000),
            policy_session: POLICY_SESSION,
            ..Default::default()
        };
        let name = Tpm2bName::default();

        let step = TpmPolicyCommand::from_policy_secret(&cmd, &name).unwrap();
        assert_eq!(step.code(), TpmCc::PolicySecret);

        let (decoded, _) = TpmHandle::unmarshal(step.body()).unwrap();
        assert_eq!(decoded, TpmHandle(0x8100_0000));
    }
}
