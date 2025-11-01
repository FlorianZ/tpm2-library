// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

//! A reader and writer for the [TPM 2.0
//! Key](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)
//! ASN.1 files. The format is extended with optional `parentPubkey` field,
//! containing `Tpm2bPublic` of the parent key.

use pem::Pem;
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use std::collections::HashMap;
use thiserror::Error;
use tpm2_policy_language::{Expression, Handle, HandleClass, PcrSelection, PolicyState};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmlPcrSelection},
    frame::{tpm_unmarshal_command, TpmBodyMarshal, TpmCommandBody, TpmFrame},
    TpmError, TpmHandle, TpmMarshal, TpmSized, TpmUnmarshal, TpmWriter,
};

/// Error type for TPM key format operations.
#[derive(Debug, Error)]
pub enum TpmKeyError {
    #[error("unsupported algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("malformed data: {0}")]
    MalformedData(String),
    #[error("unsupported policy command: 0x{0:08x}")]
    UnsupportedPolicyCommand(u32),
    #[error("unknown OID: {0}")]
    UnknownOid(String),
    #[error("unknown PEM tag: {0}")]
    UnknownPemTag(String),
}

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmError> {
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
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 3]));
pub const OID_IMPORTABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 4]));
pub const OID_SEALED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 5]));

/// A single policy command step, directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmPolicyCommand {
    #[rasn(tag(explicit(context, 0)))]
    pub command_code: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub command_policy: OctetString,
}

impl TpmPolicyCommand {
    /// Converts a sequence of `TpmPolicyCommand`s into an `Expression` AST.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the
    /// command body bytes cannot be umarshaled, when the policy sequence is empty,
    /// or when an invalid PCR index is found.
    /// Returns [`UnsupportedPolicyCommand`](crate::TpmKeyError::UnsupportedPolicyCommand)
    /// when a command code is encountered that is not supported by the
    /// `Expression` AST representation.
    pub fn to_expression(commands: Vec<Self>) -> Result<Expression, TpmKeyError> {
        let mut expressions: Vec<Expression> = commands
            .into_iter()
            .map(|cmd| {
                let cc = TpmCc::try_from(cmd.command_code)
                    .map_err(|()| TpmKeyError::UnsupportedPolicyCommand(cmd.command_code))?;
                match cc {
                    TpmCc::PolicyPcr => {
                        let (pcrs, remainder) = TpmlPcrSelection::unmarshal(&cmd.command_policy)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (pcr_digest, _) = Tpm2bDigest::unmarshal(remainder)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;

                        let selections = pcrs
                            .iter()
                            .map(|sel| {
                                let mut indices = Vec::new();
                                for (byte_idx, &byte) in sel.pcr_select.iter().enumerate() {
                                    for bit_idx in 0..8 {
                                        if (byte >> bit_idx) & 1 == 1 {
                                            let index = u32::try_from(byte_idx * 8 + bit_idx)
                                                .map_err(|e| {
                                                    TpmKeyError::MalformedData(e.to_string())
                                                })?;
                                            indices.push(index);
                                        }
                                    }
                                }
                                Ok(PcrSelection {
                                    alg: sel.hash,
                                    indices,
                                })
                            })
                            .collect::<Result<Vec<_>, TpmKeyError>>()?;

                        let digest = if pcr_digest.is_empty() {
                            None
                        } else {
                            Some(hex::encode(pcr_digest))
                        };
                        Ok(Expression::Pcr {
                            selections,
                            digest,
                            count: None,
                        })
                    }
                    TpmCc::PolicySecret => {
                        let (handle, remainder) = TpmHandle::unmarshal(&cmd.command_policy)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (_name, remainder) = Tpm2bName::unmarshal(remainder)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (_policy_ref, _) = Tpm2bDigest::unmarshal(remainder)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;

                        Ok(Expression::Secret {
                            auth_handle: Box::new(Expression::Handle(Handle::new(
                                HandleClass::Tpm,
                                handle.0,
                            ))),
                            password: None,
                            cp_hash: None,
                        })
                    }
                    _ => Err(TpmKeyError::UnsupportedPolicyCommand(cc as u32)),
                }
            })
            .collect::<Result<_, _>>()?;

        match expressions.len() {
            0 => Err(TpmKeyError::MalformedData(
                "policy command sequence cannot be empty".to_string(),
            )),
            1 => Ok(expressions.remove(0)),
            _ => Ok(Expression::And(expressions)),
        }
    }
}

/// A TPM authorization policy struct that is directly compatible with ASN.1 DER
/// encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmAuthPolicy {
    #[rasn(tag(explicit(context, 0)))]
    pub name: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Vec<TpmPolicyCommand>,
}

/// A TPM key struct that is directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmKeyAsn1 {
    pub key_type: ObjectIdentifier,
    #[rasn(tag(explicit(context, 0)))]
    pub empty_auth: Option<bool>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Option<Vec<TpmPolicyCommand>>,
    #[rasn(tag(explicit(context, 2)))]
    pub secret: Option<OctetString>,
    #[rasn(tag(explicit(context, 3)))]
    pub auth_policy: Option<Vec<TpmAuthPolicy>>,
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

impl TpmKeyAsn1 {
    /// Parses and returns the public area of the key.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the
    /// public key bytes cannot be umarshaled.
    pub fn public(&self) -> Result<Tpm2bPublic, TpmKeyError> {
        let (public, _) = Tpm2bPublic::unmarshal(&self.pubkey)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        Ok(public)
    }

    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`](crate::TpmKeyError::InvalidData) when the key's
    /// fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmKeyError> {
        Ok(pem::encode(&Pem::new("TSS2 PRIVATE KEY", self.to_der()?)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`](crate::TpmKeyError::InvalidData) when the key's
    /// fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        rasn::der::encode(self).map_err(|e| TpmKeyError::InvalidData(e.to_string()))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the PEM
    /// or inner DER bytes cannot be umarshaled.
    /// Returns [`UnknownPemTag`](crate::TpmKeyError::UnknownPemTag) when the PEM
    /// tag is not 'TSS2 PRIVATE KEY'.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        let pem = pem::parse(pem_bytes).map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        if pem.tag() == "TSS2 PRIVATE KEY" {
            Self::from_der(pem.contents())
        } else {
            Err(TpmKeyError::UnknownPemTag(pem.tag().to_string()))
        }
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the DER
    /// bytes cannot be umarshaled.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        rasn::der::decode(der_bytes).map_err(|e| TpmKeyError::MalformedData(e.to_string()))
    }
}

/// A high-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKey {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
    pub parent_handle: TpmHandle,
    pub parent_public: Option<Tpm2bPublic>,
    pub key_type: TpmAlgId,
    pub empty_auth: Option<bool>,
    pub policy: Option<Vec<Vec<u8>>>,
}

fn oid_to_key_type(oid: &ObjectIdentifier) -> Result<TpmAlgId, TpmKeyError> {
    if oid == &OID_LOADABLE_KEY || oid == &OID_IMPORTABLE_KEY {
        Ok(TpmAlgId::Null)
    } else if oid == &OID_SEALED_DATA {
        Ok(TpmAlgId::KeyedHash)
    } else {
        Err(TpmKeyError::UnknownOid(oid.to_string()))
    }
}

fn key_type_to_oid(key_type: TpmAlgId) -> Result<ObjectIdentifier, TpmKeyError> {
    match key_type {
        TpmAlgId::Rsa | TpmAlgId::Ecc => Ok(OID_LOADABLE_KEY.clone()),
        TpmAlgId::KeyedHash => Ok(OID_SEALED_DATA.clone()),
        _ => Err(TpmKeyError::InvalidAlgorithm(key_type.to_string())),
    }
}

impl TpmKey {
    /// Returns the public area of the key.
    #[must_use]
    pub fn public(&self) -> &Tpm2bPublic {
        &self.public
    }

    /// Returns the private area of the key.
    #[must_use]
    pub fn private(&self) -> &Tpm2bPrivate {
        &self.private
    }

    /// Returns the parent handle of the key.
    #[must_use]
    pub fn parent_handle(&self) -> TpmHandle {
        self.parent_handle
    }

    /// Returns the parent's public area, if available.
    #[must_use]
    pub fn parent_public(&self) -> Option<&Tpm2bPublic> {
        self.parent_public.as_ref()
    }

    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`](crate::TpmKeyError::InvalidData) when the key's
    /// fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmKeyError> {
        let asn1 = self.to_asn1()?;
        asn1.to_pem()
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`](crate::TpmKeyError::InvalidData) when the key's
    /// fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        let asn1 = self.to_asn1()?;
        asn1.to_der()
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the PEM
    /// or inner DER bytes cannot be umarshaled.
    /// Returns [`UnknownPemTag`](crate::TpmKeyError::UnknownPemTag) when the PEM
    /// tag is not 'TSS2 PRIVATE KEY'.
    pub fn from_pem(pem_bytes: &[u8], context: &PolicyState) -> Result<Self, TpmKeyError> {
        let asn1 = TpmKeyAsn1::from_pem(pem_bytes)?;
        Self::from_asn1(asn1, context)
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the DER
    /// bytes cannot be umarshaled.
    pub fn from_der(der_bytes: &[u8], context: &PolicyState) -> Result<Self, TpmKeyError> {
        let asn1 = TpmKeyAsn1::from_der(der_bytes)?;
        Self::from_asn1(asn1, context)
    }

    /// Converts the runtime `TpmKey` into its ASN.1 representation.
    fn to_asn1(&self) -> Result<TpmKeyAsn1, TpmKeyError> {
        let rsa_parent = self
            .parent_public
            .as_ref()
            .map(|pp| pp.inner.object_type == TpmAlgId::Rsa);

        let parent_pubkey_bytes = if let Some(parent_public) = &self.parent_public {
            Some(OctetString::copy_from_slice(
                &write_object(parent_public)
                    .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
            ))
        } else {
            None
        };

        let resolved_key_type = if self.key_type == TpmAlgId::Null {
            self.public.inner.object_type
        } else {
            self.key_type
        };
        let key_type_oid = key_type_to_oid(resolved_key_type)?;

        let (policy, auth_policy) = if let Some(blobs) = &self.policy {
            let expr = Expression::from_command_list(blobs)
                .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;

            let (policy, auth_policy) = match expr {
                Expression::Or(branches) => {
                    let auth_policies = branches
                        .iter()
                        .map(|branch| {
                            let (branch_blobs, _) = branch
                                .to_command_list(
                                    self.public.inner.name_alg,
                                    &PolicyState {
                                        banks: vec![],
                                        names: HashMap::default(),
                                    },
                                )
                                .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                            let commands = blobs_to_policy_commands(&branch_blobs)?;
                            Ok(TpmAuthPolicy {
                                name: None,
                                policy: commands,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    (None, Some(auth_policies))
                }
                _ => (Some(blobs_to_policy_commands(blobs)?), None),
            };
            (policy, auth_policy)
        } else {
            (None, None)
        };

        Ok(TpmKeyAsn1 {
            key_type: key_type_oid,
            empty_auth: self.empty_auth,
            policy,
            secret: None,
            auth_policy,
            description: None,
            rsa_parent,
            parent_pubkey: parent_pubkey_bytes,
            parent: self.parent_handle.0,
            pubkey: OctetString::copy_from_slice(
                &write_object(&self.public).map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
            ),
            privkey: OctetString::copy_from_slice(
                &write_object(&self.private)
                    .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
            ),
        })
    }

    /// Converts the ASN.1 `TpmKeyAsn1` into the runtime representation.
    fn from_asn1(asn1: TpmKeyAsn1, context: &PolicyState) -> Result<Self, TpmKeyError> {
        let (public, _) = Tpm2bPublic::unmarshal(&asn1.pubkey)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        let (private, _) = Tpm2bPrivate::unmarshal(&asn1.privkey)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        let parent_public = if let Some(parent_bytes) = &asn1.parent_pubkey {
            let (parent_pub, _) = Tpm2bPublic::unmarshal(parent_bytes)
                .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
            Some(parent_pub)
        } else {
            None
        };

        let mut key_type = oid_to_key_type(&asn1.key_type)?;
        if key_type == TpmAlgId::Null {
            key_type = public.inner.object_type;
        }

        let temp_expr = match (asn1.auth_policy, asn1.policy) {
            (Some(auth_policies), _) if !auth_policies.is_empty() => {
                let branches: Result<Vec<_>, _> = auth_policies
                    .into_iter()
                    .map(|p| TpmPolicyCommand::to_expression(p.policy))
                    .collect();
                Some(Expression::Or(branches?))
            }
            (_, Some(policy_commands)) => Some(TpmPolicyCommand::to_expression(policy_commands)?),
            _ => None,
        };

        let policy_blobs = if let Some(expr) = temp_expr {
            let (blobs, _) = expr
                .to_command_list(public.inner.name_alg, context)
                .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
            Some(blobs)
        } else {
            None
        };

        Ok(Self {
            public,
            private,
            parent_handle: TpmHandle(asn1.parent),
            parent_public,
            key_type,
            empty_auth: asn1.empty_auth,
            policy: policy_blobs,
        })
    }
}

/// Converts a list of TPM command blobs into a `Vec<TpmPolicyCommand>`.
fn blobs_to_policy_commands(blobs: &[Vec<u8>]) -> Result<Vec<TpmPolicyCommand>, TpmKeyError> {
    blobs
        .iter()
        .map(|blob| {
            let (_, cmd_body, _) = tpm_unmarshal_command(blob)
                .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;

            let mut params_buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
            let params_len = {
                let mut writer = TpmWriter::new(&mut params_buf);
                let marshal_result = match &cmd_body {
                    TpmCommandBody::PolicyPcr(c) => c.marshal_parameters(&mut writer),
                    TpmCommandBody::PolicySecret(c) => c.marshal_parameters(&mut writer),
                    TpmCommandBody::PolicyOr(c) => c.marshal_parameters(&mut writer),
                    TpmCommandBody::PolicyRestart(c) => c.marshal_parameters(&mut writer),
                    _ => return Err(TpmKeyError::UnsupportedPolicyCommand(cmd_body.cc() as u32)),
                };
                marshal_result.map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                writer.len()
            };
            params_buf.truncate(params_len);

            Ok(TpmPolicyCommand {
                command_code: cmd_body.cc() as u32,
                command_policy: OctetString::copy_from_slice(&params_buf),
            })
        })
        .collect()
}
