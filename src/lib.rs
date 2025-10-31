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
use thiserror::Error;
use tpm2_policy_language::{Expression, Handle, HandleClass, PcrSelection};
use tpm2_protocol::{
    data::{
        Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmlPcrSelection,
        TpmsPcrSelect, TpmsPcrSelection,
    },
    TpmBuild, TpmError, TpmHandle, TpmParse, TpmSized, TpmWriter,
};

/// Error type for TPM key format operations.
#[derive(Debug, Error)]
pub enum TpmKeyError {
    /// Returned when an unsupported algorithm is specified for key creation or
    /// serialization.
    #[error("unsupported algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Returned when data provided for serialization (e.g., to PEM) is invalid.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Returned when input data (e.g., from a PEM or DER file) is malformed
    /// and cannot be parsed.
    #[error("malformed data: {0}")]
    MalformedData(String),

    /// Returned when an ASN.1 `SEQUENCE OF TPMPolicy` contains a command that
    /// cannot be represented by the `Expression` AST.
    #[error("unsupported policy command: 0x{0:08x}")]
    UnsupportedPolicyCommand(u32),

    /// Returned when an unknown ASN.1 Object Identifier (OID) is
    /// encountered during parsing.
    #[error("unknown OID: {0}")]
    UnknownOid(String),

    /// Returned when a PEM file has an unknown tag.
    #[error("unknown PEM tag: {0}")]
    UnknownPemTag(String),
}

/// Serialize a type implementing `TpmBuild` type into `Vec<u8>`.
fn write_object<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmError> {
    let mut buf = vec![0u8; tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
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
    /// Returns [`MalformedData`] if the command body bytes cannot be parsed, if
    /// the policy sequence is empty, or if an invalid PCR index is found.
    /// Returns [`UnsupportedPolicyCommand`] if a command code is encountered that
    /// is not supported by the `Expression` AST representation.
    pub fn to_expression(commands: Vec<Self>) -> Result<Expression, TpmKeyError> {
        let mut expressions: Vec<Expression> = commands
            .into_iter()
            .map(|cmd| {
                let cc = TpmCc::try_from(cmd.command_code)
                    .map_err(|()| TpmKeyError::UnsupportedPolicyCommand(cmd.command_code))?;
                match cc {
                    TpmCc::PolicyPcr => {
                        let (pcrs, remainder) = TpmlPcrSelection::parse(&cmd.command_policy)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (pcr_digest, _) = Tpm2bDigest::parse(remainder)
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
                        let (handle, remainder) = TpmHandle::parse(&cmd.command_policy)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (_name, remainder) = Tpm2bName::parse(remainder)
                            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
                        let (_policy_ref, _) = Tpm2bDigest::parse(remainder)
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

    /// Converts an `Expression` AST into a sequence of `TpmPolicyCommand`s.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`] if the expression contains constructs that cannot
    /// be serialized into the `TPMPolicy` ASN.1 format, such as `OR` logic or
    /// malformed PCR digest strings.
    pub fn from_expression(expr: &Expression) -> Result<Vec<Self>, TpmKeyError> {
        let mut expressions = Vec::new();
        let mut stack = vec![expr];
        while let Some(e) = stack.pop() {
            match e {
                Expression::And(sub_exprs) => {
                    stack.extend(sub_exprs.iter().rev());
                }
                Expression::Or(_) => {
                    return Err(TpmKeyError::InvalidData(
                        "OR policies are not supported for serialization".to_string(),
                    ));
                }
                _ => expressions.push(e),
            }
        }

        expressions
            .into_iter()
            .map(|e| {
                let (command_code, command_policy_bytes) = match e {
                    Expression::Pcr {
                        selections, digest, ..
                    } => {
                        let pcr_digest = digest.as_ref().map_or_else(
                            || Ok(Tpm2bDigest::default()),
                            |hex_str| {
                                let bytes = hex::decode(hex_str)
                                    .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                                Tpm2bDigest::try_from(bytes.as_slice())
                                    .map_err(|e| TpmKeyError::InvalidData(e.to_string()))
                            },
                        )?;
                        let pcrs = pcr_selection_vec_to_tpml(selections)?;
                        let mut buf = Vec::new();
                        let mut writer = TpmWriter::new(&mut buf);
                        pcrs.build(&mut writer)
                            .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                        pcr_digest
                            .build(&mut writer)
                            .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                        (TpmCc::PolicyPcr, buf)
                    }
                    Expression::Secret { auth_handle, .. } => {
                        let handle = if let Expression::Handle(h) = **auth_handle {
                            h.value().ok_or_else(|| {
                                TpmKeyError::InvalidData(
                                    "secret() handle must not be a pattern".to_string(),
                                )
                            })?
                        } else {
                            return Err(TpmKeyError::InvalidData(
                                "secret() auth_handle must be a Handle expression".to_string(),
                            ));
                        };
                        let mut buf = Vec::new();
                        let mut writer = TpmWriter::new(&mut buf);
                        TpmHandle(handle)
                            .build(&mut writer)
                            .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                        Tpm2bName::default()
                            .build(&mut writer)
                            .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                        Tpm2bDigest::default()
                            .build(&mut writer)
                            .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
                        (TpmCc::PolicySecret, buf)
                    }
                    _ => {
                        return Err(TpmKeyError::InvalidData(format!(
                            "unsupported expression in policy sequence: {e}"
                        )));
                    }
                };
                Ok(Self {
                    command_code: command_code as u32,
                    command_policy: OctetString::copy_from_slice(&command_policy_bytes),
                })
            })
            .collect()
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
    pub parent_pub_key: Option<OctetString>,
    pub parent: u32,
    pub pub_key: OctetString,
    pub priv_key: OctetString,
}

impl TpmKeyAsn1 {
    /// Parses and returns the public area of the key.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`] if the public key bytes cannot be parsed.
    pub fn public(&self) -> Result<Tpm2bPublic, TpmKeyError> {
        let (public, _) = Tpm2bPublic::parse(&self.pub_key)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        Ok(public)
    }

    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`] if the key's fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmKeyError> {
        Ok(pem::encode(&Pem::new("TSS2 PRIVATE KEY", self.to_der()?)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`] if the key's fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        rasn::der::encode(self).map_err(|e| TpmKeyError::InvalidData(e.to_string()))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`] if the PEM or inner DER bytes cannot be parsed.
    /// Returns [`UnknownPemTag`] if the PEM tag is not 'TSS2 PRIVATE KEY'.
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
    /// Returns [`MalformedData`] if the DER bytes cannot be parsed.
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
    pub policy: Option<Expression>,
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
    /// Returns [`InvalidData`] if the key's fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmKeyError> {
        let asn1 = self.to_asn1()?;
        asn1.to_pem()
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`] if the key's fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmKeyError> {
        let asn1 = self.to_asn1()?;
        asn1.to_der()
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`] if the PEM or inner DER bytes cannot be parsed.
    /// Returns [`UnknownPemTag`] if the PEM tag is not 'TSS2 PRIVATE KEY'.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        let asn1 = TpmKeyAsn1::from_pem(pem_bytes)?;
        Self::from_asn1(asn1)
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`] if the DER bytes cannot be parsed.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, TpmKeyError> {
        let asn1 = TpmKeyAsn1::from_der(der_bytes)?;
        Self::from_asn1(asn1)
    }

    /// Converts the runtime `TpmKey` into its ASN.1 representation.
    fn to_asn1(&self) -> Result<TpmKeyAsn1, TpmKeyError> {
        let rsa_parent = self
            .parent_public
            .as_ref()
            .map(|pp| pp.inner.object_type == TpmAlgId::Rsa);

        let parent_pub_key_bytes = if let Some(parent_public) = &self.parent_public {
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

        Ok(TpmKeyAsn1 {
            key_type: key_type_oid,
            empty_auth: self.empty_auth,
            policy: self
                .policy
                .as_ref()
                .map(TpmPolicyCommand::from_expression)
                .transpose()?,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent,
            parent_pub_key: parent_pub_key_bytes,
            parent: self.parent_handle.0,
            pub_key: OctetString::copy_from_slice(
                &write_object(&self.public).map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
            ),
            priv_key: OctetString::copy_from_slice(
                &write_object(&self.private)
                    .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
            ),
        })
    }

    /// Converts the ASN.1 `TpmKeyAsn1` into the runtime representation.
    fn from_asn1(asn1: TpmKeyAsn1) -> Result<Self, TpmKeyError> {
        let (public, _) = Tpm2bPublic::parse(&asn1.pub_key)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        let (private, _) = Tpm2bPrivate::parse(&asn1.priv_key)
            .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
        let parent_public = if let Some(parent_bytes) = &asn1.parent_pub_key {
            let (parent_pub, _) = Tpm2bPublic::parse(parent_bytes)
                .map_err(|e| TpmKeyError::MalformedData(e.to_string()))?;
            Some(parent_pub)
        } else {
            None
        };

        let mut key_type = oid_to_key_type(&asn1.key_type)?;
        if key_type == TpmAlgId::Null {
            key_type = public.inner.object_type;
        }

        Ok(Self {
            public,
            private,
            parent_handle: TpmHandle(asn1.parent),
            parent_public,
            key_type,
            empty_auth: asn1.empty_auth,
            policy: asn1
                .policy
                .map(TpmPolicyCommand::to_expression)
                .transpose()?,
        })
    }
}

/// Converts a `Vec<PcrSelection>` to the TPM wire format `TpmlPcrSelection`.
fn pcr_selection_vec_to_tpml(selections: &[PcrSelection]) -> Result<TpmlPcrSelection, TpmKeyError> {
    let mut list = TpmlPcrSelection::new();
    for selection in selections {
        let mut pcr_select_bytes = vec![0u8; 3];
        for &pcr_index in &selection.indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= 24 {
                return Err(TpmKeyError::InvalidData(format!(
                    "invalid PCR index {pcr_index}"
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: selection.alg,
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())
                .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?,
        })
        .map_err(|e| TpmKeyError::InvalidData(e.to_string()))?;
    }
    Ok(list)
}
