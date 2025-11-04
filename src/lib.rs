//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::no_effect_underscore_binding)]

//! A reader and writer for the [TPM 2.0
//! Key](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)
//! ASN.1 files. The format is extended with optional `parentPubkey` field,
//! containing `Tpm2bPublic` of the parent key.

mod error;

pub use crate::error::*;
use pem::Pem;
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use tpm2_policy_language::{Expression, PolicyState};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmSt},
    frame::{
        tpm_marshal_command, tpm_unmarshal_command, TpmAuthCommands, TpmCommandBody, TpmFrame,
    },
    TpmHandle, TpmMarshal, TpmMarshalError, TpmUnmarshal, TpmWriter,
};

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmMarshalError> {
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
struct TpmPolicyCommandAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub command_code: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub command_policy: OctetString,
}

impl TpmPolicyCommandAsn1 {
    /// Marshals a command and auth session into an ASN.1-compatible struct.
    fn from_command(
        command: &TpmCommandBody,
        sessions: &TpmAuthCommands,
    ) -> Result<Self, TpmMarshalError> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let tag = if sessions.is_empty() {
            TpmSt::NoSessions
        } else {
            TpmSt::Sessions
        };
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            tpm_marshal_command(command, tag, sessions, &mut writer)?;
            writer.len()
        };
        buf.truncate(len);

        Ok(Self {
            command_code: command.cc() as u32,
            command_policy: OctetString::copy_from_slice(&buf),
        })
    }
}

/// A TPM authorization policy struct that is directly compatible with ASN.1 DER
/// encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
struct TpmAuthPolicyAsn1 {
    #[rasn(tag(explicit(context, 0)))]
    pub name: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Vec<TpmPolicyCommandAsn1>,
}

/// A TPM key struct that is directly compatible with ASN.1 DER encoding.
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

/// A high-level runtime representation of a TPM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKey {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
    pub parent_handle: TpmHandle,
    pub parent_public: Option<Tpm2bPublic>,
    pub key_type: TpmAlgId,
    pub empty_auth: Option<bool>,
    pub policy: Option<Vec<(TpmCommandBody, TpmAuthCommands)>>,
}

fn oid_to_key_type(oid: &ObjectIdentifier) -> Result<TpmAlgId, Error> {
    if oid == &OID_LOADABLE_KEY || oid == &OID_IMPORTABLE_KEY {
        Ok(TpmAlgId::Null)
    } else if oid == &OID_SEALED_DATA {
        Ok(TpmAlgId::KeyedHash)
    } else {
        Err(Error::Key(KeyError::UnknownOid(oid.to_string())))
    }
}

fn key_type_to_oid(key_type: TpmAlgId) -> Result<ObjectIdentifier, Error> {
    match key_type {
        TpmAlgId::Rsa | TpmAlgId::Ecc => Ok(OID_LOADABLE_KEY.clone()),
        TpmAlgId::KeyedHash => Ok(OID_SEALED_DATA.clone()),
        _ => Err(Error::Key(KeyError::InvalidAlgorithm(key_type.to_string()))),
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
    pub fn to_pem(&self, context: &PolicyState) -> Result<String, Error> {
        Ok(pem::encode(&Pem::new(
            "TSS2 PRIVATE KEY",
            self.to_der(context)?,
        )))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidData`](crate::TpmKeyError::InvalidData) when the key's
    /// fields cannot be encoded to DER.
    pub fn to_der(&self, context: &PolicyState) -> Result<Vec<u8>, Error> {
        let asn1 = self.to_asn1(context)?;
        rasn::der::encode(&asn1).map_err(|e| Error::Der(DerError::InvalidData(e.to_string())))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the PEM
    /// or inner DER bytes cannot be umarshaled.
    /// Returns [`UnknownPemTag`](crate::TpmKeyError::UnknownPemTag) when the PEM
    /// tag is not 'TSS2 PRIVATE KEY'.
    pub fn from_pem(pem_bytes: &[u8], context: &PolicyState) -> Result<Self, Error> {
        let pem = pem::parse(pem_bytes)
            .map_err(|e| Error::Pem(PemError::MalformedData(e.to_string())))?;
        if pem.tag() == "TSS2 PRIVATE KEY" {
            Self::from_der(pem.contents(), context)
        } else {
            Err(Error::Pem(PemError::InvalidTag(pem.tag().to_string())))
        }
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedData`](crate::TpmKeyError::MalformedData) when the DER
    /// bytes cannot be umarshaled.
    pub fn from_der(der_bytes: &[u8], context: &PolicyState) -> Result<Self, Error> {
        let asn1: TpmKeyAsn1 = rasn::der::decode(der_bytes)
            .map_err(|e| Error::Der(DerError::MalformedData(e.to_string())))?;
        Self::from_asn1(asn1, context)
    }

    /// Converts the runtime `TpmKey` into its ASN.1 representation.
    fn to_asn1(&self, context: &PolicyState) -> Result<TpmKeyAsn1, Error> {
        let rsa_parent = self
            .parent_public
            .as_ref()
            .map(|pp| pp.inner.object_type == TpmAlgId::Rsa);

        let parent_pubkey_bytes = if let Some(parent_public) = &self.parent_public {
            Some(OctetString::copy_from_slice(&write_object(parent_public)?))
        } else {
            None
        };

        let resolved_key_type = if self.key_type == TpmAlgId::Null {
            self.public.inner.object_type
        } else {
            self.key_type
        };
        let key_type_oid = key_type_to_oid(resolved_key_type)?;

        let (policy, auth_policy) = if let Some(commands) = &self.policy {
            let expr = Expression::from_command_list(commands)?;

            let (policy, auth_policy) = match expr {
                Expression::Or(branches) => {
                    let auth_policies = branches
                        .iter()
                        .map(|branch| {
                            let (branch_commands, _) =
                                branch.to_command_list(self.public.inner.name_alg, context)?;

                            let commands = branch_commands
                                .iter()
                                .map(|(cmd, auth)| {
                                    TpmPolicyCommandAsn1::from_command(cmd, auth)
                                        .map_err(Error::from)
                                })
                                .collect::<Result<_, _>>()?;

                            Ok::<_, Error>(TpmAuthPolicyAsn1 {
                                name: None,
                                policy: commands,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    (None, Some(auth_policies))
                }
                _ => (
                    Some(
                        commands
                            .iter()
                            .map(|(cmd, auth)| {
                                TpmPolicyCommandAsn1::from_command(cmd, auth).map_err(Error::from)
                            })
                            .collect::<Result<_, Error>>()?,
                    ),
                    None,
                ),
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
            pubkey: OctetString::copy_from_slice(&write_object(&self.public)?),
            privkey: OctetString::copy_from_slice(&write_object(&self.private)?),
        })
    }

    /// Converts the ASN.1 `TpmKeyAsn1` into the runtime representation.
    fn from_asn1(asn1: TpmKeyAsn1, _context: &PolicyState) -> Result<Self, Error> {
        let (public, _) = Tpm2bPublic::unmarshal(&asn1.pubkey)?;
        let (private, _) = Tpm2bPrivate::unmarshal(&asn1.privkey)?;
        let parent_public = if let Some(parent_bytes) = &asn1.parent_pubkey {
            let (parent_pub, _) = Tpm2bPublic::unmarshal(parent_bytes)?;
            Some(parent_pub)
        } else {
            None
        };

        let mut key_type = oid_to_key_type(&asn1.key_type)?;
        if key_type == TpmAlgId::Null {
            key_type = public.inner.object_type;
        }

        let policy_commands = if let Some(auth_policies) = asn1.auth_policy {
            let mut commands = Vec::new();
            for branch in auth_policies {
                for cmd in branch.policy {
                    let (_, body, auth) = tpm_unmarshal_command(cmd.command_policy.as_ref())?;
                    commands.push((body, auth));
                }
            }
            Some(commands)
        } else if let Some(policy) = asn1.policy {
            let commands = policy
                .iter()
                .map(|cmd| {
                    let (_, body, auth) = tpm_unmarshal_command(cmd.command_policy.as_ref())?;
                    Ok((body, auth))
                })
                .collect::<Result<_, Error>>()?;
            Some(commands)
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
            policy: policy_commands,
        })
    }
}
