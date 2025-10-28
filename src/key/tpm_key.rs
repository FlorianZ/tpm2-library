// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::no_effect_underscore_binding)]

use super::{Alg, KeyError};
use crate::{
    auth::Auth,
    device::{Device, DeviceError},
    job::{Job, JobError},
    template,
    vtpm::VtpmError,
    write_object,
};

use pem::Pem;
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use tpm2_protocol::data::TpmRcBase;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitiveCreate,
        Tpm2bSensitiveData, TpmCc, TpmaObject, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    message::TpmCreateCommand,
    TpmError, TpmHandle, TpmParse,
};

pub const OID_LOADABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 3]));
pub const OID_IMPORTABLE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 4]));
pub const OID_SEALED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 23, 133, 10, 1, 5]));

/// A template for creating a new TPM key object.
pub struct TpmKeyTemplate<'a> {
    pub alg_desc: &'a Alg,
    pub sensitive_data: Tpm2bSensitiveData,
    pub key_type_oid: ObjectIdentifier,
}

/// A TPM policy struct that is directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmPolicy {
    #[rasn(tag(explicit(context, 0)))]
    pub command_code: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub command_policy: OctetString,
}

/// A TPM authorization policy struct that is directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmAuthPolicy {
    #[rasn(tag(explicit(context, 0)))]
    pub name: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Vec<TpmPolicy>,
}

/// A TPM key struct that is directly compatible with ASN.1 DER encoding.
#[derive(AsnType, Decode, Encode, Clone, Debug, Eq, PartialEq)]
pub struct TpmKey {
    pub key_type: ObjectIdentifier,
    #[rasn(tag(explicit(context, 0)))]
    pub empty_auth: Option<bool>,
    #[rasn(tag(explicit(context, 1)))]
    pub policy: Option<Vec<TpmPolicy>>,
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

impl TpmKey {
    /// Creates a new `TpmKey` by executing a `TPM2_Create` command.
    ///
    /// # Errors
    ///
    /// Returns a `KeyError` if any of the TPM structures cannot be serialized or the command fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &mut Job,
        device: &mut Device,
        auth_list: &[Auth],
        user_auth: Tpm2bAuth,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
        parent_handle: TpmHandle,
        template: &TpmKeyTemplate,
    ) -> Result<Self, KeyError> {
        let public_template =
            template::build_public(template.alg_desc, auth_policy, object_attributes);

        let create_cmd = TpmCreateCommand {
            parent_handle: parent_handle.0.into(),
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth,
                    data: template.sensitive_data,
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };

        let handles = [parent_handle.0];
        let (resp, _) = job
            .execute(device, &create_cmd, &handles, auth_list)
            .map_err(|e| {
                if let JobError::Device(DeviceError::TpmRc(rc)) = &e {
                    if rc.base() == TpmRcBase::Type {
                        return KeyError::InvalidParent(parent_handle.0);
                    }
                }
                match e {
                    JobError::Device(d) => KeyError::Device(d),
                    JobError::Vtpm(
                        VtpmError::Auth(_)
                        | VtpmError::HandleNotFound(_, _)
                        | VtpmError::TrailingAuthorizations,
                    ) => KeyError::Device(DeviceError::TpmProtocol(TpmError::Malformed)),
                    _ => KeyError::ValueConversionFailed(e.to_string()),
                }
            })?;

        let create_resp = resp
            .Create()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Create))?;

        let (parent_public, _) = device.read_public(parent_handle)?;
        let parent_public_2b = Tpm2bPublic {
            inner: parent_public,
        };

        Self::from_creation_data(
            user_auth.is_empty(),
            parent_handle,
            &create_resp.out_public,
            &create_resp.out_private,
            &auth_policy,
            template.key_type_oid.clone(),
            &parent_public_2b,
        )
    }

    /// Creates a new `TpmKey` from the raw TPM creation response data.
    #[allow(clippy::too_many_arguments)]
    fn from_creation_data(
        empty_auth: bool,
        parent_handle: TpmHandle,
        out_public: &Tpm2bPublic,
        out_private: &Tpm2bPrivate,
        policy_digest: &Tpm2bDigest,
        key_type: ObjectIdentifier,
        parent_public: &Tpm2bPublic,
    ) -> Result<Self, KeyError> {
        let policy = if policy_digest.is_empty() {
            None
        } else {
            Some(vec![TpmPolicy {
                command_code: 0,
                command_policy: OctetString::copy_from_slice(policy_digest.as_ref()),
            }])
        };
        Ok(Self {
            key_type,
            empty_auth: empty_auth.then_some(true),
            policy,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: None,
            parent_pub_key: Some(OctetString::copy_from_slice(
                &write_object(parent_public).map_err(DeviceError::TpmProtocol)?,
            )),
            parent: parent_handle.0,
            pub_key: OctetString::copy_from_slice(
                &write_object(out_public).map_err(DeviceError::TpmProtocol)?,
            ),
            priv_key: OctetString::copy_from_slice(
                &write_object(out_private).map_err(DeviceError::TpmProtocol)?,
            ),
        })
    }

    /// Parses and returns the public area of the key.
    ///
    /// # Errors
    ///
    /// Returns a `KeyError` if the public key bytes cannot be parsed.
    pub fn public(&self) -> Result<Tpm2bPublic, KeyError> {
        let (public, _) = Tpm2bPublic::parse(&self.pub_key).map_err(DeviceError::TpmProtocol)?;
        Ok(public)
    }

    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, KeyError> {
        Ok(pem::encode(&Pem::new("TSS2 PRIVATE KEY", self.to_der()?)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, KeyError> {
        rasn::der::encode(self).map_err(Into::into)
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the PEM bytes cannot be parsed.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, KeyError> {
        let pem = pem::parse(pem_bytes)?;
        if pem.tag() == "TSS2 PRIVATE KEY" {
            Self::from_der(pem.contents())
        } else {
            Err(KeyError::UnsupportedPemTag(pem.tag().to_string()))
        }
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the DER bytes cannot be parsed into a valid `TpmKeyAsn1` data.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, KeyError> {
        rasn::der::decode(der_bytes).map_err(Into::into)
    }
}
