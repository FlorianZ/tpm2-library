// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::no_effect_underscore_binding)]

use super::{Alg, ExternalKey, KeyError, Tpm2shAlgId};
use crate::{
    context::ContextError,
    convert::from_tpm_object_to_vec,
    crypto::{
        crypto_hmac, crypto_kdfa, crypto_make_name, derive_seed_with_ecc, protect_seed_with_rsa,
        KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
    },
    device::{Auth, Device, DeviceError},
    job::Job,
    template,
};

use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use pem::Pem;
use rand::{CryptoRng, RngCore};
use rasn::{
    prelude::ObjectIdentifier,
    types::{OctetString, Utf8String},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPrivate, Tpm2bPrivateKeyRsa, Tpm2bPublic,
        Tpm2bSensitive, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bSymKey, TpmCc,
        TpmlPcrSelection, TpmsSensitiveCreate, TpmtSensitive, TpmtSymDefObject,
        TpmuSensitiveComposite,
    },
    message::{TpmCreateCommand, TpmImportCommand},
    TpmBuild, TpmHandle, TpmParse, TpmWriter,
};
use tpm2_protocol::{
    data::{Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, TpmAlgId, TpmtPublic},
    tpm_hash_size,
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
        auth: &Auth,
        parent_handle: TpmHandle,
        template: &TpmKeyTemplate,
    ) -> Result<Self, KeyError> {
        let user_auth = match &auth {
            Auth::Password(p) => Tpm2bAuth::try_from(p.as_slice())?,
            Auth::Session(_) | Auth::Policy(_) => Tpm2bAuth::default(),
        };
        let auth_policy = match &auth {
            Auth::Policy(p) => Tpm2bAuth::try_from(p.as_slice())?,
            Auth::Session(_) | Auth::Password(_) => Tpm2bAuth::default(),
        };
        let alg = template.alg_desc.clone();
        let public_template = template::build_public(template.alg_desc, auth_policy, alg.into());

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
            .map_err(|e| match e {
                ContextError::Device(d) => KeyError::Device(d),
                ContextError::Session(s) => KeyError::Session(s),
                other => KeyError::ValueConversionFailed(other.to_string()),
            })?;

        let create_resp = resp
            .Create()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Create))?;

        Self::from_creation_data(
            user_auth.is_empty(),
            parent_handle,
            &create_resp.out_public,
            &create_resp.out_private,
            &auth_policy,
            template.key_type_oid.clone(),
        )
    }

    /// Creates a new `TpmKey` from the raw TPM creation response data.
    fn from_creation_data(
        empty_auth: bool,
        parent_handle: TpmHandle,
        out_public: &Tpm2bPublic,
        out_private: &Tpm2bPrivate,
        policy_digest: &Tpm2bDigest,
        key_type: ObjectIdentifier,
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
            parent: parent_handle.0,
            pub_key: OctetString::copy_from_slice(
                &from_tpm_object_to_vec(out_public).map_err(DeviceError::Tpm)?,
            ),
            priv_key: OctetString::copy_from_slice(
                &from_tpm_object_to_vec(out_private).map_err(DeviceError::Tpm)?,
            ),
        })
    }

    /// Imports an external key under a TPM parent, creating a new `TpmKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TPM import operation fails.
    ///
    /// # Remarks on `symmetricAlg`
    ///
    /// In `TPM2_Import` the `symmetricAlg` parameter defines the cipher for the
    /// inner wrapper of the `duplicate` blob.
    ///
    /// The key import process differences for ECC and RSA parents:
    ///
    /// - **ECC**: the import uses ECDH with AES-CFB as the symmetric algorithm.
    /// - **RSA**: the import uses RSA-OAEP to encrypt a seed, which passed in
    ///   the `inSymSeed` command parameter, `encryptionKey` is zero-length
    ///   vector and `symmetricAlg` must be set to `TPM_ALG_NULL`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_external_key(
        device: &mut Device,
        job: &mut Job,
        parent_handle: TpmHandle,
        external_key: &ExternalKey,
        rng: &mut (impl RngCore + CryptoRng),
        handles: &[u32],
        auth_list: &[Auth],
    ) -> Result<Self, KeyError> {
        let (parent_public, parent_name) = match device.read_public(parent_handle) {
            Ok(result) => result,
            Err(DeviceError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(KeyError::Device(DeviceError::UnknownHandleName(
                    parent_handle.0,
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let parent_name_alg = parent_public.name_alg;

        let public = external_key.to_public(parent_name_alg)?;
        let object_name = crypto_make_name(&public)?;
        let sensitive_blob = external_key.sensitive_blob();

        let (duplicate, in_sym_seed, encryption_key) = create_import_blob(
            &parent_public,
            &public,
            &sensitive_blob,
            &parent_name,
            &object_name,
            rng,
        )?;

        let import_cmd = TpmImportCommand {
            parent_handle: parent_handle.0.into(),
            encryption_key,
            object_public: Tpm2bPublic {
                inner: public.clone(),
            },
            duplicate,
            in_sym_seed,
            symmetric_alg: TpmtSymDefObject::default(),
        };

        let (resp, _) = job
            .execute(device, &import_cmd, handles, auth_list)
            .map_err(|e| match e {
                ContextError::Device(d) => KeyError::Device(d),
                ContextError::Session(s) => KeyError::Session(s),
                other => KeyError::ValueConversionFailed(other.to_string()),
            })?;

        let import_resp = resp
            .Import()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Import))?;
        let out_private = import_resp.out_private;

        let tpm_key = Self::from_creation_data(
            true,
            parent_handle,
            &Tpm2bPublic { inner: public },
            &out_private,
            &Tpm2bDigest::default(),
            OID_IMPORTABLE_KEY,
        )?;

        Ok(tpm_key)
    }

    /// Parses and returns the public area of the key.
    ///
    /// # Errors
    ///
    /// Returns a `KeyError` if the public key bytes cannot be parsed.
    pub fn public(&self) -> Result<Tpm2bPublic, KeyError> {
        let (public, _) = Tpm2bPublic::parse(&self.pub_key).map_err(DeviceError::Tpm)?;
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

/// Create import blob. As per the TCG TPM 2.0 specification, the duplication
/// blob for import requires a zero IV for its symmetric encryption in CFB mode.
///
/// # Errors
///
/// Returns a `CryptoError` if any underlying cryptographic operations fail, if
/// the provided parent key type is unsupported for import, or if TPM data
/// structures cannot be serialized.
#[allow(clippy::too_many_arguments)]
fn create_import_blob(
    parent_public: &TpmtPublic,
    object_public: &TpmtPublic,
    private_bytes: &[u8],
    _parent_name: &Tpm2bName,
    object_name: &Tpm2bName,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), KeyError> {
    let parent_name_alg = parent_public.name_alg;
    let parent_key_type = parent_public.object_type;

    let (seed, in_sym_seed) = match parent_key_type {
        TpmAlgId::Rsa => {
            let seed_size = tpm_hash_size(&parent_name_alg).ok_or(
                KeyError::UnsupportedNameAlgorithm(Tpm2shAlgId(parent_name_alg)),
            )? as usize;
            let mut seed = vec![0u8; seed_size];
            rng.fill_bytes(&mut seed);
            let encrypted_seed = protect_seed_with_rsa(parent_public, &seed, rng)?;
            (seed, encrypted_seed)
        }
        TpmAlgId::Ecc => {
            let (derived_seed, ephemeral_point) = derive_seed_with_ecc(parent_public, rng)?;
            let point_bytes = from_tpm_object_to_vec(&ephemeral_point)?;
            let secret = Tpm2bEncryptedSecret::try_from(point_bytes.as_slice())?;
            (derived_seed, secret)
        }
        _ => {
            return Err(KeyError::UnsupportedKeyAlgorithm(Tpm2shAlgId(
                parent_key_type,
            )))
        }
    };

    let sym_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_STORAGE,
        object_name.as_ref(),
        &[],
        128,
    )?;

    let key_bits = tpm_hash_size(&parent_name_alg).ok_or(KeyError::UnsupportedNameAlgorithm(
        Tpm2shAlgId(parent_name_alg),
    ))? * 8;
    let key_bits =
        u16::try_from(key_bits).map_err(|_| KeyError::InvalidKeyBits(key_bits.to_string()))?;

    let hmac_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_INTEGRITY,
        &[],
        &[],
        key_bits,
    )?;

    let object_key_type = object_public.object_type;
    let sensitive_composite = match object_key_type {
        TpmAlgId::Rsa => TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::try_from(private_bytes)?),
        TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::try_from(private_bytes)?),
        TpmAlgId::KeyedHash => {
            TpmuSensitiveComposite::Bits(Tpm2bSensitiveData::try_from(private_bytes)?)
        }
        TpmAlgId::SymCipher => TpmuSensitiveComposite::Sym(Tpm2bSymKey::try_from(private_bytes)?),
        _ => {
            return Err(KeyError::UnsupportedKeyAlgorithm(Tpm2shAlgId(
                object_key_type,
            )))
        }
    };
    let sensitive = TpmtSensitive {
        sensitive_type: object_key_type,
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: sensitive_composite,
    };
    let sensitive_tpm2b = Tpm2bSensitive::from(sensitive);
    let mut enc_data = from_tpm_object_to_vec(&sensitive_tpm2b)?;

    let iv = [0u8; 16];
    let cipher = Encryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    cipher.encrypt(&mut enc_data);

    let final_mac = crypto_hmac(
        parent_name_alg,
        &hmac_key,
        &[&enc_data, object_name.as_ref()],
    )?;

    let duplicate_blob = {
        let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
            Tpm2bDigest::try_from(final_mac.as_slice())?.build(&mut writer)?;
            writer.write_bytes(&enc_data)?;
            writer.len()
        };
        duplicate_blob_buf[..len].to_vec()
    };

    Ok((
        Tpm2bPrivate::try_from(duplicate_blob.as_slice())?,
        in_sym_seed,
        Tpm2bData::default(),
    ))
}
