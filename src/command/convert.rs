// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError, InputArgs, OutputArgs, OutputEncodingArgs},
    device::{with_device, Device, DeviceError},
    io::{read_file_input, write_key_data},
    key::{AnyKey, ExternalKey, TpmKey, OID_IMPORTABLE_KEY},
    session::Session,
    write_object,
};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use clap::Args;
use num_traits::FromPrimitive;
use rand::{CryptoRng, RngCore};
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use tpm2_crypto::{
    ecdh as crypto_ecdh, hash_size as crypto_hash_size, hmac as crypto_hmac, kdfa as crypto_kdfa,
    make_name as crypto_make_name, CryptoError, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
};
use tpm2_policy_language::{Handle, HandleClass};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData,
        Tpm2bSymKey, TpmAlgId, TpmCc, TpmRcBase, TpmsEccPoint, TpmtPublic, TpmtSensitive,
        TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSensitiveComposite,
    },
    frame::TpmImportCommand,
    TpmHandle, TpmMarshal, TpmWriter,
};

/// Convert external keys to TPM keys.
#[derive(Args, Debug)]
pub struct Convert {
    /// Parent handle: 'tpm:<handle>' or 'vtpm:<handle>'
    pub parent: Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,
}

impl Job for Convert {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        self.parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(job.device.clone(), |device| {
            let parent_handle = match self.parent.class() {
                HandleClass::Tpm => self
                    .parent
                    .value()
                    .map(TpmHandle)
                    .ok_or(CommandError::InvalidHandle),
                HandleClass::Vtpm => job.load_context(device, &self.parent).map_err(Into::into),
            }?;

            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            if input_bytes.is_empty() {
                return Ok(());
            }
            let tpm_key = Self::create_external_key(
                job,
                device,
                parent_handle,
                &input_bytes,
                &self.auth_args,
            )?;

            write_key_data(
                &mut job.writer,
                &tpm_key,
                self.output_args.output.as_deref(),
                self.output_encoding_args.output_encoding,
            )
        })
    }
}

impl Convert {
    /// Encrypts a seed using the parent's RSA public key for duplication.
    fn create_import_seed_rsa(
        parent_public: &TpmtPublic,
        seed: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Tpm2bEncryptedSecret, CommandError> {
        let n = match &parent_public.unique {
            TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
            _ => Err(CommandError::InvalidInput(
                "Parent key is not an RSA key".to_string(),
            )),
        }?;
        let e_raw = match &parent_public.parameters {
            TpmuPublicParms::Rsa(params) => Ok(params.exponent),
            _ => Err(CommandError::InvalidInput(
                "Parent key is not an RSA key".to_string(),
            )),
        }?;
        let e = if e_raw == 0 { 65537 } else { e_raw };
        let rsa_pub_key = RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(n),
            rsa::BigUint::from_u32(e).ok_or(CommandError::InvalidInput(
                "Invalid RSA exponent".to_string(),
            ))?,
        )
        .map_err(|_| CommandError::InvalidInput("Invalid RSA parameters".to_string()))?;

        let label = "DUPLICATE\0";

        let result = match parent_public.name_alg {
            TpmAlgId::Sha1 => {
                rsa_pub_key.encrypt(rng, Oaep::new_with_label::<Sha1, _>(label), seed)
            }
            TpmAlgId::Sha256 => {
                rsa_pub_key.encrypt(rng, Oaep::new_with_label::<Sha256, _>(label), seed)
            }
            TpmAlgId::Sha384 => {
                rsa_pub_key.encrypt(rng, Oaep::new_with_label::<Sha384, _>(label), seed)
            }
            TpmAlgId::Sha512 => {
                rsa_pub_key.encrypt(rng, Oaep::new_with_label::<Sha512, _>(label), seed)
            }
            _ => {
                return Err(CommandError::InvalidInput(format!(
                    "Unsupported hash algorithm for RSA OAEP: {}",
                    parent_public.name_alg
                )))
            }
        };
        let encrypted_seed = result
            .map_err(|e| CommandError::InvalidInput(format!("RSA-OAEP encryption failed: {e}")))?;

        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice()).map_err(CommandError::TpmProtocol)
    }

    /// Derives a `seed` and an ephemeral public key using ECDH with the parent's ECC public key.
    fn create_import_seed_ecc(
        parent_public: &TpmtPublic,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, TpmsEccPoint), CommandError> {
        let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
            (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => {
                Ok((point, params.curve_id))
            }
            _ => Err(CommandError::InvalidInput(
                "Parent key is not an ECC key".to_string(),
            )),
        }?;

        crypto_ecdh(curve_id, parent_point, parent_public.name_alg, rng).map_err(|e| {
            if let CryptoError::UnsupportedEccCurve = e {
                CommandError::InvalidInput(format!(
                    "Unsupported ECC curve specified by parent key: {curve_id:?}"
                ))
            } else {
                CommandError::Crypto(e)
            }
        })
    }

    /// Generates the appropriate seed and encrypted seed based on parent key type.
    fn create_import_seed(
        parent_public: &TpmtPublic,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<u8>, Tpm2bEncryptedSecret), CommandError> {
        let parent_key_type = parent_public.object_type;
        match parent_key_type {
            TpmAlgId::Rsa => {
                let parent_name_alg = parent_public.name_alg;
                let seed_size = crypto_hash_size(parent_name_alg)?;
                let mut seed = vec![0u8; seed_size];
                rng.fill_bytes(&mut seed);
                let encrypted_seed = Self::create_import_seed_rsa(parent_public, &seed, rng)?;
                Ok((seed, encrypted_seed))
            }
            TpmAlgId::Ecc => {
                let (derived_seed, ephemeral_point) =
                    Self::create_import_seed_ecc(parent_public, rng)?;
                let point_bytes =
                    write_object(&ephemeral_point).map_err(CommandError::TpmProtocol)?;
                let secret = Tpm2bEncryptedSecret::try_from(point_bytes.as_slice())
                    .map_err(CommandError::TpmProtocol)?;
                Ok((derived_seed, secret))
            }
            _ => Err(CommandError::InvalidInput(format!(
                "Unsupported parent key type for import: {parent_key_type}"
            ))),
        }
    }

    /// Derives symmetric and HMAC keys using KDFa.
    fn create_import_keys(
        parent_name_alg: TpmAlgId,
        seed: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<(Vec<u8>, Vec<u8>), CommandError> {
        let sym_key = crypto_kdfa(
            parent_name_alg,
            seed,
            KDF_LABEL_STORAGE,
            object_name.as_ref(),
            &[],
            128,
        )
        .map_err(CommandError::Crypto)?;

        let key_bits = crypto_hash_size(parent_name_alg)? * 8;
        let key_bits = u16::try_from(key_bits)?;

        let hmac_key = crypto_kdfa(
            parent_name_alg,
            seed,
            KDF_LABEL_INTEGRITY,
            &[],
            &[],
            key_bits,
        )
        .map_err(CommandError::Crypto)?;

        Ok((sym_key, hmac_key))
    }

    /// Encrypts the sensitive portion of the key.
    fn encrypt_sensitive_data(
        object_public: &TpmtPublic,
        private_bytes: &[u8],
        sym_key: &[u8],
    ) -> Result<Vec<u8>, CommandError> {
        let object_key_type = object_public.object_type;
        let sensitive_composite = match object_key_type {
            TpmAlgId::Rsa => TpmuSensitiveComposite::Rsa(
                Tpm2bPrivateKeyRsa::try_from(private_bytes).map_err(CommandError::TpmProtocol)?,
            ),
            TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::try_from(private_bytes).map_err(CommandError::TpmProtocol)?,
            ),
            TpmAlgId::KeyedHash => TpmuSensitiveComposite::Bits(
                Tpm2bSensitiveData::try_from(private_bytes).map_err(CommandError::TpmProtocol)?,
            ),
            TpmAlgId::SymCipher => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::try_from(private_bytes).map_err(CommandError::TpmProtocol)?,
            ),
            _ => {
                return Err(CommandError::InvalidInput(format!(
                    "Unsupported object type for import: {object_key_type}"
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
        let mut enc_data = write_object(&sensitive_tpm2b).map_err(CommandError::TpmProtocol)?;

        let iv = [0u8; 16];
        let cipher = Encryptor::<Aes128>::new(sym_key.into(), &iv.into());
        cipher.encrypt(&mut enc_data);

        Ok(enc_data)
    }

    /// Calculates the outer HMAC and assembles the final private blob.
    fn create_private_blob(
        parent_name_alg: TpmAlgId,
        hmac_key: &[u8],
        encrypted_sensitive_data: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<Tpm2bPrivate, CommandError> {
        let final_mac = crypto_hmac(
            parent_name_alg,
            hmac_key,
            &[encrypted_sensitive_data, object_name.as_ref()],
        )
        .map_err(CommandError::Crypto)?;

        let duplicate_blob = {
            let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE as usize];
            let len = {
                let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
                Tpm2bDigest::try_from(final_mac.as_slice())
                    .map_err(CommandError::TpmProtocol)?
                    .marshal(&mut writer)?;
                writer.write_bytes(encrypted_sensitive_data)?;
                writer.len()
            };
            duplicate_blob_buf[..len].to_vec()
        };

        Tpm2bPrivate::try_from(duplicate_blob.as_slice()).map_err(CommandError::TpmProtocol)
    }

    /// Creates the import blob components (`duplicate`, `in_sym_seed`, `encryption_key`).
    fn create_import_blob_internal(
        parent_public: &tpm2_protocol::data::TpmtPublic,
        object_public: &tpm2_protocol::data::TpmtPublic,
        private_bytes: &[u8],
        object_name: &Tpm2bName,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), CommandError> {
        let parent_name_alg = parent_public.name_alg;

        let (seed, in_sym_seed) = Self::create_import_seed(parent_public, rng)?;

        let (sym_key, hmac_key) = Self::create_import_keys(parent_name_alg, &seed, object_name)?;

        let encrypted_sensitive_data =
            Self::encrypt_sensitive_data(object_public, private_bytes, &sym_key)?;

        let duplicate = Self::create_private_blob(
            parent_name_alg,
            &hmac_key,
            &encrypted_sensitive_data,
            object_name,
        )?;

        Ok((duplicate, in_sym_seed, Tpm2bData::default()))
    }

    fn create_external_key(
        job: &mut Session,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auth_args: &AuthArgs,
    ) -> Result<TpmKey, CommandError> {
        let external_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(_) => {
                return Err(CommandError::InvalidFormat);
            }
            AnyKey::External(key) => key,
        };
        let mut rng = rand::thread_rng();

        let (parent_public, _) = match device.read_public(parent_handle) {
            Ok(result) => result,
            Err(DeviceError::TpmRc(rc)) => {
                let base = rc.base();
                if base == TpmRcBase::Handle
                    || base == TpmRcBase::ReferenceH0
                    || base == TpmRcBase::Type
                {
                    return Err(CommandError::InvalidParent("tpm:", parent_handle.0));
                }
                return Err(DeviceError::TpmRc(rc).into());
            }
            Err(e) => return Err(e.into()),
        };

        let public = external_key
            .to_public(parent_public.name_alg)
            .map_err(CommandError::Key)?;
        let object_name = crypto_make_name(&public).map_err(CommandError::Crypto)?;
        let sensitive_blob = external_key.sensitive_blob();

        let (duplicate, in_sym_seed, encryption_key) = Self::create_import_blob_internal(
            &parent_public,
            &public,
            &sensitive_blob,
            &object_name,
            &mut rng,
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

        let handles = [parent_handle.0];
        let (resp, _) = job.execute(device, &import_cmd, &handles, &auth_args.auths())?;

        let import_resp = resp
            .Import()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Import))?;
        let out_private = import_resp.out_private;

        let parent_public_2b = Tpm2bPublic {
            inner: parent_public,
        };

        let key_type = match external_key.as_ref() {
            ExternalKey::Rsa2048(_)
            | ExternalKey::Rsa3072(_)
            | ExternalKey::Rsa4096(_)
            | ExternalKey::EccP256(_)
            | ExternalKey::EccP384(_)
            | ExternalKey::EccP521(_) => OID_IMPORTABLE_KEY,
        };

        let tpm_key = TpmKey {
            key_type,
            empty_auth: Some(true),
            policy: None,
            secret: None,
            auth_policy: None,
            description: None,
            rsa_parent: Some(parent_public_2b.inner.object_type == TpmAlgId::Rsa),
            parent_pub_key: Some(rasn::types::OctetString::copy_from_slice(&write_object(
                &parent_public_2b,
            )?)),
            parent: parent_handle.0,
            pub_key: rasn::types::OctetString::copy_from_slice(&write_object(&Tpm2bPublic {
                inner: public,
            })?),
            priv_key: rasn::types::OctetString::copy_from_slice(&write_object(&out_private)?),
        };

        Ok(tpm_key)
    }
}
