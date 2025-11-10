//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError, InputArgs, OutputArgs, OutputEncodingArgs},
    device::{with_device, Device, DeviceError},
    io::{read_file_input, write_key_data},
    key::{ecc_to_public_id, rsa_to_public_id, KeyError},
    session::Session,
    write_object,
};
use clap::Args;
use openssl::{
    bn::BigNum,
    md::{Md, MdRef},
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    rsa::{Padding, Rsa},
    symm::{encrypt, Cipher},
};
use rand;
use tpm2_crypto::{
    make_name as crypto_make_name, EccCurve, Error as CryptoError, Hash, KDF_LABEL_INTEGRITY,
    KDF_LABEL_STORAGE,
};
use tpm2_policy_language::{Handle, HandleClass};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId,
        TpmCc, TpmRcBase, TpmsEccPoint, TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuPublicId,
        TpmuPublicParms, TpmuSensitiveComposite,
    },
    frame::TpmImportCommand,
    TpmHandle, TpmMarshal, TpmProtocolError, TpmWriter,
};
use tpm2_tpmkey::TpmKey;

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
    fn tpm_alg_to_openssl_md(alg: TpmAlgId) -> Result<&'static MdRef, CommandError> {
        match alg {
            TpmAlgId::Sha1 => Ok(Md::sha1()),
            TpmAlgId::Sha256 => Ok(Md::sha256()),
            TpmAlgId::Sha384 => Ok(Md::sha384()),
            TpmAlgId::Sha512 => Ok(Md::sha512()),
            _ => Err(CommandError::InvalidInput(format!(
                "Unsupported hash algorithm for RSA OAEP: {alg}",
            ))),
        }
    }

    /// Encrypts a seed using the parent's RSA public key for duplication.
    fn create_import_seed_rsa(
        parent_public: &TpmtPublic,
        seed: &[u8],
    ) -> Result<Tpm2bEncryptedSecret, CommandError> {
        let n_bytes = match &parent_public.unique {
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

        let e_val = if e_raw == 0 { 65537 } else { e_raw };
        let n = BigNum::from_slice(n_bytes)?;
        let e = BigNum::from_u32(e_val)?;
        let rsa = Rsa::from_public_components(n, e)?;
        let pkey = PKey::from_rsa(rsa)?;

        let oaep_md = Self::tpm_alg_to_openssl_md(parent_public.name_alg)?;

        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.encrypt_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        ctx.set_rsa_oaep_md(oaep_md)?;
        ctx.set_rsa_mgf1_md(oaep_md)?;
        ctx.set_rsa_oaep_label("DUPLICATE\\0".as_bytes())?;

        let mut encrypted_seed = vec![0; pkey.size()];
        let len = ctx.encrypt(seed, Some(encrypted_seed.as_mut_slice()))?;
        encrypted_seed.truncate(len);

        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())
            .map_err(|_| CommandError::CapacityExceeded)
    }

    /// Derives a `seed` and an ephemeral public key using ECDH with the parent's ECC public key.
    fn create_import_seed_ecc(
        parent_public: &TpmtPublic,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(Vec<u8>, TpmsEccPoint), CommandError> {
        let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
            (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => {
                Ok((point, params.curve_id))
            }
            _ => Err(CommandError::InvalidInput(
                "Parent key is not an ECC key".to_string(),
            )),
        }?;

        EccCurve::from(curve_id)
            .ecdh(parent_point, Hash::from(parent_public.name_alg), rng)
            .map_err(|e| {
                if let CryptoError::InvalidEccCurve(_) = e {
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
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(Vec<u8>, Tpm2bEncryptedSecret), CommandError> {
        let parent_key_type = parent_public.object_type;
        match parent_key_type {
            TpmAlgId::Rsa => {
                let parent_name_alg = parent_public.name_alg;
                let seed_size = Hash::from(parent_name_alg).size()?;
                let mut seed = vec![0u8; seed_size];
                rand_bytes(&mut seed)?;
                let encrypted_seed = Self::create_import_seed_rsa(parent_public, &seed)?;
                Ok((seed, encrypted_seed))
            }
            TpmAlgId::Ecc => {
                let (derived_seed, ephemeral_point) =
                    Self::create_import_seed_ecc(parent_public, rng)?;
                let point_bytes = write_object(&ephemeral_point)?;
                let secret = Tpm2bEncryptedSecret::try_from(point_bytes.as_slice())
                    .map_err(|_| CommandError::CapacityExceeded)?;
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
        let sym_key = Hash::from(parent_name_alg)
            .kdfa(seed, KDF_LABEL_STORAGE, object_name.as_ref(), &[], 128)
            .map_err(CommandError::Crypto)?;

        let key_bits = Hash::from(parent_name_alg).size()? * 8;
        let key_bits = u16::try_from(key_bits)?;

        let hmac_key = Hash::from(parent_name_alg)
            .kdfa(seed, KDF_LABEL_INTEGRITY, &[], &[], key_bits)
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
                Tpm2bSensitiveData::try_from(private_bytes)
                    .map_err(|_| CommandError::CapacityExceeded)?,
            ),
            TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::try_from(private_bytes)
                    .map_err(|_| CommandError::CapacityExceeded)?,
            ),
            TpmAlgId::KeyedHash => TpmuSensitiveComposite::Bits(
                Tpm2bSensitiveData::try_from(private_bytes)
                    .map_err(|_| CommandError::CapacityExceeded)?,
            ),
            TpmAlgId::SymCipher => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::try_from(private_bytes).map_err(|_| CommandError::CapacityExceeded)?,
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
        let enc_data_in = write_object(&sensitive_tpm2b)?;
        let iv = [0u8; 16];

        let enc_data = encrypt(Cipher::aes_128_cfb128(), sym_key, Some(&iv), &enc_data_in)?;

        Ok(enc_data)
    }

    /// Calculates the outer HMAC and assembles the final private blob.
    fn create_private_blob(
        parent_name_alg: TpmAlgId,
        hmac_key: &[u8],
        encrypted_sensitive_data: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<Tpm2bPrivate, CommandError> {
        let final_mac = Hash::from(parent_name_alg)
            .hmac(hmac_key, &[encrypted_sensitive_data, object_name.as_ref()])
            .map_err(CommandError::Crypto)?;

        let duplicate_blob = {
            let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE as usize];
            let len = {
                let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
                Tpm2bDigest::try_from(final_mac.as_slice())
                    .map_err(|_| CommandError::CapacityExceeded)?
                    .marshal(&mut writer)
                    .map_err(|e: TpmProtocolError| e)?;
                writer.write_bytes(encrypted_sensitive_data)?;
                writer.len()
            };
            duplicate_blob_buf[..len].to_vec()
        };

        Tpm2bPrivate::try_from(duplicate_blob.as_slice())
            .map_err(|_| CommandError::CapacityExceeded)
    }

    /// Creates the import blob components (`duplicate`, `in_sym_seed`, `encryption_key`).
    fn create_import_blob_internal(
        parent_public: &tpm2_protocol::data::TpmtPublic,
        object_public: &tpm2_protocol::data::TpmtPublic,
        private_bytes: &[u8],
        object_name: &Tpm2bName,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
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

    fn build_tpm_public_from_openssl(
        pkey: &PKey<Private>,
        hash_alg: TpmAlgId,
    ) -> Result<TpmtPublic, KeyError> {
        let symmetric = TpmtSymDefObject::default();

        if pkey.rsa().is_ok() {
            rsa_to_public_id(pkey, hash_alg, symmetric)
        } else if pkey.ec_key().is_ok() {
            ecc_to_public_id(pkey, hash_alg, symmetric)
        } else {
            Err(KeyError::InvalidFormat)
        }
    }

    fn get_sensitive_blob_from_openssl_pkey(pkey: &PKey<Private>) -> Result<Vec<u8>, KeyError> {
        if let Ok(rsa) = pkey.rsa() {
            let p = rsa.p().ok_or(KeyError::InvalidFormat)?.to_vec();
            Ok(p)
        } else if let Ok(ec_key) = pkey.ec_key() {
            let d = ec_key.private_key().to_vec();
            Ok(d)
        } else {
            Err(KeyError::InvalidFormat)
        }
    }

    fn create_external_key(
        job: &mut Session,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auth_args: &AuthArgs,
    ) -> Result<TpmKey, CommandError> {
        let der_bytes = if let Ok(pems) = pem::parse_many(input_bytes) {
            pems.into_iter()
                .find(|p| {
                    matches!(
                        p.tag(),
                        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
                    )
                })
                .map(|p| p.contents().to_vec())
                .ok_or(CommandError::InvalidFormat)?
        } else {
            input_bytes.to_vec()
        };

        let pkey = PKey::private_key_from_der(&der_bytes).map_err(KeyError::from)?;
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

        let public = Self::build_tpm_public_from_openssl(&pkey, parent_public.name_alg)?;
        let object_name = crypto_make_name(&public).map_err(CommandError::Crypto)?;
        let sensitive_blob = Self::get_sensitive_blob_from_openssl_pkey(&pkey)?;

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

        let tpm_key = TpmKey {
            public: Tpm2bPublic {
                inner: public.clone(),
            },
            private: out_private,
            parent_handle,
            parent_public: Some(parent_public_2b),
            key_type: public.object_type,
            empty_auth: Some(true),
            policy: None,
        };

        Ok(tpm_key)
    }
}
