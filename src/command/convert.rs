// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{CommandError, InputArgs, OutputArgs, OutputEncodingArgs, ParenBindArgs},
    crypto::{
        crypto_hash_size, crypto_hmac, crypto_kdfa, crypto_make_name, derive_seed_with_ecc,
        protect_seed_with_rsa, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
    },
    device::{with_device, Device, DeviceError},
    handle::HandleClass,
    io::{read_file_input, write_key_data},
    job::Job,
    key::{AnyKey, ExternalKey, KeyError, Tpm2shAlgId, TpmKey, OID_IMPORTABLE_KEY},
    write_object,
};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use clap::Args;
use rand::{CryptoRng, RngCore};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData,
        Tpm2bSymKey, TpmAlgId, TpmCc, TpmtSensitive, TpmtSymDefObject, TpmuSensitiveComposite,
    },
    message::TpmImportCommand,
    TpmBuild, TpmHandle, TpmWriter,
};

/// Convert external keys to TPM keys.
#[derive(Args, Debug)]
pub struct Convert {
    #[clap(flatten)]
    pub parent_args: ParenBindArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,
}

impl Convert {
    fn create_external_key(
        job: &mut Job,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
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
            Err(DeviceError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(KeyError::InvalidParent(parent_handle.0).into());
            }
            Err(e) => return Err(e.into()),
        };
        let parent_name_alg = parent_public.name_alg;

        let public = external_key
            .to_public(parent_name_alg)
            .map_err(CommandError::Key)?;
        let object_name = crypto_make_name(&public).map_err(CommandError::Crypto)?;
        let sensitive_blob = external_key.sensitive_blob();

        let (duplicate, in_sym_seed, encryption_key) = create_import_blob(
            &parent_public,
            &public,
            &sensitive_blob,
            &object_name,
            &mut rng,
        )
        .map_err(CommandError::Key)?;

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
        let (resp, _) = job.execute(device, &import_cmd, &handles, job.auth_list)?;

        let import_resp = resp
            .Import()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Import))?;
        let out_private = import_resp.out_private;

        let parent_public_2b = Tpm2bPublic {
            inner: parent_public,
        };

        let policy_digest = Tpm2bDigest::default();
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
            policy: if policy_digest.is_empty() {
                None
            } else {
                return Err(CommandError::InvalidInput(
                    "Policy digest not supported for imported keys".to_string(),
                ));
            },
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

impl SubCommand for Convert {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let parent_handle = match self.parent_args.parent.class() {
                HandleClass::Tpm => Ok(TpmHandle(self.parent_args.parent.value())),
                HandleClass::Vtpm => job.load_context(device, &self.parent_args.parent),
            }?;

            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            let tpm_key = Convert::create_external_key(job, device, parent_handle, &input_bytes)?;

            write_key_data(
                &mut job.writer,
                &tpm_key,
                self.output_args.output.as_deref(),
                self.output_encoding_args.output_encoding,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn create_import_blob(
    parent_public: &tpm2_protocol::data::TpmtPublic,
    object_public: &tpm2_protocol::data::TpmtPublic,
    private_bytes: &[u8],
    object_name: &Tpm2bName,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), KeyError> {
    let parent_name_alg = parent_public.name_alg;
    let parent_key_type = parent_public.object_type;

    let (seed, in_sym_seed) = match parent_key_type {
        TpmAlgId::Rsa => {
            let seed_size = crypto_hash_size(parent_name_alg).ok_or(
                KeyError::UnsupportedNameAlgorithm(Tpm2shAlgId(parent_name_alg)),
            )? as usize;
            let mut seed = vec![0u8; seed_size];
            rng.fill_bytes(&mut seed);
            let encrypted_seed = protect_seed_with_rsa(parent_public, &seed, rng)?;
            (seed, encrypted_seed)
        }
        TpmAlgId::Ecc => {
            let (derived_seed, ephemeral_point) = derive_seed_with_ecc(parent_public, rng)?;
            let point_bytes = write_object(&ephemeral_point)?;
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

    let key_bits = crypto_hash_size(parent_name_alg).ok_or(KeyError::UnsupportedNameAlgorithm(
        Tpm2shAlgId(parent_name_alg),
    ))? * 8;
    let key_bits =
        u16::try_from(key_bits).map_err(|_| KeyError::InvalidRsaKeyBits(key_bits.to_string()))?;

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
    let mut enc_data = write_object(&sensitive_tpm2b)?;

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
