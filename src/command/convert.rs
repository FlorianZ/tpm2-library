//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs, OutputArgs, OutputEncodingArgs},
    io::{read_file_input, write_key_data, write_object},
    task::{TaskAuth, TaskState},
};
use clap::Args;
use openssl::symm::{encrypt, Cipher};
use rand;
use tpm2_crypto::{
    tpm_make_name, TpmCryptoError, TpmEccPublicKey, TpmHash, TpmPublicKey, TpmRsaPublicKey,
    KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
};
use tpm2_device::{with_device, TpmDevice};
use tpm2_policy_language::TpmHandleRef;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId,
        TpmCc, TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuSensitiveComposite,
    },
    frame::TpmImportCommand,
    TpmHandle, TpmMarshal, TpmProtocolError, TpmWriter,
};
use tpm2_tpmkey::TpmKey;

/// Convert external keys to TPM keys.
#[derive(Args, Debug)]
pub struct Convert {
    /// Parent handle: 'tpm:<handle>' or 'vtpm:<handle>'
    pub parent: TpmHandleRef,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,
}

impl Task for Convert {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        self.parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(task_state.device.clone(), |device| {
            let parent_handle = task_state.load_context(device, &self.parent)?;

            let (policy_blob, name_alg, parent_empty_auth) =
                task_state.resolve_policy(device, &self.parent, parent_handle)?;

            let (auths, policy_session_auth) = task_state.build_auth(
                device,
                &policy_blob,
                name_alg,
                parent_empty_auth,
                &self.auth_args,
            )?;

            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            if input_bytes.is_empty() {
                return Ok(());
            }

            let tpm_key_result =
                Self::create_external_key(task_state, device, parent_handle, &input_bytes, &auths);

            if let Some(TaskAuth::Session(vhandle)) = policy_session_auth {
                if let Err(e) = task_state.remove_session(device, vhandle) {
                    log::error!("vtpm:{vhandle:08x}: {e}");
                }
            }

            let tpm_key = tpm_key_result?;

            write_key_data(
                writer,
                &tpm_key,
                self.output_args.output.as_deref(),
                self.output_encoding_args.output_encoding,
            )
        })
    }
}

impl Convert {
    fn create_import_keys(
        parent_name_alg: TpmAlgId,
        seed: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<(Vec<u8>, Vec<u8>), CommandError> {
        let sym_key = TpmHash::from(parent_name_alg)
            .kdfa(seed, KDF_LABEL_STORAGE, object_name.as_ref(), &[], 128)
            .map_err(CommandError::Crypto)?;

        let key_bits = TpmHash::from(parent_name_alg).size() * 8;
        let key_bits = u16::try_from(key_bits)?;

        let hmac_key = TpmHash::from(parent_name_alg)
            .kdfa(seed, KDF_LABEL_INTEGRITY, &[], &[], key_bits)
            .map_err(CommandError::Crypto)?;

        Ok((sym_key, hmac_key))
    }

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

    fn create_private_blob(
        parent_name_alg: TpmAlgId,
        hmac_key: &[u8],
        sensitive: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<Tpm2bPrivate, CommandError> {
        let final_mac = TpmHash::from(parent_name_alg)
            .hmac(hmac_key, &[sensitive, object_name.as_ref()])
            .map_err(CommandError::Crypto)?;

        let duplicate_blob = {
            let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE as usize];
            let len = {
                let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
                Tpm2bDigest::try_from(final_mac.as_slice())
                    .map_err(|_| CommandError::CapacityExceeded)?
                    .marshal(&mut writer)
                    .map_err(|e: TpmProtocolError| e)?;
                writer.write_bytes(sensitive)?;
                writer.len()
            };
            duplicate_blob_buf[..len].to_vec()
        };

        Tpm2bPrivate::try_from(duplicate_blob.as_slice())
            .map_err(|_| CommandError::CapacityExceeded)
    }

    fn create_import_blob(
        parent_public: &tpm2_protocol::data::TpmtPublic,
        object_public: &tpm2_protocol::data::TpmtPublic,
        private_bytes: &[u8],
        object_name: &Tpm2bName,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), CommandError> {
        let name_alg = parent_public.name_alg;
        let (seed, in_sym_seed) = match parent_public.object_type {
            TpmAlgId::Rsa => {
                let key = TpmRsaPublicKey::try_from(parent_public).map_err(CommandError::Crypto)?;
                key.to_seed(TpmHash::from(name_alg), rng)
                    .map_err(CommandError::Crypto)?
            }
            TpmAlgId::Ecc => {
                let key = TpmEccPublicKey::try_from(parent_public).map_err(CommandError::Crypto)?;
                key.to_seed(TpmHash::from(name_alg), rng)
                    .map_err(CommandError::Crypto)?
            }
            _ => return Err(CommandError::InvalidParentType),
        };
        let (sym_key, hmac_key) = Self::create_import_keys(name_alg, &seed, object_name)?;
        let sensitive = Self::encrypt_sensitive_data(object_public, private_bytes, &sym_key)?;
        let duplicate = Self::create_private_blob(name_alg, &hmac_key, &sensitive, object_name)?;
        Ok((duplicate, in_sym_seed, Tpm2bData::default()))
    }

    fn create_external_key(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[TaskAuth],
    ) -> Result<TpmKey, CommandError> {
        let der_bytes = pem::parse_many(input_bytes)
            .ok()
            .and_then(|pems| {
                pems.into_iter().find_map(|p| {
                    if matches!(
                        p.tag(),
                        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
                    ) {
                        Some(p.contents().to_vec())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| input_bytes.to_vec());

        let mut rng = rand::thread_rng();

        let (parent_public, _) = device
            .read_public(parent_handle)
            .map_err(CommandError::from)?;

        let (public, sensitive_blob) = {
            let symmetric = TpmtSymDefObject::default();
            let name_alg = parent_public.name_alg;

            match TpmRsaPublicKey::from_der(&der_bytes) {
                Ok((public_key, sensitive)) => {
                    let public = public_key.to_public(name_alg, symmetric);
                    Ok((public, sensitive))
                }
                Err(TpmCryptoError::InvalidRsaParameters) => TpmEccPublicKey::from_der(&der_bytes)
                    .map_err(CommandError::Crypto)
                    .map(|(public_key, sensitive)| {
                        let public = public_key.to_public(name_alg, symmetric);
                        (public, sensitive)
                    }),
                Err(e) => Err(CommandError::Crypto(e)),
            }
        }?;

        let object_name = tpm_make_name(&public).map_err(CommandError::Crypto)?;

        let (duplicate, in_sym_seed, encryption_key) = Self::create_import_blob(
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

        let (resp, _) = task_state.execute(device, &import_cmd, &handles, auths)?;

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
            empty_auth: None,
            policy: None,
            auth_policy: None,
            secret: None,
            description: None,
        };

        Ok(tpm_key)
    }
}
