// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{
        common::build_policy_command_list, AuthArgs, CommandError, CreationArgs, InputArgs,
        OutputArgs, OutputEncodingArgs,
    },
    io::{read_file_input, write_key_data, write_object},
    task::{Auth, TaskState},
};
use clap::Args;
use openssl::symm::{encrypt, Cipher};
use rand;
use tpm2_crypto::{
    tpm_make_name, TpmCryptoError, TpmEccExternalKey, TpmExternalKey, TpmHash, TpmPublicTemplate,
    TpmRsaExternalKey, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
};
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId,
        TpmaObject, TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuPublicParms,
        TpmuSensitiveComposite, TpmuSymKeyBits,
    },
    frame::{TpmAuthCommands, TpmCommand},
    TpmMarshal, TpmWriter,
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyPolicy, TpmKeyPolicyCommand};

/// Import external keys to TPM keys.
#[derive(Args, Debug)]
pub struct Import {
    /// Parent's TPM handle as an eight characters hex string.
    pub parent: crate::handle::Handle,

    /// Create a loadable key instead of an importable key.
    #[arg(long)]
    pub loadable: bool,

    /// Description
    #[arg(short = 'd', long)]
    pub description: Option<String>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Task for Import {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        let parent = self
            .parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(task_state.device.clone(), |device| {
            let (parent_handle, name_alg, auth) = task_state.resolve_auth(
                device,
                TpmUint32(parent),
                &self.auth_args.build_auth_map()?,
            )?;

            let input_bytes = read_file_input(self.input_args.input.as_deref())?;

            let user_auth = match &self.creation_args.password {
                Some(hex_str) => {
                    let auth = hex::decode(hex_str).map_err(|_| CommandError::InvalidPassword)?;
                    Tpm2bAuth::try_from(auth.as_slice()).map_err(CommandError::Unmarshal)?
                }
                None => Tpm2bAuth::default(),
            };

            let mut object_attributes = TpmaObject::DECRYPT;

            if self.creation_args.password.is_some()
                || self.creation_args.policy_expression.is_none()
            {
                object_attributes |= TpmaObject::USER_WITH_AUTH;
            }

            let (auth_policy, policy_commands) =
                build_policy_command_list(&self.creation_args, task_state, device, name_alg)?;

            if !auth_policy.is_empty() {
                object_attributes |= TpmaObject::ADMIN_WITH_POLICY;
            }

            let tpm_key_result = Self::create_external_key(
                self.loadable,
                self.description.as_deref(),
                task_state,
                device,
                parent_handle,
                &input_bytes,
                &[auth],
                user_auth,
                auth_policy,
                object_attributes,
                policy_commands,
            );

            let tpm_key = tpm_key_result?;

            write_key_data(
                writer,
                &tpm_key,
                self.output_args.output.as_deref(),
                self.output_encoding_args.encoding,
            )
        })
    }
}

impl Import {
    fn public_to_sym_key_bits(parent_public: &TpmtPublic) -> Result<u16, CommandError> {
        let sym_def = match &parent_public.parameters {
            TpmuPublicParms::Rsa(parms) => &parms.symmetric,
            TpmuPublicParms::Ecc(parms) => &parms.symmetric,
            _ => return Err(CommandError::InvalidParentType),
        };

        match sym_def.key_bits {
            TpmuSymKeyBits::Aes(bits)
            | TpmuSymKeyBits::Camellia(bits)
            | TpmuSymKeyBits::Sm4(bits) => Ok(bits.value()),
            _ => Err(CommandError::InvalidParentType),
        }
    }

    fn create_import_keys(
        parent_name_alg: TpmAlgId,
        seed: &[u8],
        object_name: &Tpm2bName,
        key_bits: u16,
    ) -> Result<(Vec<u8>, Vec<u8>), CommandError> {
        let sym_key = TpmHash::from(parent_name_alg)
            .kdfa(seed, KDF_LABEL_STORAGE, object_name.as_ref(), &[], key_bits)
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
        auth_value: Tpm2bAuth,
        key_bits: u16,
    ) -> Result<Vec<u8>, CommandError> {
        let object_key_type = object_public.object_type;

        let sensitive_composite = match object_key_type {
            TpmAlgId::Rsa => TpmuSensitiveComposite::Rsa(
                Tpm2bSensitiveData::try_from(private_bytes).map_err(CommandError::Unmarshal)?,
            ),
            TpmAlgId::Ecc => TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::try_from(private_bytes).map_err(CommandError::Unmarshal)?,
            ),
            TpmAlgId::KeyedHash => TpmuSensitiveComposite::Bits(
                Tpm2bSensitiveData::try_from(private_bytes).map_err(CommandError::Unmarshal)?,
            ),
            TpmAlgId::SymCipher => TpmuSensitiveComposite::Sym(
                Tpm2bSymKey::try_from(private_bytes).map_err(CommandError::Unmarshal)?,
            ),
            _ => return Err(CommandError::UnsupportedKeyAlgorithm),
        };

        let sensitive = TpmtSensitive {
            sensitive_type: object_key_type,
            auth_value,
            seed_value: Tpm2bDigest::default(),
            sensitive: sensitive_composite,
        };
        let sensitive_tpm2b = Tpm2bSensitive::from(sensitive);
        let enc_data_in = write_object(&sensitive_tpm2b).map_err(CommandError::Marshal)?;
        let iv = [0u8; 16];

        let cipher = match key_bits {
            128 => Cipher::aes_128_cfb128(),
            256 => Cipher::aes_256_cfb128(),
            _ => return Err(CommandError::InvalidParentType),
        };

        let enc_data = encrypt(cipher, sym_key, Some(&iv), &enc_data_in)
            .map_err(|_| CommandError::EncryptingDuplicateFailed)?;

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
            let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
                Tpm2bDigest::try_from(final_mac.as_slice())
                    .map_err(CommandError::Unmarshal)?
                    .marshal(&mut writer)
                    .map_err(CommandError::Marshal)?;
                writer
                    .write_bytes(sensitive)
                    .map_err(CommandError::Marshal)?;
                writer.len()
            };
            duplicate_blob_buf[..len].to_vec()
        };

        Tpm2bPrivate::try_from(duplicate_blob.as_slice()).map_err(CommandError::Unmarshal)
    }

    fn create_import_blob(
        parent_public: &tpm2_protocol::data::TpmtPublic,
        object_public: &tpm2_protocol::data::TpmtPublic,
        private_bytes: &[u8],
        object_name: &Tpm2bName,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        user_auth: Tpm2bAuth,
    ) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), CommandError> {
        let name_alg = parent_public.name_alg;
        let (seed, in_sym_seed) = match parent_public.object_type {
            TpmAlgId::Rsa => {
                let key =
                    TpmRsaExternalKey::try_from(parent_public).map_err(CommandError::Crypto)?;
                key.to_seed(TpmHash::from(name_alg), rng)
                    .map_err(CommandError::Crypto)?
            }
            TpmAlgId::Ecc => {
                let key =
                    TpmEccExternalKey::try_from(parent_public).map_err(CommandError::Crypto)?;
                key.to_seed(TpmHash::from(name_alg), rng)
                    .map_err(CommandError::Crypto)?
            }
            _ => return Err(CommandError::InvalidParentType),
        };

        let key_bits = Self::public_to_sym_key_bits(parent_public)?;

        let (sym_key, hmac_key) = Self::create_import_keys(name_alg, &seed, object_name, key_bits)?;
        let sensitive = Self::encrypt_sensitive_data(
            object_public,
            private_bytes,
            &sym_key,
            user_auth,
            key_bits,
        )?;
        let duplicate = Self::create_private_blob(name_alg, &hmac_key, &sensitive, object_name)?;
        Ok((duplicate, in_sym_seed, Tpm2bData::default()))
    }

    /// Parses external key bytes (PEM or DER) into a TPM public structure and
    /// private data.
    ///
    /// This attempts to interpret the input as RSA first, falling back to ECC
    /// if RSA parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`Crypto`](crate::command::CommandError::Crypto) if the input
    /// cannot be parsed as either RSA or ECC.
    fn parse_external_key(
        input_bytes: &[u8],
        name_alg: TpmAlgId,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
    ) -> Result<(TpmtPublic, Vec<u8>), CommandError> {
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

        let symmetric = TpmtSymDefObject::default();
        let template = TpmPublicTemplate::new()
            .with_name_alg(name_alg)
            .with_object_attributes(object_attributes)
            .with_symmetric(symmetric);

        match TpmRsaExternalKey::from_der(&der_bytes) {
            Ok((public_key, sensitive)) => {
                let mut public = public_key.to_public(&template);
                public.auth_policy = auth_policy;
                Ok((public, sensitive))
            }
            Err(TpmCryptoError::InvalidRsaParameters) => {
                let (public_key, sensitive) =
                    TpmEccExternalKey::from_der(&der_bytes).map_err(CommandError::Crypto)?;
                let mut public = public_key.to_public(&template);
                public.auth_policy = auth_policy;
                Ok((public, sensitive))
            }
            Err(e) => Err(CommandError::Crypto(e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_external_key(
        loadable: bool,
        name: Option<&str>,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
        user_auth: Tpm2bAuth,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
        policy_commands: Option<Vec<(TpmCommand, TpmAuthCommands)>>,
    ) -> Result<TpmKeyFile, CommandError> {
        let (parent_public, _) = device
            .read_public(parent_handle)
            .map_err(CommandError::from)?;

        let (public, sensitive_blob) = Self::parse_external_key(
            input_bytes,
            parent_public.name_alg,
            auth_policy,
            object_attributes,
        )?;

        let mut rng = rand::thread_rng();
        let object_name = tpm_make_name(&public).map_err(CommandError::Crypto)?;

        let (duplicate, in_sym_seed, encryption_key) = Self::create_import_blob(
            &parent_public,
            &public,
            &sensitive_blob,
            &object_name,
            &mut rng,
            user_auth,
        )?;

        let tpm_public = Tpm2bPublic {
            inner: public.clone(),
        };
        let symmetric_alg = TpmtSymDefObject::default();

        let mut file = if loadable {
            let out_private = task_state
                .import_key(
                    device,
                    parent_handle,
                    &tpm_public,
                    &duplicate,
                    &in_sym_seed,
                    &encryption_key,
                    &symmetric_alg,
                    auths,
                )
                .map_err(CommandError::Task)?;

            task_state
                .save_key(
                    device,
                    tpm_public,
                    out_private,
                    parent_handle,
                    user_auth.is_empty(),
                    policy_commands,
                )
                .map_err(CommandError::from)?
        } else {
            let mut file = TpmKeyFile::new()
                .with_empty_auth(user_auth.is_empty())
                .with_public(tpm_public)
                .with_private(duplicate)
                .with_secret(in_sym_seed.as_ref().to_vec())
                .with_parent(parent_handle);

            if let Some(vtpm_policy) = task_state
                .save_policy(device, policy_commands)
                .map_err(CommandError::Task)?
            {
                let mut policy = Vec::with_capacity(vtpm_policy.len());
                for cmd in vtpm_policy {
                    policy.push(TpmKeyPolicyCommand::new(cmd.cc(), cmd.body()));
                }
                file = file.with_policy(TpmKeyPolicy::new(None, policy));
            }

            file
        };

        if let Some(n) = name {
            file = file.with_description(n.to_string());
        }

        Ok(file)
    }
}
