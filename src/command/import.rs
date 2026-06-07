// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, parse_password},
        CommandError,
    },
    io::{read_file_input, write_key_data, write_object},
    task::{Auth, TaskState},
};
use argh::FromArgs;
use openssl::symm::{encrypt, Cipher};
use rand;
use std::path::PathBuf;
use tpm2_crypto::{
    tpm_make_name, TpmEccExternalKey, TpmExternalKey, TpmHash, TpmPublicTemplate,
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
    frame::{TpmAuthCommands, TpmCommandValue as TpmCommand},
    TpmMarshal, TpmWriter,
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyType};

/// Import external keys to TPM keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "import", help_triggers("-h", "--help", "help"))]
pub struct Import {
    /// parent's TPM handle as an eight characters hex string
    #[argh(positional)]
    pub parent: crate::handle::Handle,

    /// create a loadable key instead of an importable key
    #[argh(switch)]
    pub loadable: bool,

    /// description
    #[argh(option, short = 'd')]
    pub description: Option<String>,

    /// input file path (defaults to stdin as PEM)
    #[argh(option, short = 'I')]
    pub input: Option<PathBuf>,

    /// output file path (defaults to stdout as PEM)
    #[argh(option, short = 'O')]
    pub output: Option<PathBuf>,

    /// authentication value: '<hex string>'
    #[argh(option)]
    pub password: Option<String>,

    /// policy expression: e.g., 'pcr(sha256:7)'
    #[argh(option, long = "policy")]
    pub policy_expression: Option<String>,

    /// enable dictionary attack protection
    #[argh(switch)]
    pub lock: bool,
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
            let (parent_handle, name_alg, auth) =
                task_state.resolve_auth(device, TpmUint32::new(parent))?;

            let input_bytes = read_file_input(self.input.as_deref())?;

            let user_auth = parse_password(self.password.as_deref())?;

            let mut object_attributes = TpmaObject::DECRYPT;

            if self.password.is_some() || self.policy_expression.is_none() {
                object_attributes |= TpmaObject::USER_WITH_AUTH;
            }

            let (auth_policy, policy_commands) = build_policy_command_list(
                self.policy_expression.as_deref(),
                task_state,
                device,
                name_alg,
            )?;

            if !auth_policy.is_empty() {
                object_attributes |= TpmaObject::ADMIN_WITH_POLICY;
            }

            let tpm_key_result = self.build_external_key(
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

            write_key_data(writer, &tpm_key, self.output.as_deref())
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
        let parent_hash = TpmHash::try_from(parent_name_alg)?;
        let sym_key = parent_hash
            .kdfa(
                seed,
                KDF_LABEL_STORAGE,
                object_name.as_ref(),
                &[],
                usize::from(key_bits),
            )
            .map_err(CommandError::Crypto)?;

        let key_bits = parent_hash.size() * 8;

        let hmac_key = parent_hash
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
        let final_mac = TpmHash::try_from(parent_name_alg)?
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

    fn build_import_blob(
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
                key.to_seed(TpmHash::try_from(name_alg)?, rng)
                    .map_err(CommandError::Crypto)?
            }
            TpmAlgId::Ecc => {
                let key =
                    TpmEccExternalKey::try_from(parent_public).map_err(CommandError::Crypto)?;
                key.to_seed(TpmHash::try_from(name_alg)?, rng)
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

    /// Parses external key bytes (PEM) into a TPM public structure and
    /// private data.
    ///
    /// This function attempts to interpret the input as RSA first, falling back to ECC
    /// if RSA parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidInput`] if the input is not a valid PEM
    /// containing a supported private key.
    /// Returns [`Crypto`](crate::command::CommandError::Crypto) if the input
    /// cannot be parsed as either RSA or ECC.
    fn parse_external_key(
        input_bytes: &[u8],
        name_alg: TpmAlgId,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
    ) -> Result<(TpmtPublic, Vec<u8>), CommandError> {
        let der_bytes = pem::parse_many(input_bytes)
            .map_err(|_| CommandError::InvalidInput("Input is not valid PEM".to_string()))?
            .into_iter()
            .find_map(|p| {
                if matches!(
                    p.tag(),
                    "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
                ) {
                    Some(p.contents().to_vec())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                CommandError::InvalidInput("No supported private key found in PEM".to_string())
            })?;

        let symmetric = TpmtSymDefObject::default();
        let template = TpmPublicTemplate::new()
            .with_name_alg(TpmHash::try_from(name_alg)?)
            .with_object_attributes(object_attributes)
            .with_symmetric(symmetric);

        if let Ok((public_key, sensitive)) = TpmRsaExternalKey::from_der(&der_bytes) {
            let mut public = public_key.to_public(&template);
            public.auth_policy = auth_policy;
            Ok((public, sensitive.to_vec()))
        } else {
            let (public_key, sensitive) =
                TpmEccExternalKey::from_der(&der_bytes).map_err(CommandError::Crypto)?;
            let mut public = public_key.to_public(&template);
            public.auth_policy = auth_policy;
            Ok((public, sensitive.to_vec()))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_key_file(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        public: Tpm2bPublic,
        duplicate: &Tpm2bPrivate,
        in_sym_seed: &Tpm2bEncryptedSecret,
        encryption_key: &Tpm2bData,
        auths: &[Auth],
        user_auth: Tpm2bAuth,
        policy_commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<TpmKeyFile, CommandError> {
        let symmetric_alg = TpmtSymDefObject::default();
        let policy = task_state.save_key_policy(device, policy_commands)?;

        let mut file = if self.loadable {
            let out_private = task_state.import_key(
                device,
                parent_handle,
                &public,
                duplicate,
                in_sym_seed,
                encryption_key,
                &symmetric_alg,
                auths,
            )?;

            TpmKeyFile::new()
                .with_kind(TpmKeyType::Loadable)
                .with_empty_auth(user_auth.is_empty())
                .with_public(public)
                .with_private(out_private)
                .with_parent(parent_handle)
                .with_policy(&policy)
        } else {
            TpmKeyFile::new()
                .with_kind(TpmKeyType::Importable)
                .with_empty_auth(user_auth.is_empty())
                .with_public(public)
                .with_private(*duplicate)
                .with_secret(in_sym_seed.as_ref())
                .with_parent(parent_handle)
                .with_policy(&policy)
        };

        if let Some(n) = &self.description {
            file = file.with_description(n.clone());
        }

        Ok(file)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_external_key(
        &self,
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
        user_auth: Tpm2bAuth,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
        policy_commands: Vec<(TpmCommand, TpmAuthCommands)>,
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

        let (duplicate, in_sym_seed, encryption_key) = Self::build_import_blob(
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

        self.build_key_file(
            task_state,
            device,
            parent_handle,
            tpm_public,
            &duplicate,
            &in_sym_seed,
            &encryption_key,
            auths,
            user_auth,
            policy_commands,
        )
    }
}
