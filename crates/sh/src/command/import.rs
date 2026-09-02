// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::common::{
        build_policy_command_list, default_symmetric, parse_import_attributes, parse_password,
    },
    error::device_err,
    io::{read_file_input, write_key_data, write_object},
    task::{Auth, TaskState},
};
use anyhow::{Result, anyhow};
use argh::FromArgs;
use openssl::symm::{Cipher, encrypt};
use std::{path::PathBuf, str::FromStr};
use tpm2_crypto::{
    KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE, TpmEccExternalKey, TpmExternalKey, TpmHash,
    TpmPublicTemplate, TpmRsaExternalKey, tpm_make_name,
};
use tpm2_device::{TpmDevice, with_device};
use tpm2_protocol::{
    TpmMarshal, TpmWriter,
    basic::{TpmHandle, TpmUint32},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitive, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId,
        TpmEccCurve, TpmaObject, TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuPublicParms,
        TpmuSensitiveComposite, TpmuSymKeyBits,
    },
    frame::{TpmAuthCommands, TpmCommandValue as TpmCommand},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyType};

/// Import external keys to TPM keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "import", help_triggers("-h", "--help", "help"))]
pub struct Import {
    /// parent's TPM handle as an eight characters hex string
    #[argh(positional)]
    pub parent: crate::handle::Handle,

    /// object algorithm: e.g., 'rsa-2048:sha256:rsassa' (defaults to unrestricted :null)
    #[argh(positional)]
    pub algorithm: Option<TpmPublicTemplate>,

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

enum ImportKeyShape {
    Rsa(tpm2_protocol::basic::TpmUint16),
    Ecc(tpm2_crypto::TpmEllipticCurve),
}

impl Task for Import {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        let parent = self
            .parent
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.parent))?;

        with_device(task_state.device.clone().as_ref(), |device| {
            let (parent_handle, name_alg, auth) =
                task_state.resolve_auth(device, TpmUint32::new(parent))?;

            let input_bytes = read_file_input(self.input.as_deref())?;
            let user_auth = parse_password(self.password.as_deref())?;
            let (der_bytes, template) =
                Self::parse_external_key(&input_bytes, name_alg, self.algorithm.as_ref())?;
            let (auth_policy, policy_commands) = build_policy_command_list(
                self.policy_expression.as_deref(),
                task_state,
                device,
                template.name_alg(),
            )?;
            let object_attributes = parse_import_attributes(
                self.password.as_deref(),
                self.policy_expression.as_deref(),
                self.lock,
                &template,
            )?;
            let tpm_key = self.build_external_key(
                task_state,
                device,
                parent_handle,
                &der_bytes,
                template,
                &[auth],
                user_auth,
                auth_policy,
                object_attributes,
                policy_commands,
            )?;

            write_key_data(writer, &tpm_key, self.output.as_deref())
        })
    }
}

impl Import {
    fn public_to_sym_key_bits(parent_public: &TpmtPublic) -> Result<u16> {
        let sym_def = match &parent_public.parameters {
            TpmuPublicParms::Rsa(parms) => &parms.symmetric,
            TpmuPublicParms::Ecc(parms) => &parms.symmetric,
            _ => return Err(anyhow!("invalid parent key type")),
        };

        match sym_def.key_bits {
            TpmuSymKeyBits::Aes(bits)
            | TpmuSymKeyBits::Camellia(bits)
            | TpmuSymKeyBits::Sm4(bits) => Ok(bits.value()),
            _ => Err(anyhow!("invalid parent key type")),
        }
    }

    fn create_import_keys(
        parent_name_alg: TpmAlgId,
        seed: &[u8],
        object_name: &Tpm2bName,
        key_bits: u16,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let parent_hash = TpmHash::try_from(parent_name_alg)?;
        let sym_key = parent_hash.kdfa(
            seed,
            KDF_LABEL_STORAGE,
            object_name.as_ref(),
            &[],
            usize::from(key_bits),
        )?;

        let key_bits = parent_hash.size() * 8;

        let hmac_key = parent_hash.kdfa(seed, KDF_LABEL_INTEGRITY, &[], &[], key_bits)?;

        Ok((sym_key, hmac_key))
    }

    fn encrypt_sensitive_data(
        object_public: &TpmtPublic,
        private_bytes: &[u8],
        sym_key: &[u8],
        auth_value: Tpm2bAuth,
        key_bits: u16,
    ) -> Result<Vec<u8>> {
        let object_key_type = object_public.object_type;

        let sensitive_composite = match object_key_type {
            TpmAlgId::Rsa => {
                TpmuSensitiveComposite::Rsa(Tpm2bSensitiveData::try_from(private_bytes)?)
            }
            TpmAlgId::Ecc => {
                TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::try_from(private_bytes)?)
            }
            TpmAlgId::KeyedHash => {
                TpmuSensitiveComposite::Bits(Tpm2bSensitiveData::try_from(private_bytes)?)
            }
            TpmAlgId::SymCipher => {
                TpmuSensitiveComposite::Sym(Tpm2bSymKey::try_from(private_bytes)?)
            }
            _ => return Err(anyhow!("unsupported key algorithm")),
        };

        let sensitive = TpmtSensitive {
            sensitive_type: object_key_type,
            auth_value,
            seed_value: Tpm2bDigest::default(),
            sensitive: sensitive_composite,
        };
        let sensitive_tpm2b = Tpm2bSensitive::from(sensitive);
        let enc_data_in = write_object(&sensitive_tpm2b)?;
        let iv = [0u8; 16];

        let cipher = match key_bits {
            128 => Cipher::aes_128_cfb128(),
            256 => Cipher::aes_256_cfb128(),
            _ => return Err(anyhow!("invalid parent key type")),
        };

        let enc_data = encrypt(cipher, sym_key, Some(&iv), &enc_data_in)
            .map_err(|_| anyhow!("encrypting duplicate blob for external key failed"))?;

        Ok(enc_data)
    }

    fn create_private_blob(
        parent_name_alg: TpmAlgId,
        hmac_key: &[u8],
        sensitive: &[u8],
        object_name: &Tpm2bName,
    ) -> Result<Tpm2bPrivate> {
        let final_mac = TpmHash::try_from(parent_name_alg)?
            .hmac(hmac_key, &[sensitive, object_name.as_ref()])?;

        let duplicate_blob = {
            let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
                Tpm2bDigest::try_from(final_mac.as_slice())?.marshal(&mut writer)?;
                writer.write_bytes(sensitive)?;
                writer.len()
            };
            duplicate_blob_buf[..len].to_vec()
        };

        Ok(Tpm2bPrivate::try_from(duplicate_blob.as_slice())?)
    }

    fn build_import_blob(
        parent_public: &tpm2_protocol::data::TpmtPublic,
        object_public: &tpm2_protocol::data::TpmtPublic,
        private_bytes: &[u8],
        object_name: &Tpm2bName,
        user_auth: Tpm2bAuth,
    ) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData)> {
        let name_alg = parent_public.name_alg;
        let (seed, in_sym_seed) = match parent_public.object_type {
            TpmAlgId::Rsa => {
                let key = TpmRsaExternalKey::try_from(parent_public)?;
                key.to_seed(TpmHash::try_from(name_alg)?)?
            }
            TpmAlgId::Ecc => {
                let key = TpmEccExternalKey::try_from(parent_public)?;
                key.to_seed(TpmHash::try_from(name_alg)?)?
            }
            _ => return Err(anyhow!("invalid parent key type")),
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

    /// Parses an external PEM private key and resolves its public-area template.
    ///
    /// Attempts RSA first, then ECC. When `algorithm` is omitted, the template
    /// is an unrestricted `:null` key of the imported type and size.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid PEM containing a supported
    /// private key, the key cannot be parsed as RSA or ECC, or `algorithm` does
    /// not match the imported key.
    fn parse_external_key(
        input_bytes: &[u8],
        name_alg: TpmAlgId,
        algorithm: Option<&TpmPublicTemplate>,
    ) -> Result<(Vec<u8>, TpmPublicTemplate)> {
        let der_bytes = pem::parse_many(input_bytes)
            .map_err(|_| anyhow!("invalid input: Input is not valid PEM"))?
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
            .ok_or_else(|| anyhow!("invalid input: No supported private key found in PEM"))?;

        let shape = Self::import_key_shape(&der_bytes)?;
        let template = Self::resolve_import_template(&shape, name_alg, algorithm)?;
        Ok((der_bytes, template))
    }

    fn import_key_shape(der_bytes: &[u8]) -> Result<ImportKeyShape> {
        if let Ok((key, _)) = TpmRsaExternalKey::from_der(der_bytes) {
            Ok(ImportKeyShape::Rsa(key.key_bits()))
        } else {
            let (key, _) = TpmEccExternalKey::from_der(der_bytes)?;
            Ok(ImportKeyShape::Ecc(key.curve()))
        }
    }

    fn resolve_import_template(
        shape: &ImportKeyShape,
        name_alg: TpmAlgId,
        algorithm: Option<&TpmPublicTemplate>,
    ) -> Result<TpmPublicTemplate> {
        match algorithm {
            Some(template) => Self::validate_import_template(shape, template),
            None => Self::default_unrestricted_template(shape, name_alg),
        }
    }

    fn validate_import_template(
        shape: &ImportKeyShape,
        template: &TpmPublicTemplate,
    ) -> Result<TpmPublicTemplate> {
        match shape {
            ImportKeyShape::Rsa(key_bits) => {
                let TpmuPublicParms::Rsa(parms) = template.public_parms() else {
                    return Err(anyhow!("algorithm type does not match imported key"));
                };
                if parms.key_bits != *key_bits {
                    return Err(anyhow!("algorithm size does not match imported key"));
                }
            }
            ImportKeyShape::Ecc(curve) => {
                let TpmuPublicParms::Ecc(parms) = template.public_parms() else {
                    return Err(anyhow!("algorithm type does not match imported key"));
                };
                if parms.curve_id != TpmEccCurve::from(*curve) {
                    return Err(anyhow!("algorithm curve does not match imported key"));
                }
            }
        }
        Ok(template.clone())
    }

    fn default_unrestricted_template(
        shape: &ImportKeyShape,
        name_alg: TpmAlgId,
    ) -> Result<TpmPublicTemplate> {
        let hash = TpmHash::try_from(name_alg)?;
        let s = match shape {
            ImportKeyShape::Rsa(key_bits) => format!("rsa-{key_bits}:{hash}:null"),
            ImportKeyShape::Ecc(curve) => format!("ecc-{curve}:{hash}:null"),
        };
        TpmPublicTemplate::from_str(&s).map_err(Into::into)
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
    ) -> Result<TpmKeyFile> {
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
                .with_secret(in_sym_seed)
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
        der_bytes: &[u8],
        template: TpmPublicTemplate,
        auths: &[Auth],
        user_auth: Tpm2bAuth,
        auth_policy: Tpm2bDigest,
        object_attributes: TpmaObject,
        policy_commands: Vec<(TpmCommand, TpmAuthCommands)>,
    ) -> Result<TpmKeyFile> {
        let (parent_public, _) = device.read_public(parent_handle).map_err(device_err)?;
        let symmetric = if template.is_storage_parent() {
            default_symmetric()
        } else {
            TpmtSymDefObject::default()
        };
        let template = template
            .with_object_attributes(object_attributes)
            .with_auth_policy(auth_policy)
            .with_symmetric(symmetric);
        let (public, sensitive_blob) =
            if let Ok((key, sensitive)) = TpmRsaExternalKey::from_der(der_bytes) {
                (key.to_public(&template), sensitive.to_vec())
            } else {
                let (key, sensitive) = TpmEccExternalKey::from_der(der_bytes)?;
                (key.to_public(&template), sensitive.to_vec())
            };

        let object_name = tpm_make_name(&public)?;
        let (duplicate, in_sym_seed, encryption_key) = Self::build_import_blob(
            &parent_public,
            &public,
            &sensitive_blob,
            &object_name,
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
