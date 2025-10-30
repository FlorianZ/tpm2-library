// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles the `create` command, which creates secondary keys or sealed objects.

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError, CreationArgs, OutputArgs, OutputEncodingArgs},
    device::{with_device, Device, DeviceError},
    io::write_key_data,
    key::{Alg, AlgInfo, TpmKey, TpmPolicy, OID_LOADABLE_KEY, OID_SEALED_DATA},
    session::{Session, SessionError},
    template, write_object,
};
use clap::Args;
use rasn::types::OctetString;
use tpm2_policy_language::Handle;
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmRcBase,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    message::TpmCreateCommand,
};

/// A template for creating a new TPM key object.
pub struct TpmKeyTemplate<'a> {
    pub alg_desc: &'a Alg,
    pub sensitive_data: Tpm2bSensitiveData,
    pub key_type_oid: rasn::prelude::ObjectIdentifier,
}

/// Creates secondary keys or sealed data objects.
#[derive(Args, Debug, Clone)]
#[command(about = "Creates a secondary key or a sealed data object.")]
pub struct Create {
    /// Parent handle: 'tpm:<handle>' or 'vtpm:<handle>'
    pub parent: Handle,

    /// Object algorithm: e.g., 'ecc-nist-p256:sha256' or 'keyedhash:sha256'.
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    /// Sensitive data: hex string
    #[arg(long = "data")]
    pub data: Option<String>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Job for Create {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        self.parent
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.parent.to_string()))?;

        with_device(job.device.clone(), |device| self.create_object(job, device))
    }
}

impl Create {
    #[allow(clippy::too_many_lines)]
    fn create_object(&self, job: &mut Session, device: &mut Device) -> Result<(), CommandError> {
        let parent_handle = job.load_context(device, &self.parent)?;

        let (object_attributes, user_auth, auth_policy) =
            self.creation_args.parse(&self.algorithm)?;

        let (sensitive_data, key_type_oid) = match (&self.data, &self.algorithm.params) {
            (Some(hex_data), AlgInfo::KeyedHash) => {
                let bytes = hex::decode(hex_data)?;
                if bytes.is_empty() {
                    Err(CommandError::SensitiveDataMissing)
                } else {
                    Ok((
                        Tpm2bSensitiveData::try_from(bytes.as_slice())?,
                        OID_SEALED_DATA,
                    ))
                }
            }
            (None, AlgInfo::Rsa { .. } | AlgInfo::Ecc { .. }) => {
                Ok((Tpm2bSensitiveData::default(), OID_LOADABLE_KEY))
            }
            (Some(_), _) | (None, AlgInfo::KeyedHash) => Err(CommandError::SensitiveDataDenied),
        }?;

        let template = TpmKeyTemplate {
            alg_desc: &self.algorithm,
            sensitive_data,
            key_type_oid,
        };

        let tpm_key = {
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
                .execute(device, &create_cmd, &handles, &self.auth_args.auths())
                .map_err(|e| {
                    if let SessionError::Device(DeviceError::TpmRc(rc)) = &e {
                        if rc.base() == TpmRcBase::Type {
                            if let Ok(key) = job.cache.find_by_phandle(device, parent_handle.0) {
                                return CommandError::InvalidParent(
                                    "vtpm:",
                                    key.context.saved_handle.0,
                                );
                            }
                            return CommandError::InvalidParent("tpm:", parent_handle.0);
                        }
                    }
                    e.into()
                })?;

            let create_resp = resp
                .Create()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Create))?;

            let (parent_public_data, _) = device.read_public(parent_handle)?;
            let parent_public_2b = Tpm2bPublic {
                inner: parent_public_data,
            };

            let empty_auth_flag = user_auth.is_empty();
            let key_type = template.key_type_oid.clone();

            let policy = if auth_policy.is_empty() {
                None
            } else {
                Some(vec![TpmPolicy {
                    command_code: 0,
                    command_policy: OctetString::copy_from_slice(auth_policy.as_ref()),
                }])
            };

            TpmKey {
                key_type,
                empty_auth: empty_auth_flag.then_some(true),
                policy,
                secret: None,
                auth_policy: None,
                description: None,
                rsa_parent: None,
                parent_pub_key: Some(OctetString::copy_from_slice(
                    &write_object(&parent_public_2b).map_err(DeviceError::TpmProtocol)?,
                )),
                parent: parent_handle.0,
                pub_key: OctetString::copy_from_slice(
                    &write_object(&create_resp.out_public).map_err(DeviceError::TpmProtocol)?,
                ),
                priv_key: OctetString::copy_from_slice(
                    &write_object(&create_resp.out_private).map_err(DeviceError::TpmProtocol)?,
                ),
            }
        };

        write_key_data(
            &mut job.writer,
            &tpm_key,
            self.output_args.output.as_deref(),
            self.output_encoding_args.output_encoding,
        )
    }
}
