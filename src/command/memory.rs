// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::Job,
    command::{print_table, AuthArgs, CommandError, Tabled},
    device::{self, Device, DeviceError},
    handle::Handle,
    key::{
        Alg, AlgInfo, Tpm2shAlgId, OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384,
        OID_ECDSA_WITH_SHA512, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION, OID_SHA1_WITH_RSA_ENCRYPTION,
        OID_SHA256_WITH_RSA_ENCRYPTION, OID_SHA384_WITH_RSA_ENCRYPTION,
        OID_SHA512_WITH_RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
    },
    session::Session,
    vtpm::build_password_session,
};
use clap::Args;
use num_bigint::ToBigInt;
use rasn::{
    types::{BitString, Integer, ObjectIdentifier, SequenceOf},
    AsnType, Decode, Decoder,
};
use strum::Display;
use tpm2_protocol::{
    data::{TpmAlgId, TpmCc, TpmHt, TpmPt, TpmRcBase, TpmRh, TpmaNv, TpmsAuthCommand},
    message::{TpmNvReadCommand, TpmNvReadPublicCommand},
    TpmHandle,
};

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[strum(serialize_all = "kebab-case")]
enum MemoryHandleType {
    Transient,
    Persistent,
    Session,
    Certificate,
}

struct MemoryRow {
    handle: String,
    class: String,
    details: String,
}

impl Tabled for MemoryRow {
    fn headers() -> Vec<String> {
        vec![
            "HANDLE".to_string(),
            "TYPE".to_string(),
            "DETAILS".to_string(),
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.handle.clone(),
            self.class.clone(),
            self.details.clone(),
        ]
    }
}

/// Lists active TPM objects or inspects a single handle.
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory or inspects a single handle.")]
pub struct Memory {
    /// Optional handle to inspect: 'tpm:<handle>'
    pub handle: Option<Handle>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Job for Memory {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        if let Some(handle) = self.handle {
            Self::inspect_handle(job, handle, &self.auth_args)
        } else {
            Self::list_all_memory(job, &self.auth_args)
        }
    }
}

fn default_bool_false() -> bool {
    false
}

#[derive(AsnType, Decode, Debug)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<rasn::types::Any>,
}

#[derive(AsnType, Decode, Debug)]
struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

#[derive(AsnType, Decode, Debug)]
struct RsaPublicKey {
    modulus: Integer,
    _public_exponent: Integer,
}

#[derive(AsnType, Decode, Debug)]
struct Extension {
    _extn_id: ObjectIdentifier,
    #[rasn(default = "default_bool_false")]
    _critical: bool,
    _extn_value: rasn::types::OctetString,
}

#[derive(AsnType, Decode, Debug)]
struct TbsCertificate {
    #[rasn(tag(explicit(context, 0)))]
    _version: Option<Integer>,
    _serial_number: Integer,
    signature: AlgorithmIdentifier,
    _issuer: rasn::types::Any,
    _validity: rasn::types::Any,
    _subject: rasn::types::Any,
    subject_public_key_info: SubjectPublicKeyInfo,
    #[rasn(tag(context, 1))]
    _issuer_unique_id: Option<BitString>,
    #[rasn(tag(context, 2))]
    _subject_unique_id: Option<BitString>,
    #[rasn(tag(explicit(context, 3)))]
    _extensions: Option<SequenceOf<Extension>>,
}

#[derive(AsnType, Decode, Debug)]
struct Certificate {
    tbs_cert: TbsCertificate,
    _signature_algorithm: AlgorithmIdentifier,
    _signature_value: BitString,
}

impl Memory {
    fn inspect_handle(
        job: &mut Session,
        handle: Handle,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        device::with_device(job.device.clone(), |device| {
            let handle_val = handle.value();
            if (0x01C0_0000..=0x01C0_FFFF).contains(&handle_val) {
                Self::fetch_certificate(job, device, handle_val, auth_args)
            } else {
                match device.read_public(handle_val.into()) {
                    Ok(_) => Ok(()),
                    Err(DeviceError::TpmRc(rc))
                        if rc.base() == TpmRcBase::Handle
                            || rc.base() == TpmRcBase::ReferenceH0 =>
                    {
                        Err(CommandError::UnknownHandle(handle.to_string()))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        })
    }

    fn list_all_memory(job: &mut Session, auth_args: &AuthArgs) -> Result<(), CommandError> {
        device::with_device(job.device.clone(), |device| {
            let mut rows: Vec<MemoryRow> = Vec::new();
            Self::fetch_rows(
                job,
                device,
                &mut rows,
                TpmHt::Persistent,
                MemoryHandleType::Persistent,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, handle).map(Some),
            )?;
            Self::fetch_rows(
                job,
                device,
                &mut rows,
                TpmHt::Transient,
                MemoryHandleType::Transient,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, handle).map(Some),
            )?;
            Self::fetch_rows(
                job,
                device,
                &mut rows,
                TpmHt::LoadedSession,
                MemoryHandleType::Session,
                auth_args,
                |_, _, handle, _| {
                    let ht = TpmHt::try_from(handle)?;
                    let detail = if ht == TpmHt::HmacSession {
                        "hmac"
                    } else {
                        "policy"
                    };
                    Ok(Some(detail.to_string()))
                },
            )?;

            Self::fetch_rows(
                job,
                device,
                &mut rows,
                TpmHt::SavedSession,
                MemoryHandleType::Session,
                auth_args,
                |_, _, _, _| Ok(Some("saved".to_string())),
            )?;

            Self::fetch_rows(
                job,
                device,
                &mut rows,
                TpmHt::NvIndex,
                MemoryHandleType::Certificate,
                auth_args,
                |_, device, handle, auth_args| {
                    let handle_val = handle.value();
                    if !(0x01C0_0000..=0x01C0_FFFF).contains(&handle_val) {
                        return Ok(None);
                    }

                    let cert_bytes = match Self::read_nv_index(device, handle_val, auth_args) {
                        Ok(bytes) => bytes,
                        Err(CommandError::Device(DeviceError::TpmRc(_))) => {
                            return Ok(None);
                        }
                        Err(e) => return Err(e),
                    };

                    if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != 0x30 {
                        return Ok(None);
                    }
                    Ok(Some(Memory::fetch_alg_name(&cert_bytes)?))
                },
            )?;
            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
            print_table(&mut job.writer, &rows)?;
            Ok(())
        })
    }

    fn read_nv_index(
        device: &mut Device,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<Vec<u8>, CommandError> {
        let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax).unwrap_or(0) as usize;

        if max_read_size == 0 {
            return Ok(Vec::new());
        }

        let nv_read_public_cmd = TpmNvReadPublicCommand {
            nv_index: handle.into(),
        };
        let (resp, _) = device.execute(&nv_read_public_cmd, &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size as usize;

        if data_size == 0 {
            return Ok(Vec::new());
        }

        let auth_handle_val = if nv_public.attributes.contains(TpmaNv::AUTHREAD) {
            handle
        } else if nv_public.attributes.contains(TpmaNv::PPREAD) {
            TpmRh::Platform as u32
        } else if nv_public.attributes.contains(TpmaNv::OWNERREAD) {
            TpmRh::Owner as u32
        } else {
            handle
        };

        let mut cert_bytes = Vec::with_capacity(data_size);
        let mut offset = 0;
        while offset < data_size {
            let chunk_size = std::cmp::min(max_read_size, data_size - offset);
            let nv_read_cmd = TpmNvReadCommand {
                auth_handle: auth_handle_val.into(),
                nv_index: handle.into(),
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
            };
            let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
            let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;

            let auths_cow = auth_args.auths();
            let effective_auths: &[Auth] = if needs_auth { auths_cow.as_ref() } else { &[] };

            let mut sessions: Vec<TpmsAuthCommand> = Vec::new();
            for auth in effective_auths {
                if let Auth::Password(value) = auth {
                    sessions.push(build_password_session(value)?);
                } else {
                    return Err(CommandError::InvalidInput(
                        "Session-based auth for NV read not supported directly in memory command"
                            .to_string(),
                    ));
                }
            }

            let (resp, _) = device.execute(&nv_read_cmd, &sessions)?;
            let read_resp = resp
                .NvRead()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvRead))?;
            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += chunk_size;
        }
        Ok(cert_bytes)
    }

    fn fetch_certificate(
        job: &mut Session,
        device: &mut Device,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        let cert_bytes = Self::read_nv_index(device, handle, auth_args)?;

        if cert_bytes.is_empty() {
            log::warn!("{handle:08x}: no certificate");
            return Ok(());
        }

        let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
        writeln!(job.writer, "{pem_cert}")?;

        Ok(())
    }

    fn fetch_rows<F>(
        job: &mut Session,
        device: &mut Device,
        rows: &mut Vec<MemoryRow>,
        class: TpmHt,
        display_type: MemoryHandleType,
        auth_args: &AuthArgs,
        mut get_details: F,
    ) -> Result<(), CommandError>
    where
        F: FnMut(
            &mut Session,
            &mut Device,
            Handle,
            &AuthArgs,
        ) -> Result<Option<String>, CommandError>,
    {
        for handle in device.fetch_handles((class as u32) << 24)? {
            match get_details(job, device, handle, auth_args) {
                Ok(Some(details)) => {
                    rows.push(MemoryRow {
                        handle: format!("{:08x}", handle.value()),
                        class: display_type.to_string(),
                        details,
                    });
                }
                Ok(None) => {}
                Err(e) => log::debug!("{:08x}: {e}", handle.value()),
            }
        }
        Ok(())
    }

    fn fetch_details(device: &mut Device, handle: Handle) -> Result<String, CommandError> {
        let tpm_handle = TpmHandle(handle.value());
        let (public, _) = device.read_public(tpm_handle)?;
        Ok(crate::key::format_alg_from_public(&public))
    }

    /// Creates a placeholder Alg struct for error reporting.
    fn oid_to_placeholder_alg(oid: &ObjectIdentifier) -> Alg {
        Alg {
            name: oid.to_string(),
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Null,
            params: AlgInfo::KeyedHash,
        }
    }

    fn fetch_hash_alg(oid: &ObjectIdentifier) -> Result<TpmAlgId, CommandError> {
        if oid == &OID_SHA1_WITH_RSA_ENCRYPTION {
            Ok(TpmAlgId::Sha1)
        } else if oid == &OID_SHA256_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA256 {
            Ok(TpmAlgId::Sha256)
        } else if oid == &OID_SHA384_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA384 {
            Ok(TpmAlgId::Sha384)
        } else if oid == &OID_SHA512_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA512 {
            Ok(TpmAlgId::Sha512)
        } else {
            Err(CommandError::UnsupportedSignatureAlgorithm(
                Self::oid_to_placeholder_alg(oid),
            ))
        }
    }

    fn fetch_alg_name(cert_der: &[u8]) -> Result<String, CommandError> {
        let cert: Certificate = rasn::der::decode(cert_der).map_err(|e| {
            CommandError::InvalidInput(format!("DER certificate decode failed: {e}"))
        })?;
        let tbs = cert.tbs_cert;
        let spki = tbs.subject_public_key_info;
        let sig_alg = Self::fetch_hash_alg(&tbs.signature.algorithm)?;
        let sig_alg_str = Tpm2shAlgId(sig_alg).to_string();

        let key_oid = &spki.algorithm.algorithm;
        if key_oid == &OID_RSA_ENCRYPTION {
            let key: RsaPublicKey = rasn::der::decode(spki.subject_public_key.as_raw_slice())
                .map_err(|e| {
                    CommandError::InvalidInput(format!("DER RSA public key decode failed: {e}"))
                })?;
            let modulus = key.modulus.to_bigint().ok_or_else(|| {
                CommandError::InvalidInput(format!("Invalid RSA modulus value: {}", key.modulus))
            })?;
            let key_bits = u16::try_from(modulus.bits()).map_err(|_| {
                CommandError::InvalidInput(format!(
                    "RSA modulus bit size calculation failed for: {modulus}"
                ))
            })?;
            Ok(format!("rsa-{key_bits}:{sig_alg_str}"))
        } else if key_oid == &OID_EC_PUBLIC_KEY {
            let curve_param_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|any| rasn::der::decode::<ObjectIdentifier>(any.as_ref()).ok());
            let curve_str = if curve_param_oid.as_ref() == Some(&SECP_256_R_1) {
                "nist-p256"
            } else if curve_param_oid.as_ref() == Some(&SECP_384_R_1) {
                "nist-p384"
            } else if curve_param_oid.as_ref() == Some(&SECP_521_R_1) {
                "nist-p521"
            } else if let Some(oid) = curve_param_oid.as_ref() {
                return Err(CommandError::UnsupportedKeyAlgorithm(
                    Self::oid_to_placeholder_alg(oid),
                ));
            } else {
                return Err(CommandError::MissingEccCurveParameters);
            };
            Ok(format!("ecc-{curve_str}:{sig_alg_str}"))
        } else {
            Err(CommandError::UnsupportedKeyAlgorithm(
                Self::oid_to_placeholder_alg(key_oid),
            ))
        }
    }
}
