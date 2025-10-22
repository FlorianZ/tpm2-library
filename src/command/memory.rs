// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{print_table, CommandError},
    device::{self, Device},
    job::Job,
    key::{
        format_alg_from_public, KeyError, Tpm2shAlgId, OID_ECDSA_WITH_SHA256,
        OID_ECDSA_WITH_SHA384, OID_ECDSA_WITH_SHA512, OID_RSA_ENCRYPTION,
        OID_SHA1_WITH_RSA_ENCRYPTION, OID_SHA256_WITH_RSA_ENCRYPTION,
        OID_SHA384_WITH_RSA_ENCRYPTION, OID_SHA512_WITH_RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1,
        SECP_521_R_1,
    },
};
use clap::Args;
use num_bigint::ToBigInt;
use rasn::{
    types::{BitString, Integer, ObjectIdentifier, SequenceOf},
    AsnType, Decode, Decoder,
};
use strum::Display;
use tabled::Tabled;
use tpm2_protocol::data::{TpmAlgId, TpmHt, TpmPt};

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[strum(serialize_all = "kebab-case")]
enum MemoryHandleType {
    Transient,
    Persistent,
    Session,
    Certificate,
}

#[derive(Tabled)]
struct MemoryRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "TYPE")]
    handle_type: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists active TPM objects.
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory")]
pub struct Memory {}

impl SubCommand for Memory {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        device::with_device(job.device.clone(), |device| {
            let mut rows: Vec<MemoryRow> = Vec::new();
            Self::fetch_rows(
                device,
                &mut rows,
                TpmHt::Persistent as u32,
                MemoryHandleType::Persistent,
                Self::fetch_details,
            )?;
            Self::fetch_rows(
                device,
                &mut rows,
                TpmHt::Transient as u32,
                MemoryHandleType::Transient,
                Self::fetch_details,
            )?;
            Self::fetch_rows(
                device,
                &mut rows,
                TpmHt::LoadedSession as u32,
                MemoryHandleType::Session,
                |_, handle| {
                    let mso = (handle >> 24) as u8;
                    let detail = if mso == TpmHt::HmacSession as u8 {
                        "hmac"
                    } else {
                        "policy"
                    };
                    Ok(detail.to_string())
                },
            )?;

            Self::fetch_rows(
                device,
                &mut rows,
                TpmHt::SavedSession as u32,
                MemoryHandleType::Session,
                |_, _| Ok("saved".to_string()),
            )?;

            let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax).unwrap_or(0) as usize;

            if max_read_size > 0 {
                Self::fetch_rows(
                    device,
                    &mut rows,
                    TpmHt::NvIndex as u32,
                    MemoryHandleType::Certificate,
                    |device, handle| {
                        if !(0x01C0_0000..=0x01C0_FFFF).contains(&handle) {
                            return Err(CommandError::InvalidInput("Not a certificate".into()));
                        }
                        let auths = vec![Auth::Password(Vec::new())];
                        let cert_bytes = job
                            .read_certificate(device, &auths, handle, max_read_size)?
                            .ok_or(CommandError::InvalidInput("No certificate data".into()))?;
                        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != (0x30) {
                            return Err(CommandError::InvalidInput("Not a DER certificate".into()));
                        }
                        Ok(Memory::fetch_alg_name(&cert_bytes)?)
                    },
                )?;
            }
            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
            print_table(&mut job.key_cache.writer, rows)?;
            Ok(())
        })
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
    fn fetch_rows<F>(
        device: &mut Device,
        rows: &mut Vec<MemoryRow>,
        handle_type: u32,
        display_type: MemoryHandleType,
        mut get_details: F,
    ) -> Result<(), CommandError>
    where
        F: FnMut(&mut Device, u32) -> Result<String, CommandError>,
    {
        for handle in device.fetch_handles(handle_type << 24)? {
            match get_details(device, handle) {
                Ok(details) => {
                    rows.push(MemoryRow {
                        handle: format!("{handle:08x}"),
                        handle_type: display_type.to_string(),
                        details,
                    });
                }
                Err(e) => log::debug!("{handle:08x}: {e}"),
            }
        }
        Ok(())
    }

    fn fetch_details(device: &mut Device, handle: u32) -> Result<String, CommandError> {
        let (public, _) = device.read_public(handle.into())?;
        Ok(format_alg_from_public(&public))
    }

    fn fetch_hash_alg(oid: &ObjectIdentifier) -> Result<TpmAlgId, KeyError> {
        if oid == &OID_SHA1_WITH_RSA_ENCRYPTION {
            Ok(TpmAlgId::Sha1)
        } else if oid == &OID_SHA256_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA256 {
            Ok(TpmAlgId::Sha256)
        } else if oid == &OID_SHA384_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA384 {
            Ok(TpmAlgId::Sha384)
        } else if oid == &OID_SHA512_WITH_RSA_ENCRYPTION || oid == &OID_ECDSA_WITH_SHA512 {
            Ok(TpmAlgId::Sha512)
        } else {
            Err(KeyError::UnsupportedOid(oid.to_string()))
        }
    }

    fn fetch_alg_name(cert_der: &[u8]) -> Result<String, KeyError> {
        let cert: Certificate = rasn::der::decode(cert_der)?;
        let tbs = cert.tbs_cert;
        let spki = tbs.subject_public_key_info;
        let sig_alg = Memory::fetch_hash_alg(&tbs.signature.algorithm)?;
        let sig_alg_str = Tpm2shAlgId(sig_alg).to_string();

        let key_oid = &spki.algorithm.algorithm;
        if key_oid == &OID_RSA_ENCRYPTION {
            let key: RsaPublicKey = rasn::der::decode(spki.subject_public_key.as_raw_slice())?;
            let modulus = key
                .modulus
                .to_bigint()
                .ok_or_else(|| KeyError::InvalidRsaModulus(key.modulus.to_string()))?;
            let key_bits = u16::try_from(modulus.bits())
                .map_err(|_| KeyError::InvalidRsaModulus(modulus.to_string()))?;
            Ok(format!("rsa-{key_bits}:{sig_alg_str}"))
        } else if key_oid == &crate::key::OID_EC_PUBLIC_KEY {
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
                return Err(KeyError::UnsupportedOid(oid.to_string()));
            } else {
                return Err(KeyError::InvalidOid);
            };
            Ok(format!("ecc-{curve_str}:{sig_alg_str}"))
        } else {
            Err(KeyError::UnsupportedOid(key_oid.to_string()))
        }
    }
}
