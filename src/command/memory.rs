// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::{Alg, AlgInfo},
    cli::Task,
    command::{print_table, AuthArgs, CommandError},
    task::{TaskAuth, TaskState},
};
use clap::Args;
use openssl::{nid::Nid, pkey::Id as PKeyId, x509::X509};
use pem;
use strum::Display;
use tabled::Tabled;
use tpm2_crypto::{TpmEllipticCurve, TpmHash};
use tpm2_device::{with_device, TpmDevice, TpmDeviceError};
use tpm2_protocol::{
    data::{TpmAlgId, TpmCc, TpmHt, TpmPt, TpmRcBase, TpmRh, TpmaNv},
    frame::{TpmNvReadCommand, TpmNvReadPublicCommand},
    TpmHandle,
};
use tpm2_vtpm::VtpmHandle;

const EK_CERT_RANGE: std::ops::RangeInclusive<u32> = 0x01C0_0000..=0x01C0_FFFF;

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
    #[tabled(rename = "CLASS")]
    class: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists active TPM objects or inspects a single handle.
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory or inspects a single handle.")]
pub struct Memory {
    /// Optional handle to inspect: 'tpm:<handle>'
    pub handle: Option<VtpmHandle>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Memory {
    fn run(
        &self,
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        is_tty: bool,
    ) -> Result<(), CommandError> {
        if let Some(handle) = self.handle {
            let handle_val = handle
                .value()
                .ok_or_else(|| CommandError::PatternNotAllowed(handle.to_string()))?;
            Self::inspect_handle(
                session,
                writer,
                handle_val,
                handle.to_string(),
                &self.auth_args,
            )
        } else {
            Self::list_all_memory(session, writer, &self.auth_args, is_tty)
        }
    }
}

impl Memory {
    fn inspect_handle(
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        handle_val: u32,
        handle_str: String,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        with_device(session.device.clone(), |device| {
            if EK_CERT_RANGE.contains(&handle_val) {
                Self::fetch_certificate(session, device, writer, handle_val, auth_args)
            } else {
                match device.read_public(handle_val.into()) {
                    Ok(_) => Ok(()),
                    Err(TpmDeviceError::TpmRc(rc))
                        if rc.base() == TpmRcBase::Handle
                            || rc.base() == TpmRcBase::ReferenceH0 =>
                    {
                        Err(CommandError::UnknownHandle(handle_str))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        })
    }

    fn list_all_memory(
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        auth_args: &AuthArgs,
        is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(session.device.clone(), |device| {
            let mut rows: Vec<MemoryRow> = Vec::new();

            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::Persistent,
                MemoryHandleType::Persistent,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, *handle).map(Some),
            )?;
            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::Transient,
                MemoryHandleType::Transient,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, *handle).map(Some),
            )?;
            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::LoadedSession,
                MemoryHandleType::Session,
                auth_args,
                |_, _, handle, _| {
                    let TpmHandle(handle) = handle;
                    let ht = (handle >> 24) as u8;

                    let detail = if ht == TpmHt::HmacSession as u8 {
                        "hmac"
                    } else {
                        "policy"
                    };

                    Ok(Some(detail.to_string()))
                },
            )?;

            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::SavedSession,
                MemoryHandleType::Session,
                auth_args,
                |_, _, _, _| Ok(Some("saved".to_string())),
            )?;

            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::NvIndex,
                MemoryHandleType::Certificate,
                auth_args,
                Self::fetch_certificate_details,
            )?;
            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));

            print_table(&rows, writer, is_tty)?;
            Ok(())
        })
    }

    /// Determines the correct handle to use for authorization based on NV
    /// attributes.
    fn resolve_nv_auth(attributes: TpmaNv, handle: u32) -> u32 {
        if attributes.contains(TpmaNv::AUTHREAD) {
            handle
        } else if attributes.contains(TpmaNv::PPREAD) {
            TpmRh::Platform as u32
        } else if attributes.contains(TpmaNv::OWNERREAD) {
            TpmRh::Owner as u32
        } else {
            handle
        }
    }

    fn read_nv_index(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<Vec<u8>, CommandError> {
        let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax).unwrap_or(0) as usize;

        if max_read_size == 0 {
            return Ok(Vec::new());
        }

        let nv_read_public_cmd = TpmNvReadPublicCommand {
            handles: [handle.into()],
        };
        let (resp, _) = session.execute(device, &nv_read_public_cmd, &[], &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size as usize;

        if data_size == 0 {
            return Ok(Vec::new());
        }

        let auth_handle_val = Self::resolve_nv_auth(nv_public.attributes, handle);

        let mut cert_bytes = Vec::with_capacity(data_size);
        let mut offset = 0;

        let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
        let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;
        let auths_cow = auth_args.auths(false);
        let effective_auths: &[TaskAuth] = if needs_auth { auths_cow.as_ref() } else { &[] };
        let handles = [auth_handle_val];

        while offset < data_size {
            let chunk_size = std::cmp::min(max_read_size, data_size - offset);
            let nv_read_cmd = TpmNvReadCommand {
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
                handles: [auth_handle_val.into(), handle.into()],
            };

            let (resp, _) = session.execute(device, &nv_read_cmd, &handles, effective_auths)?;

            let read_resp = resp
                .NvRead()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvRead))?;
            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += chunk_size;
        }
        Ok(cert_bytes)
    }

    fn fetch_certificate(
        session: &mut TaskState,
        device: &mut TpmDevice,
        writer: &mut dyn std::io::Write,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        let cert_bytes = Self::read_nv_index(session, device, handle, auth_args)?;

        if cert_bytes.is_empty() {
            log::warn!("{handle:08x}: no certificate");
            return Ok(());
        }

        let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
        writeln!(writer, "{pem_cert}")?;

        Ok(())
    }

    fn fetch_rows<F>(
        session: &mut TaskState,
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
        class: TpmHt,
        display_type: MemoryHandleType,
        auth_args: &AuthArgs,
        mut get_details: F,
    ) -> Result<(), CommandError>
    where
        F: FnMut(
            &mut TaskState,
            &mut TpmDevice,
            &TpmHandle,
            &AuthArgs,
        ) -> Result<Option<String>, CommandError>,
    {
        for handle in device.fetch_handles(class)? {
            let TpmHandle(handle_val) = handle;

            match get_details(session, device, &handle, auth_args) {
                Ok(Some(details)) => {
                    rows.push(MemoryRow {
                        handle: format!("{handle_val:08x}"),
                        class: display_type.to_string(),
                        details,
                    });
                }
                Ok(None) => {}
                Err(e) => log::debug!("{handle_val:08x}: {e}"),
            }
        }
        Ok(())
    }

    fn fetch_certificate_details(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: &TpmHandle,
        auth_args: &AuthArgs,
    ) -> Result<Option<String>, CommandError> {
        let TpmHandle(handle_val) = *handle;
        if !EK_CERT_RANGE.contains(&handle_val) {
            return Ok(None);
        }

        let cert_bytes = match Self::read_nv_index(session, device, handle_val, auth_args) {
            Ok(bytes) => bytes,
            Err(CommandError::Device(TpmDeviceError::TpmRc(_))) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != 0x30 {
            return Ok(None);
        }
        Ok(Some(format!(
            "endorsement:{}",
            Memory::fetch_alg_name(&cert_bytes)?
        )))
    }

    fn fetch_details(device: &mut TpmDevice, handle: TpmHandle) -> Result<String, CommandError> {
        let (public, _) = device.read_public(handle)?;
        let TpmHandle(handle) = handle;

        let details = crate::alg::alg_details(&public);

        if (handle & 0xFF00_0000) == (TpmHt::Persistent as u32) << 24 {
            let hierarchy = if handle >= 0x8180_0000 {
                "platform"
            } else {
                "owner"
            };
            Ok(format!("{hierarchy}:{details}"))
        } else {
            Ok(details)
        }
    }

    fn fetch_hash_alg(oid_nid: Nid) -> Result<TpmHash, CommandError> {
        match oid_nid {
            Nid::SHA1WITHRSAENCRYPTION => Ok(TpmHash::Sha1),
            Nid::ECDSA_WITH_SHA256 | Nid::SHA256WITHRSAENCRYPTION => Ok(TpmHash::Sha256),
            Nid::ECDSA_WITH_SHA384 | Nid::SHA384WITHRSAENCRYPTION => Ok(TpmHash::Sha384),
            Nid::ECDSA_WITH_SHA512 | Nid::SHA512WITHRSAENCRYPTION => Ok(TpmHash::Sha512),
            _ => Err(CommandError::UnsupportedSignatureAlgorithm(Alg {
                name: oid_nid.long_name().unwrap_or("unknown").to_string(),
                object_type: TpmAlgId::Null,
                name_alg: TpmAlgId::Null,
                params: AlgInfo::KeyedHash,
            })),
        }
    }

    fn fetch_alg_name(cert_der: &[u8]) -> Result<String, CommandError> {
        let cert = X509::from_der(cert_der).map_err(|e| {
            CommandError::InvalidInput(format!("DER certificate decode failed: {e}"))
        })?;

        let sig_nid = cert.signature_algorithm().object().nid();
        let sig_alg = Self::fetch_hash_alg(sig_nid)?;
        let sig_alg_str = sig_alg.to_string();

        let pkey = cert.public_key()?;
        match pkey.id() {
            PKeyId::RSA => {
                let rsa = pkey.rsa()?;
                let key_bits = u16::try_from(rsa.size() * 8)?;
                Ok(format!("rsa-{key_bits}:{sig_alg_str}"))
            }
            PKeyId::EC => {
                let ec_key = pkey.ec_key()?;
                let curve_nid = ec_key.group().curve_name();
                let curve = match curve_nid {
                    Some(Nid::X9_62_PRIME256V1) => TpmEllipticCurve::NistP256,
                    Some(Nid::SECP384R1) => TpmEllipticCurve::NistP384,
                    Some(Nid::SECP521R1) => TpmEllipticCurve::NistP521,
                    _ => {
                        let name = curve_nid
                            .and_then(|n| n.long_name().ok())
                            .unwrap_or("unknown");
                        return Err(CommandError::UnsupportedKeyAlgorithm(Alg {
                            name: name.to_string(),
                            object_type: TpmAlgId::Null,
                            name_alg: TpmAlgId::Null,
                            params: AlgInfo::KeyedHash,
                        }));
                    }
                };
                Ok(format!("ecc-{curve}:{sig_alg_str}"))
            }
            _ => Err(CommandError::UnsupportedKeyAlgorithm(Alg {
                name: format!("{:?}", pkey.id()),
                object_type: TpmAlgId::Null,
                name_alg: TpmAlgId::Null,
                params: AlgInfo::KeyedHash,
            })),
        }
    }
}
