//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::{Alg, AlgInfo},
    cli::Task,
    command::{print_table, AuthArgs, CommandError},
    device::{self, Device, DeviceError},
    task::{Auth, TaskState},
};
use clap::Args;
use openssl::{nid::Nid, pkey::Id as PKeyId, x509::X509};
use pem;
use strum::Display;
use tabled::Tabled;
use tpm2_crypto::{EccCurve, Hash};
use tpm2_policy_language::TpmHandleRef;
use tpm2_protocol::{
    data::{TpmAlgId, TpmCc, TpmHt, TpmPt, TpmRcBase, TpmRh, TpmaNv},
    frame::{TpmNvReadCommand, TpmNvReadPublicCommand},
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

#[derive(Tabled)]
struct MemoryRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "TYPE")]
    class: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists active TPM objects or inspects a single handle.
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory or inspects a single handle.")]
pub struct Memory {
    /// Optional handle to inspect: 'tpm:<handle>'
    pub handle: Option<TpmHandleRef>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Memory {
    fn run(&self, session: &mut TaskState) -> Result<(), CommandError> {
        if let Some(handle) = self.handle {
            handle
                .value()
                .ok_or_else(|| CommandError::PatternNotAllowed(handle.to_string()))?;
            Self::inspect_handle(session, handle, &self.auth_args)
        } else {
            Self::list_all_memory(session, &self.auth_args)
        }
    }
}

impl Memory {
    fn inspect_handle(
        session: &mut TaskState,
        handle: TpmHandleRef,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        device::with_device(session.device.clone(), |device| {
            if let Some(handle_val) = handle.value() {
                if (0x01C0_0000..=0x01C0_FFFF).contains(&handle_val) {
                    Self::fetch_certificate(session, device, handle_val, auth_args)
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
            } else {
                Err(CommandError::PatternNotAllowed(handle.to_string()))
            }
        })
    }

    fn list_all_memory(session: &mut TaskState, auth_args: &AuthArgs) -> Result<(), CommandError> {
        device::with_device(session.device.clone(), |device| {
            let mut rows: Vec<MemoryRow> = Vec::new();
            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::Persistent,
                MemoryHandleType::Persistent,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, handle).map(Some),
            )?;
            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::Transient,
                MemoryHandleType::Transient,
                auth_args,
                |_, device, handle, _| Self::fetch_details(device, handle).map(Some),
            )?;
            Self::fetch_rows(
                session,
                device,
                &mut rows,
                TpmHt::LoadedSession,
                MemoryHandleType::Session,
                auth_args,
                |_, _, handle, _| {
                    let ht = TpmHt::try_from(*handle)
                        .map_err(|_| CommandError::InvalidInput(handle.to_string()))?;
                    let detail = if ht == TpmHt::HmacSession {
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
                |session, device, handle, auth_args| {
                    if let Some(handle_val) = handle.value() {
                        if !(0x01C0_0000..=0x01C0_FFFF).contains(&handle_val) {
                            return Ok(None);
                        }

                        let cert_bytes =
                            match Self::read_nv_index(session, device, handle_val, auth_args) {
                                Ok(bytes) => bytes,
                                Err(CommandError::Device(DeviceError::TpmRc(_))) => {
                                    return Ok(None);
                                }
                                Err(e) => return Err(e),
                            };

                        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != 0x30 {
                            return Ok(None);
                        }
                        return Ok(Some(Memory::fetch_alg_name(&cert_bytes)?));
                    }
                    Ok(None)
                },
            )?;
            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));

            print_table(session, &rows)?;
            Ok(())
        })
    }

    fn read_nv_index(
        session: &mut TaskState,
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
        let (resp, _) = session.execute(device, &nv_read_public_cmd, &[], &[])?;
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

        let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
        let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;
        let auths_cow = auth_args.auths(false);
        let effective_auths: &[Auth] = if needs_auth { auths_cow.as_ref() } else { &[] };
        let handles = [auth_handle_val];

        while offset < data_size {
            let chunk_size = std::cmp::min(max_read_size, data_size - offset);
            let nv_read_cmd = TpmNvReadCommand {
                auth_handle: auth_handle_val.into(),
                nv_index: handle.into(),
                size: u16::try_from(chunk_size)?,
                offset: u16::try_from(offset)?,
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
        device: &mut Device,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        let cert_bytes = Self::read_nv_index(session, device, handle, auth_args)?;

        if cert_bytes.is_empty() {
            log::warn!("{handle:08x}: no certificate");
            return Ok(());
        }

        let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
        writeln!(session.writer, "{pem_cert}")?;

        Ok(())
    }

    fn fetch_rows<F>(
        session: &mut TaskState,
        device: &mut Device,
        rows: &mut Vec<MemoryRow>,
        class: TpmHt,
        display_type: MemoryHandleType,
        auth_args: &AuthArgs,
        mut get_details: F,
    ) -> Result<(), CommandError>
    where
        F: FnMut(
            &mut TaskState,
            &mut Device,
            &TpmHandleRef,
            &AuthArgs,
        ) -> Result<Option<String>, CommandError>,
    {
        for handle in device.fetch_handles((class as u32) << 24)? {
            if let Some(handle_val) = handle.value() {
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
        }
        Ok(())
    }

    fn fetch_details(device: &mut Device, handle: &TpmHandleRef) -> Result<String, CommandError> {
        if let Some(handle_val) = handle.value() {
            let tpm_handle = TpmHandle(handle_val);
            let (public, _) = device.read_public(tpm_handle)?;
            Ok(crate::alg::format_alg_from_public(&public))
        } else {
            Err(CommandError::PatternNotAllowed(handle.to_string()))
        }
    }

    fn fetch_hash_alg(oid_nid: Nid) -> Result<Hash, CommandError> {
        match oid_nid {
            Nid::SHA1WITHRSAENCRYPTION => Ok(Hash::Sha1),
            Nid::ECDSA_WITH_SHA256 | Nid::SHA256WITHRSAENCRYPTION => Ok(Hash::Sha256),
            Nid::ECDSA_WITH_SHA384 | Nid::SHA384WITHRSAENCRYPTION => Ok(Hash::Sha384),
            Nid::ECDSA_WITH_SHA512 | Nid::SHA512WITHRSAENCRYPTION => Ok(Hash::Sha512),
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
                    Some(Nid::X9_62_PRIME256V1) => EccCurve::NistP256,
                    Some(Nid::SECP384R1) => EccCurve::NistP384,
                    Some(Nid::SECP521R1) => EccCurve::NistP521,
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
