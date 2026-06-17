// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::print_table,
    error::device_err,
    handle::handle_type,
    response::parse_response,
    task::{Auth, TaskState},
};
use anyhow::{Result, anyhow};
use argh::FromArgs;
use openssl::{nid::Nid, pkey::Id as PKeyId, x509::X509};
use pem;
use std::collections::HashMap;
use strum::Display;
use tabled::Tabled;
use tpm2_crypto::{TpmEllipticCurve, TpmHash, TpmPublicTemplate, tpm_make_name};
use tpm2_device::{TpmDevice, TpmDeviceError, with_device};
use tpm2_policy_language::TpmPolicyExpression;
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint16, TpmUint32},
    data::{
        Tpm2bName, Tpm2bNvPublic, TpmAlgId, TpmHt, TpmPt, TpmRcBase, TpmRh, TpmaNv, TpmtPublic,
    },
    frame::{
        TpmCommandValue as TpmCommand, TpmNvReadCommand, TpmNvReadPublicCommand,
        TpmNvReadPublicResponse, TpmNvReadResponse,
    },
};
use tpm2_vtpm::VtpmPolicyCommand;

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[strum(serialize_all = "kebab-case")]
enum MemoryHandleType {
    Transient,
    Persistent,
    Session,
    NvIndex,
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
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "memory", help_triggers("-h", "--help", "help"))]
pub struct Memory {
    /// TPM handle as a eight characters hex string
    #[argh(positional)]
    pub handle: Option<crate::handle::Handle>,

    /// do not use cache; show physical handles in transient range
    #[argh(switch)]
    pub no_cache: bool,
}

impl Task for Memory {
    fn run(
        &self,
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        is_tty: bool,
    ) -> Result<()> {
        if let Some(handle) = self.handle {
            let handle_val = handle
                .require_value()
                .map_err(|_| anyhow!("handle pattern not allowed: {handle}"))?;
            Self::inspect_handle(session, writer, handle_val, &handle.to_string())
        } else {
            Self::list_all_memory(session, writer, is_tty, self.no_cache)
        }
    }
}

impl Memory {
    fn inspect_handle(
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        handle_val: u32,
        handle_str: &str,
    ) -> Result<()> {
        with_device(session.device.clone(), |device| -> Result<()> {
            if handle_type(handle_val) == Some(TpmHt::NvIndex) {
                Self::inspect_nv_index(session, device, writer, handle_val)
            } else {
                Self::inspect_object(session, device, writer, handle_val, handle_str)
            }
        })
    }

    fn hierarchy_name(rh: TpmRh) -> &'static str {
        match rh {
            TpmRh::Owner => "owner",
            TpmRh::Platform => "platform",
            TpmRh::Endorsement => "endorsement",
            TpmRh::Null => "null",
            _ => "unknown",
        }
    }

    fn resolve_hierarchy_str(rh: Option<TpmRh>, handle_val: u32) -> &'static str {
        if let Some(h) = rh {
            Self::hierarchy_name(h)
        } else if handle_val >= 0x8180_0000 {
            "platform"
        } else if handle_val >= 0x8100_0000 {
            "owner"
        } else {
            "unknown"
        }
    }

    fn format_algorithm(public: &TpmtPublic) -> String {
        public_to_template(public).map_or_else(
            |_| format!("{:?}", public.object_type),
            |t| t.try_into().unwrap_or_else(|_| "unknown".to_string()),
        )
    }

    fn resolve_parent_str(
        session: &TaskState,
        device: &mut TpmDevice,
        parent_public: &TpmtPublic,
        hierarchy_str: &str,
    ) -> String {
        if parent_public.object_type == TpmAlgId::Null {
            return hierarchy_str.to_string();
        }

        let mut name_to_handle = HashMap::new();

        if let Ok(persistent_map) = crate::command::common::fetch_persistent_names(device) {
            for (handle, name) in persistent_map {
                name_to_handle.insert(name, format!("{:08x}", handle.value()));
            }
        }

        for (vhandle, k) in session.cache.key_iter() {
            if let Ok(name) = tpm_make_name(k.public()) {
                name_to_handle.insert(name, format!("{vhandle:08x}"));
            }
        }

        if let Ok(pname) = tpm_make_name(parent_public) {
            name_to_handle
                .get(&pname)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "error".to_string()
        }
    }

    fn inspect_object(
        session: &mut TaskState,
        device: &mut TpmDevice,
        writer: &mut dyn std::io::Write,
        handle_val: u32,
        handle_str: &str,
    ) -> Result<()> {
        let handle = TpmUint32::new(handle_val);

        let (public, hierarchy_str, parent_str, policy_str) = if let Some(key) =
            session.cache.find_by_handle(handle)
        {
            let public = key.public();
            let hierarchy_str =
                Self::resolve_hierarchy_str(Some(key.context().hierarchy), handle_val);
            let parent_str = Self::resolve_parent_str(session, device, key.parent(), hierarchy_str);
            let policy_str = Self::format_policy(key.policy())
                .unwrap_or_else(|| hex::encode(public.auth_policy));
            (public.clone(), hierarchy_str, parent_str, policy_str)
        } else {
            match device.read_public(handle) {
                Ok((public, _)) => {
                    let hierarchy_str = Self::resolve_hierarchy_str(None, handle_val);
                    let policy_str = hex::encode(public.auth_policy);
                    (public, hierarchy_str, "unknown".to_string(), policy_str)
                }
                Err(TpmDeviceError::TpmRc(rc))
                    if rc.base() == TpmRcBase::Handle || rc.base() == TpmRcBase::ReferenceH0 =>
                {
                    return Err(anyhow!("unknown handle: {handle_str}"));
                }
                Err(e) => return Err(device_err(e)),
            }
        };

        let alg_str = Self::format_algorithm(&public);

        writeln!(writer, "algorithm: {alg_str}")?;
        writeln!(writer, "hierarchy: {hierarchy_str}")?;
        writeln!(writer, "parent: {parent_str}")?;
        writeln!(
            writer,
            "attributes: {:08x}",
            public.object_attributes.bits()
        )?;
        if !policy_str.is_empty() {
            writeln!(writer, "policy: {policy_str}")?;
        }

        Ok(())
    }

    fn list_all_memory(
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        is_tty: bool,
        no_cache: bool,
    ) -> Result<()> {
        with_device(session.device.clone(), |device| {
            let mut rows: Vec<MemoryRow> = Vec::new();

            Self::fetch_persistent_rows(device, &mut rows)?;

            if no_cache {
                Self::fetch_device_transient_rows(device, &mut rows)?;
            } else {
                Self::fetch_cached_transient_rows(session, device, &mut rows)?;
            }

            Self::fetch_session_rows(device, &mut rows)?;
            Self::fetch_saved_session_rows(device, &mut rows)?;
            Self::fetch_nv_rows(session, device, &mut rows)?;

            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
            print_table(&rows, writer, is_tty)?;

            Ok(())
        })
    }

    fn fetch_persistent_rows(device: &mut TpmDevice, rows: &mut Vec<MemoryRow>) -> Result<()> {
        for handle in device
            .fetch_handles(TpmHt::Persistent)
            .map_err(device_err)?
        {
            let handle_val = handle.value();
            let (public, _) = device.read_public(handle).map_err(device_err)?;
            let details: String = public_to_template(&public)?.try_into()?;

            let hierarchy = if handle_val >= 0x8180_0000 {
                "platform"
            } else {
                "owner"
            };

            rows.push(MemoryRow {
                handle: format!("{handle_val:08x}"),
                class: MemoryHandleType::Persistent.to_string(),
                details: format!("{hierarchy}:{details}"),
            });
        }
        Ok(())
    }

    fn fetch_device_transient_rows(
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<()> {
        for handle in device.fetch_handles(TpmHt::Transient).map_err(device_err)? {
            let handle_val = handle.value();
            let (public, _) = device.read_public(handle).map_err(device_err)?;
            let details: String = public_to_template(&public)?.try_into()?;

            rows.push(MemoryRow {
                handle: format!("{handle_val:08x}"),
                class: MemoryHandleType::Transient.to_string(),
                details: details.clone(),
            });
        }
        Ok(())
    }

    fn fetch_cached_transient_rows(
        session: &mut TaskState,
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<()> {
        session.refresh_cache(device)?;

        let mut name_to_handle: HashMap<Tpm2bName, String> = HashMap::new();
        if let Ok(persistent_map) = crate::command::common::fetch_persistent_names(device) {
            for (handle, name) in persistent_map {
                name_to_handle.insert(name, format!("{:08x}", handle.value()));
            }
        }

        for (vhandle, key) in session.cache.key_iter() {
            if let Ok(name) = tpm_make_name(key.public()) {
                name_to_handle.insert(name, format!("{vhandle:08x}"));
            }
        }

        for (vhandle, key) in session.cache.key_iter() {
            if handle_type(*vhandle) == Some(TpmHt::Persistent) {
                continue;
            }

            let parent = key.parent();
            let parent_str = if parent.object_type == TpmAlgId::Null {
                Self::hierarchy_name(key.context().hierarchy).to_string()
            } else {
                match tpm_make_name(parent) {
                    Ok(pname) => name_to_handle
                        .get(&pname)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    Err(_) => "error".to_string(),
                }
            };

            let details = public_to_template(key.public()).map_or_else(
                |_| TpmHash::try_from(key.public().object_type).map(|hash| hash.to_string()),
                String::try_from,
            )?;

            rows.push(MemoryRow {
                handle: format!("{:08x}", key.handle().value()),
                class: MemoryHandleType::Transient.to_string(),
                details: format!("{parent_str}:{details}"),
            });
        }
        Ok(())
    }

    fn fetch_session_rows(device: &mut TpmDevice, rows: &mut Vec<MemoryRow>) -> Result<()> {
        for handle in device
            .fetch_handles(TpmHt::LoadedSession)
            .map_err(device_err)?
        {
            let handle_val = handle.value();

            let detail = if handle_type(handle_val) == Some(TpmHt::HmacSession) {
                "hmac"
            } else {
                "policy"
            };

            rows.push(MemoryRow {
                handle: format!("{handle_val:08x}"),
                class: MemoryHandleType::Session.to_string(),
                details: detail.to_string(),
            });
        }
        Ok(())
    }

    fn fetch_saved_session_rows(device: &mut TpmDevice, rows: &mut Vec<MemoryRow>) -> Result<()> {
        for handle in device
            .fetch_handles(TpmHt::SavedSession)
            .map_err(device_err)?
        {
            let handle_val = handle.value();
            rows.push(MemoryRow {
                handle: format!("{handle_val:08x}"),
                class: MemoryHandleType::Session.to_string(),
                details: "saved".to_string(),
            });
        }
        Ok(())
    }

    fn fetch_nv_rows(
        session: &mut TaskState,
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<()> {
        for handle in device.fetch_handles(TpmHt::NvIndex).map_err(device_err)? {
            let handle_val = handle.value();
            let details = Self::fetch_nv_details(session, device, handle);
            rows.push(MemoryRow {
                handle: format!("{handle_val:08x}"),
                class: MemoryHandleType::NvIndex.to_string(),
                details,
            });
        }
        Ok(())
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

    fn read_nv_public(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: u32,
    ) -> Result<Tpm2bNvPublic> {
        let nv_read_public_cmd = TpmNvReadPublicCommand {
            handles: [handle.into()],
        };
        let resp = session.execute(device, &nv_read_public_cmd, &[])?;
        let read_public_resp = parse_response::<TpmNvReadPublicResponse>(resp)?;
        Ok(read_public_resp.nv_public)
    }

    fn read_nv_index(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: u32,
    ) -> Result<Vec<u8>> {
        let max_read_size = device
            .get_tpm_property(TpmPt::NvBufferMax)
            .map_err(device_err)?;
        let nv_public = Self::read_nv_public(session, device, handle)?;
        let data_size = nv_public.data_size.value() as usize;

        if data_size == 0 {
            return Ok(Vec::new());
        }

        let auth_handle_val = Self::resolve_nv_auth(nv_public.attributes, handle);

        let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
        let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;

        let auth = session
            .auth_map
            .get(&TpmUint32::new(auth_handle_val))
            .cloned()
            .unwrap_or_default();

        let effective_auths: &[Auth] = if needs_auth {
            std::slice::from_ref(&auth)
        } else {
            &[]
        };

        let mut cert_bytes = Vec::with_capacity(data_size);
        let mut offset: usize = 0;

        while offset < data_size {
            let chunk_size = std::cmp::min(max_read_size.value() as usize, data_size - offset);
            let nv_read_cmd = TpmNvReadCommand {
                size: TpmUint16::new(u16::try_from(chunk_size)?),
                offset: TpmUint16::new(u16::try_from(offset)?),
                handles: [auth_handle_val.into(), handle.into()],
            };

            let resp = session.execute(device, &nv_read_cmd, effective_auths)?;
            let read_resp = parse_response::<TpmNvReadResponse>(resp)?;

            let received_len = read_resp.data.len();
            if received_len == 0 {
                break;
            }

            cert_bytes.extend_from_slice(read_resp.data.as_ref());
            offset += received_len;
        }
        Ok(cert_bytes)
    }

    fn inspect_nv_index(
        session: &mut TaskState,
        device: &mut TpmDevice,
        writer: &mut dyn std::io::Write,
        handle: u32,
    ) -> Result<()> {
        let cert_bytes = Self::read_nv_index(session, device, handle)?;

        if cert_bytes.is_empty() {
            log::warn!("{handle:08x}: empty");
            return Ok(());
        }

        if X509::from_der(&cert_bytes).is_ok() {
            let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
            writeln!(writer, "{pem_cert}")?;
        } else {
            writeln!(writer, "{}", hex::encode(&cert_bytes))?;
        }

        Ok(())
    }

    fn fetch_nv_details(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: TpmHandle,
    ) -> String {
        let handle_val = handle.value();

        let Ok(cert_bytes) = Self::read_nv_index(session, device, handle_val) else {
            return String::new();
        };

        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != 0x30 {
            return String::new();
        }

        Memory::fetch_alg_name(&cert_bytes).unwrap_or_default()
    }

    fn fetch_hash_alg(oid_nid: Nid) -> Result<TpmHash> {
        match oid_nid {
            Nid::SHA1WITHRSAENCRYPTION => Ok(TpmHash::Sha1),
            Nid::ECDSA_WITH_SHA256 | Nid::SHA256WITHRSAENCRYPTION => Ok(TpmHash::Sha256),
            Nid::ECDSA_WITH_SHA384 | Nid::SHA384WITHRSAENCRYPTION => Ok(TpmHash::Sha384),
            Nid::ECDSA_WITH_SHA512 | Nid::SHA512WITHRSAENCRYPTION => Ok(TpmHash::Sha512),
            _ => Err(anyhow!("unsupported hash algorithm")),
        }
    }

    fn fetch_alg_name(cert_der: &[u8]) -> Result<String> {
        let cert = X509::from_der(cert_der)
            .map_err(|e| anyhow!("invalid input: DER certificate decode failed: {e}"))?;

        let sig_nid = cert.signature_algorithm().object().nid();
        let sig_alg = Self::fetch_hash_alg(sig_nid)?;
        let sig_alg_str = sig_alg.to_string();

        let pkey = cert
            .public_key()
            .map_err(|_| anyhow!("invalid certificate"))?;
        match pkey.id() {
            PKeyId::RSA => {
                let rsa = pkey.rsa().map_err(|_| anyhow!("invalid RSA parameters"))?;
                let key_bits = u16::try_from(rsa.size() * 8)?;
                Ok(format!("rsa-{key_bits}:{sig_alg_str}"))
            }
            PKeyId::EC => {
                let ec_key = pkey
                    .ec_key()
                    .map_err(|_| anyhow!("invalid ECC parameters"))?;
                let curve_nid = ec_key.group().curve_name();
                let curve = match curve_nid {
                    Some(Nid::X9_62_PRIME256V1) => TpmEllipticCurve::NistP256,
                    Some(Nid::SECP384R1) => TpmEllipticCurve::NistP384,
                    Some(Nid::SECP521R1) => TpmEllipticCurve::NistP521,
                    _ => {
                        return Err(anyhow!("unsupported key algorithm"));
                    }
                };
                Ok(format!("ecc-{curve}:{sig_alg_str}"))
            }
            _ => Err(anyhow!("unsupported key algorithm")),
        }
    }

    fn format_policy(policy: &[Box<dyn VtpmPolicyCommand>]) -> Option<String> {
        if policy.is_empty() {
            return None;
        }

        let mut command_list: Vec<TpmCommand> = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            match vtpm_cmd.to_command() {
                Ok(cmd) => command_list.push(cmd),
                Err(_) => return None,
            }
        }

        match TpmPolicyExpression::from_commands(&command_list) {
            Ok(expr) => Some(expr.to_string()),
            Err(_) => None,
        }
    }
}

fn public_to_template(public: &TpmtPublic) -> Result<TpmPublicTemplate> {
    let name_alg = TpmHash::try_from(public.name_alg)?;
    Ok(TpmPublicTemplate::new()
        .with_public(public.unique.clone(), public.parameters)?
        .with_name_alg(name_alg))
}
