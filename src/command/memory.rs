// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{print_table, AuthArgs, CommandError},
    task::{Auth, TaskState},
};
use clap::Args;
use openssl::{nid::Nid, pkey::Id as PKeyId, x509::X509};
use pem;
use std::collections::HashMap;
use strum::Display;
use tabled::Tabled;
use tpm2_crypto::{tpm_make_name, TpmEllipticCurve, TpmHash, TpmPublicTemplate};
use tpm2_device::{with_device, TpmDevice, TpmDeviceError};
use tpm2_policy_language::TpmPolicyExpression;
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint16, TpmUint32},
    data::{
        Tpm2bName, TpmAlgId, TpmCc, TpmHt, TpmPt, TpmRcBase, TpmRh, TpmaNv, TpmsContext,
        TpmtPublic, TpmuPublicParms,
    },
    frame::{TpmAuthCommands, TpmCommand, TpmNvReadCommand, TpmNvReadPublicCommand},
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
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory or inspects a single handle.")]
pub struct Memory {
    /// TPM handle as a eight characters hex string.
    pub handle: Option<crate::handle::Handle>,

    /// Do not use cache. Show physical handles in transient range.
    #[arg(long)]
    pub no_cache: bool,

    /// Show policy expression for the given handle.
    #[arg(short = 'p', long = "policy")]
    pub policy: bool,

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
                self.policy,
            )
        } else {
            Self::list_all_memory(session, writer, &self.auth_args, is_tty, self.no_cache)
        }
    }
}

impl Memory {
    fn refresh_key(device: &mut TpmDevice, context: TpmsContext) -> Result<bool, TpmDeviceError> {
        match device.load_context(context) {
            Ok(handle) => match device.flush_context(handle) {
                Ok(()) => Ok(true),
                Err(e) => Err(e),
            },
            Err(TpmDeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn refresh_cache(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
    ) -> Result<(), CommandError> {
        let vhandles: Vec<u32> = task_state.cache.key_iter().map(|(h, _)| *h).collect();
        let mut errors: Vec<CommandError> = Vec::new();
        let mut handles_to_remove = Vec::new();

        for &vhandle in &vhandles {
            if (vhandle >> 24) as u8 == TpmHt::Persistent as u8 {
                continue;
            }

            if let Some(key) = task_state.cache.find_by_handle(TpmUint32(vhandle)) {
                match Memory::refresh_key(device, key.context().clone()) {
                    Ok(true) => {
                        task_state.cache.mark_dirty(vhandle);
                    }
                    Ok(false) => handles_to_remove.push(vhandle),
                    Err(e) => {
                        log::warn!("{vhandle:08x}: {e}");
                        errors.push(e.into());
                        handles_to_remove.push(vhandle);
                    }
                }
            }
        }

        for vhandle in handles_to_remove {
            if let Err(e) = task_state.cache.remove(vhandle) {
                log::error!("{vhandle:08x}: {e}");
                errors.push(e.into());
            }
        }

        if let Some(err) = errors.into_iter().next() {
            Err(err)
        } else {
            Ok(())
        }
    }

    fn inspect_handle(
        session: &mut TaskState,
        writer: &mut dyn std::io::Write,
        handle_val: u32,
        handle_str: String,
        auth_args: &AuthArgs,
        show_policy: bool,
    ) -> Result<(), CommandError> {
        with_device(session.device.clone(), |device| {
            if (handle_val >> 24) == (TpmHt::NvIndex as u32) {
                Self::inspect_nv_index(session, device, writer, handle_val, auth_args)
            } else if show_policy {
                let key = session
                    .cache
                    .find_by_handle(TpmUint32(handle_val))
                    .ok_or(CommandError::UnknownHandle(handle_str))?;

                if let Some(policy_str) = Self::format_policy(key.policy()) {
                    writeln!(writer, "{policy_str}")?;
                }
                Ok(())
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
        no_cache: bool,
    ) -> Result<(), CommandError> {
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
            Self::fetch_nv_rows(session, device, auth_args, &mut rows)?;

            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
            print_table(&rows, writer, is_tty)?;

            Ok(())
        })
    }

    fn fetch_persistent_rows(
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<(), CommandError> {
        for handle in device.fetch_handles(TpmHt::Persistent)? {
            let TpmUint32(handle_val) = handle;
            let (public, _) = device.read_public(handle)?;
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
    ) -> Result<(), CommandError> {
        for handle in device.fetch_handles(TpmHt::Transient)? {
            let TpmUint32(handle_val) = handle;
            let (public, _) = device.read_public(handle)?;
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
    ) -> Result<(), CommandError> {
        Self::refresh_cache(session, device)?;

        let mut name_to_handle: HashMap<Tpm2bName, String> = HashMap::new();
        if let Ok(handles) = device.fetch_handles(TpmHt::Persistent) {
            for handle in handles {
                if let Ok((_, name)) = device.read_public(handle) {
                    name_to_handle.insert(name, format!("{:08x}", handle.0));
                }
            }
        }
        for (vhandle, key) in session.cache.key_iter() {
            if let Ok(name) = tpm_make_name(key.public()) {
                name_to_handle.insert(name, format!("{vhandle:08x}"));
            }
        }

        for (vhandle, key) in session.cache.key_iter() {
            if (vhandle >> 24) as u8 == TpmHt::Persistent as u8 {
                continue;
            }

            let parent = key.parent();
            let parent_str = if parent.object_type == TpmAlgId::Null {
                match key.context().hierarchy {
                    TpmRh::Owner => "owner".to_string(),
                    TpmRh::Platform => "platform".to_string(),
                    TpmRh::Endorsement => "endorsement".to_string(),
                    TpmRh::Null => "null".to_string(),
                    _ => "unknown".to_string(),
                }
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
                |_| Ok(TpmHash::from(key.public().object_type).to_string()),
                String::try_from,
            )?;

            rows.push(MemoryRow {
                handle: format!("{:08x}", key.handle().0),
                class: MemoryHandleType::Transient.to_string(),
                details: format!("{parent_str}:{details}"),
            });
        }
        Ok(())
    }

    fn fetch_session_rows(
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<(), CommandError> {
        for handle in device.fetch_handles(TpmHt::LoadedSession)? {
            let TpmUint32(handle_val) = handle;
            let ht = (handle_val >> 24) as u8;

            let detail = if ht == TpmHt::HmacSession as u8 {
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

    fn fetch_saved_session_rows(
        device: &mut TpmDevice,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<(), CommandError> {
        for handle in device.fetch_handles(TpmHt::SavedSession)? {
            let TpmUint32(handle_val) = handle;
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
        auth_args: &AuthArgs,
        rows: &mut Vec<MemoryRow>,
    ) -> Result<(), CommandError> {
        for handle in device.fetch_handles(TpmHt::NvIndex)? {
            let TpmUint32(handle_val) = handle;
            let details = Self::fetch_nv_details(session, device, handle, auth_args);
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

    fn read_nv_index(
        session: &mut TaskState,
        device: &mut TpmDevice,
        handle: u32,
        auth_args: &AuthArgs,
    ) -> Result<Vec<u8>, CommandError> {
        let max_read_size = device
            .get_tpm_property(TpmPt::NvBufferMax)
            .unwrap_or(TpmUint32(0));

        if max_read_size.value() == 0 {
            return Ok(Vec::new());
        }

        let nv_read_public_cmd = TpmNvReadPublicCommand {
            handles: [handle.into()],
        };
        let (resp, _) = session.execute(device, &nv_read_public_cmd, &[])?;
        let read_public_resp = resp
            .NvReadPublic()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvReadPublic))?;
        let nv_public = read_public_resp.nv_public;
        let data_size = nv_public.data_size;

        if data_size.value() == 0 {
            return Ok(Vec::new());
        }

        let auth_handle_val = Self::resolve_nv_auth(nv_public.attributes, handle);

        let mut cert_bytes = Vec::with_capacity(data_size.value() as usize);
        let mut offset: usize = 0;

        let flags_to_check = TpmaNv::AUTHREAD | TpmaNv::OWNERREAD | TpmaNv::PPREAD;
        let needs_auth = (nv_public.attributes.bits() & flags_to_check.bits()) != 0;
        let auth_map = auth_args.build_auth_map();
        let auth = auth_map
            .get(&TpmUint32(auth_handle_val))
            .cloned()
            .unwrap_or_default();
        let effective_auths: &[Auth] = if needs_auth { &[auth] } else { &[] };

        while offset < data_size.value() as usize {
            let chunk_size = std::cmp::min(
                max_read_size.value() as usize,
                data_size.value() as usize - offset,
            );
            let nv_read_cmd = TpmNvReadCommand {
                size: TpmUint16(u16::try_from(chunk_size)?),
                offset: TpmUint16(u16::try_from(offset)?),
                handles: [auth_handle_val.into(), handle.into()],
            };

            let (resp, _) = session.execute(device, &nv_read_cmd, effective_auths)?;

            let read_resp = resp
                .NvRead()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::NvRead))?;

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
        auth_args: &AuthArgs,
    ) -> Result<(), CommandError> {
        let cert_bytes = Self::read_nv_index(session, device, handle, auth_args)?;

        if cert_bytes.is_empty() {
            log::warn!("{handle:08x}: empty");
            return Ok(());
        }

        if cert_bytes[0] == 0x30 {
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
        auth_args: &AuthArgs,
    ) -> String {
        let TpmUint32(handle_val) = handle;

        let Ok(cert_bytes) = Self::read_nv_index(session, device, handle_val, auth_args) else {
            return String::new();
        };

        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != 0x30 {
            return String::new();
        }

        Memory::fetch_alg_name(&cert_bytes).unwrap_or_default()
    }

    fn fetch_hash_alg(oid_nid: Nid) -> Result<TpmHash, CommandError> {
        match oid_nid {
            Nid::SHA1WITHRSAENCRYPTION => Ok(TpmHash::Sha1),
            Nid::ECDSA_WITH_SHA256 | Nid::SHA256WITHRSAENCRYPTION => Ok(TpmHash::Sha256),
            Nid::ECDSA_WITH_SHA384 | Nid::SHA384WITHRSAENCRYPTION => Ok(TpmHash::Sha384),
            Nid::ECDSA_WITH_SHA512 | Nid::SHA512WITHRSAENCRYPTION => Ok(TpmHash::Sha512),
            _ => Err(CommandError::UnsupportedHashAlgorithm),
        }
    }

    fn fetch_alg_name(cert_der: &[u8]) -> Result<String, CommandError> {
        let cert = X509::from_der(cert_der).map_err(|e| {
            CommandError::InvalidInput(format!("DER certificate decode failed: {e}"))
        })?;

        let sig_nid = cert.signature_algorithm().object().nid();
        let sig_alg = Self::fetch_hash_alg(sig_nid)?;
        let sig_alg_str = sig_alg.to_string();

        let pkey = cert
            .public_key()
            .map_err(|_| CommandError::InvalidPublicKey)?;
        match pkey.id() {
            PKeyId::RSA => {
                let rsa = pkey.rsa().map_err(|_| CommandError::InvalidRsaParameters)?;
                let key_bits = u16::try_from(rsa.size() * 8)?;
                Ok(format!("rsa-{key_bits}:{sig_alg_str}"))
            }
            PKeyId::EC => {
                let ec_key = pkey
                    .ec_key()
                    .map_err(|_| CommandError::InvalidEccParameters)?;
                let curve_nid = ec_key.group().curve_name();
                let curve = match curve_nid {
                    Some(Nid::X9_62_PRIME256V1) => TpmEllipticCurve::NistP256,
                    Some(Nid::SECP384R1) => TpmEllipticCurve::NistP384,
                    Some(Nid::SECP521R1) => TpmEllipticCurve::NistP521,
                    _ => {
                        return Err(CommandError::UnsupportedKeyAlgorithm);
                    }
                };
                Ok(format!("ecc-{curve}:{sig_alg_str}"))
            }
            _ => Err(CommandError::UnsupportedKeyAlgorithm),
        }
    }

    fn format_policy(policy: &[Box<dyn VtpmPolicyCommand>]) -> Option<String> {
        if policy.is_empty() {
            return None;
        }

        let mut command_list: Vec<(TpmCommand, TpmAuthCommands)> = Vec::with_capacity(policy.len());

        for vtpm_cmd in policy {
            match vtpm_cmd.to_command() {
                Ok(cmd) => {
                    command_list.push((cmd, TpmAuthCommands::new()));
                }
                Err(_) => {
                    return None;
                }
            }
        }

        match TpmPolicyExpression::from_command_list(&command_list) {
            Ok(expr) => Some(expr.to_string()),
            Err(_) => None,
        }
    }
}

fn public_to_template(public: &TpmtPublic) -> Result<TpmPublicTemplate, CommandError> {
    match public.object_type {
        TpmAlgId::Rsa => {
            if let TpmuPublicParms::Rsa(parms) = &public.parameters {
                Ok(TpmPublicTemplate::new()
                    .with_object_type(TpmAlgId::Rsa)
                    .with_key_bits(parms.key_bits)
                    .with_name_alg(public.name_alg))
            } else {
                Err(CommandError::InvalidRsaParameters)
            }
        }
        TpmAlgId::Ecc => {
            if let TpmuPublicParms::Ecc(parms) = &public.parameters {
                Ok(TpmPublicTemplate::new()
                    .with_object_type(TpmAlgId::Ecc)
                    .with_curve_id(parms.curve_id)
                    .with_name_alg(public.name_alg))
            } else {
                Err(CommandError::InvalidEccParameters)
            }
        }
        TpmAlgId::KeyedHash => Ok(TpmPublicTemplate::new()
            .with_object_type(TpmAlgId::KeyedHash)
            .with_name_alg(public.name_alg)),
        _ => Err(CommandError::UnsupportedKeyAlgorithm),
    }
}
