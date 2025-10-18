// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{print_table, CommandError},
    device::{self, Device},
    job::Job,
    key::format_alg_from_public,
    x509::get_algorithm,
};
use argh::FromArgs;
use strum::Display;
use tabled::Tabled;
use tpm2_protocol::data::{TpmHt, TpmPt};

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

/// Lists objects inside TPM memory.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "memory", note = "Lists objects inside TPM memory")]
pub struct Memory {}

impl Memory {
    /// Fetches handles of a specific type and adds them as rows to the table.
    ///
    /// This helper function abstracts the repetitive logic of querying handles,
    /// processing each one to get its details, and adding it to the final list.
    fn fetch_rows<F>(
        device: &mut Device,
        rows: &mut Vec<MemoryRow>,
        handle_type_to_query: u32,
        display_type: MemoryHandleType,
        mut get_details: F,
    ) -> Result<(), CommandError>
    where
        F: FnMut(&mut Device, u32) -> Result<String, CommandError>,
    {
        for handle in device.get_all_handles(handle_type_to_query << 24)? {
            match get_details(device, handle) {
                Ok(details) => {
                    rows.push(MemoryRow {
                        handle: format!("{handle:08x}"),
                        handle_type: display_type.to_string(),
                        details,
                    });
                }
                Err(e) => {
                    log::debug!("Could not retrieve details for handle {handle:08x}: {e}");
                }
            }
        }
        Ok(())
    }

    /// Fetches the public part of a key and formats its algorithm details.
    fn fetch_details(device: &mut Device, handle: u32) -> Result<String, CommandError> {
        let (public, _) = device.read_public(handle.into())?;
        Ok(format_alg_from_public(&public))
    }
}

impl SubCommand for Memory {
    fn run(&self, job: &mut Job, plain: bool) -> Result<(), CommandError> {
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
                TpmHt::HmacSession as u32,
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
                TpmHt::PolicySession as u32,
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
                        let nv_auth = Auth::Password(Vec::new());
                        let cert_bytes = job
                            .read_certificate(
                                device,
                                std::slice::from_ref(&nv_auth),
                                handle,
                                max_read_size,
                            )?
                            .ok_or(CommandError::InvalidInput("No certificate data".into()))?;
                        if cert_bytes.is_empty() || u32::from(cert_bytes[0]) != (0x30) {
                            return Err(CommandError::InvalidInput("Not a DER certificate".into()));
                        }
                        Ok(get_algorithm(&cert_bytes)?)
                    },
                )?;
            }
            rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
            print_table(&mut job.key_cache.writer, rows, plain)?;
            Ok(())
        })
    }
}
