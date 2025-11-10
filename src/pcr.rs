//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

//! Abstractions and logic for handling Platform Configuration Registers (PCRs).

use crate::{
    command::CommandError,
    device::{Device, DeviceError},
    policy::{visit_pcr_expressions_mut, PolicyError},
    session::{Session, SessionError},
};
use std::collections::HashMap;
use thiserror::Error;
use tpm2_crypto::{Error as CryptoError, Hash};
use tpm2_policy_language::Expression;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmCc, TpmlPcrSelection, TpmsPcrSelect, TpmsPcrSelection,
        TpmuCapabilities,
    },
    frame::TpmPcrReadCommand,
    TpmProtocolError,
};

#[derive(Debug, Error)]
pub enum PcrError {
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid PCR selection: {0}")]
    InvalidPcrSelection(String),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("session: {0}")]
    Session(#[from] SessionError),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
}

/// Represents the state of a single PCR register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcr {
    pub bank: TpmAlgId,
    pub index: u32,
    pub value: Vec<u8>,
}

/// Represents the properties of a single PCR bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrBank {
    pub alg: TpmAlgId,
    pub count: usize,
}

/// Discovers the list of available PCR banks and their sizes from the TPM.
///
/// # Errors
///
/// Returns a `PcrError` if the TPM capability query fails or if the TPM reports
/// no active PCR banks.
pub fn pcr_get_bank_list(device: &mut Device) -> Result<Vec<PcrBank>, PcrError> {
    let (_, cap_data) = device.get_capability_page(TpmCap::Pcrs, 0, 1)?;
    let mut banks = Vec::new();
    if let TpmuCapabilities::Pcrs(pcrs) = cap_data.data {
        for bank in pcrs.iter() {
            banks.push(PcrBank {
                alg: bank.hash,
                count: bank.pcr_select.len() * 8,
            });
        }
    }
    if banks.is_empty() {
        return Err(PcrError::InvalidPcrSelection(
            "TPM reported no active PCR banks.".to_string(),
        ));
    }
    banks.sort_by_key(|b| b.alg);
    Ok(banks)
}

/// Merges multiple `TpmsPcrSelection` structs into a single `TpmlPcrSelection`.
///
/// This is used to combine all PCRs required by a policy into a single read.
///
/// # Errors
///
/// Returns a `PcrError` if bitmask operations fail.
pub(crate) fn merge_pcr_selections(
    selections: &[TpmsPcrSelection],
    banks: &[PcrBank],
) -> Result<TpmlPcrSelection, PcrError> {
    let mut merged: HashMap<TpmAlgId, Vec<u8>> = HashMap::new();

    for sel in selections {
        let bank = banks
            .iter()
            .find(|b| b.alg == sel.hash)
            .ok_or(PcrError::InvalidAlgorithm(sel.hash))?;

        let pcr_select_bytes = merged
            .entry(sel.hash)
            .or_insert_with(|| vec![0u8; bank.count.div_ceil(8)]);

        if pcr_select_bytes.len() != sel.pcr_select.len() {
            return Err(PcrError::InvalidPcrSelection(format!(
                "Mismatched PCR select size for {:?}",
                sel.hash
            )));
        }

        for (i, byte) in sel.pcr_select.iter().enumerate() {
            pcr_select_bytes[i] |= byte;
        }
    }

    let mut list = TpmlPcrSelection::new();
    for (hash, pcr_select_bytes) in merged {
        list.push(TpmsPcrSelection {
            hash,
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())?,
        })
        .map_err(|_| PcrError::CapacityExceeded)?;
    }
    Ok(list)
}

/// Reads the selected PCRs and returns them in a structured format.
///
/// # Errors
///
/// Returns a `PcrError` if the `TPM2_PcrRead` command fails or if the TPM's
/// response does not contain the expected number of digests for the selection.
pub fn pcr_read(
    session: &mut Session,
    device: &mut Device,
    pcr_selection_in: &TpmlPcrSelection,
) -> Result<(Vec<Pcr>, u32), PcrError> {
    let cmd = TpmPcrReadCommand {
        pcr_selection_in: *pcr_selection_in,
    };
    let (resp, _) = session.execute(device, &cmd, &[], &[])?;
    let pcr_read_resp = resp
        .PcrRead()
        .map_err(|_| DeviceError::ResponseMismatch(TpmCc::PcrRead))?;
    let mut pcrs = Vec::new();
    let mut digest_iter = pcr_read_resp.pcr_values.iter();
    for selection in pcr_read_resp.pcr_selection_out.iter() {
        for (byte_idx, &byte) in selection.pcr_select.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit_idx in 0..8 {
                if (byte >> bit_idx) & 1 == 1 {
                    let pcr_index = u32::try_from(byte_idx * 8 + bit_idx)
                        .map_err(|_| PcrError::InvalidPcrSelection("PCR index overflow".into()))?;
                    let value = digest_iter.next().ok_or_else(|| {
                        PcrError::InvalidPcrSelection("PCR selection mismatch".to_string())
                    })?;
                    pcrs.push(Pcr {
                        bank: selection.hash,
                        index: pcr_index,
                        value: value.to_vec(),
                    });
                }
            }
        }
    }
    Ok((pcrs, pcr_read_resp.pcr_update_counter))
}

/// Computes a composite digest from a set of PCRs using a specified algorithm.
///
/// # Errors
///
/// Returns a `PcrError` if the provided hash algorithm is not supported for
/// creating a composite digest.
pub fn pcr_composite_digest(pcrs: &[Pcr], alg: TpmAlgId) -> Result<Vec<u8>, PcrError> {
    let digests: Vec<&[u8]> = pcrs.iter().map(|p| p.value.as_slice()).collect();
    Ok(Hash::from(alg).digest(&digests)?)
}

/// Populates the AST with PCR digests by reading current values from the TPM.
///
/// # Errors
///
/// Returns [`CommandError::Policy`](crate::command::CommandError::Policy) when
/// the policy AST visitor fails.
/// Returns [`CommandError::Pcr`](crate::command::CommandError::Pcr) when
/// merging PCR selections, reading PCRs, or calculating the composite digest
/// fails.
pub fn resolve_pcr_digests(
    job: &mut Session,
    device: &mut crate::device::Device,
    ast: &mut Expression,
    session_hash_alg: TpmAlgId,
    banks: &[PcrBank],
) -> Result<(), CommandError> {
    let mut required_selections: Vec<TpmsPcrSelection> = Vec::new();
    visit_pcr_expressions_mut(ast, &mut |expr| -> Result<(), PolicyError> {
        if let Expression::Pcr {
            selections,
            digest: None,
            ..
        } = expr
        {
            for s in selections.iter() {
                required_selections.push(*s);
            }
        }
        Ok(())
    })?;

    if !required_selections.is_empty() {
        let merged_selection = crate::pcr::merge_pcr_selections(&required_selections, banks)?;
        let (pcr_values, _) = pcr_read(job, device, &merged_selection)?;

        let mut populator = |expr: &mut Expression| -> Result<(), PolicyError> {
            if let Expression::Pcr {
                selections, digest, ..
            } = expr
            {
                if digest.is_none() {
                    let mut pcr_subset: Vec<crate::pcr::Pcr> = Vec::new();
                    for sel in selections.iter() {
                        pcr_subset.extend(
                            pcr_values
                                .iter()
                                .filter(|pcr| {
                                    if pcr.bank != sel.hash {
                                        return false;
                                    }
                                    let pcr_index = pcr.index as usize;
                                    let byte_index = pcr_index / 8;
                                    let bit_index = pcr_index % 8;

                                    sel.pcr_select
                                        .get(byte_index)
                                        .is_some_and(|&byte| (byte >> bit_index) & 1 == 1)
                                })
                                .cloned(),
                        );
                    }

                    let composite_digest = pcr_composite_digest(&pcr_subset, session_hash_alg)?;
                    *digest = Some(hex::encode(composite_digest));
                }
            }
            Ok(())
        };
        visit_pcr_expressions_mut(ast, &mut populator)?;
    }
    Ok(())
}
