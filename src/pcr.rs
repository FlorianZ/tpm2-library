// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Abstractions and logic for handling Platform Configuration Registers (PCRs).

use crate::task::{TaskError, TaskState};
use std::collections::HashMap;
use thiserror::Error;

use tpm2_crypto::TpmCryptoError;
use tpm2_device::{TpmDevice, TpmDeviceError};
use tpm2_protocol::{
    data::{Tpm2bDigest, TpmAlgId, TpmCc, TpmlPcrSelection, TpmsPcrSelect, TpmsPcrSelection},
    frame::TpmPcrReadCommand,
    TpmProtocolError,
};

#[derive(Debug, Error)]
pub enum PcrError {
    #[error("device: {0}")]
    Device(#[from] TpmDeviceError),
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("consistency check failed")]
    Consistency,
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid PCR selection: {0}")]
    InvalidPcrSelection(String),
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),
    #[error("session: {0}")]
    Session(#[from] TaskError),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
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
pub fn pcr_get_bank_list(device: &mut TpmDevice) -> Result<Vec<PcrBank>, PcrError> {
    let pcrs = device.fetch_pcr_banks()?;
    let mut banks = Vec::new();
    for bank in pcrs {
        banks.push(PcrBank {
            alg: bank.hash,
            count: bank.pcr_select.len() * 8,
        });
    }
    if banks.is_empty() {
        return Err(PcrError::InvalidPcrSelection(
            "TPM reported no active PCR banks.".to_string(),
        ));
    }
    banks.sort_by_key(|b| b.alg);
    Ok(banks)
}

/// Reads all PCRs from the active banks.
///
/// This function handles response fragmentation (reading in chunks) to ensure
/// all PCRs are retrieved.
///
/// # Errors
///
/// Returns `PcrError` on device or protocol failure.
pub fn read_all_pcrs(
    task_state: &mut TaskState,
    device: &mut TpmDevice,
) -> Result<HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>>, PcrError> {
    let banks = pcr_get_bank_list(device)?;
    let mut remaining_selection = TpmlPcrSelection::new();

    for bank in &banks {
        let mut mask = Vec::new();
        mask.resize(bank.count.div_ceil(8), 0xFF);

        if bank.count % 8 != 0 {
            let last_idx = mask.len() - 1;
            mask[last_idx] &= (1 << (bank.count % 8)) - 1;
        }

        remaining_selection
            .try_push(TpmsPcrSelection {
                hash: bank.alg,
                pcr_select: TpmsPcrSelect::try_from(mask.as_slice())
                    .map_err(|_| PcrError::CapacityExceeded)?,
            })
            .map_err(|_| PcrError::CapacityExceeded)?;
    }

    let mut results: HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>> = HashMap::new();
    for bank in banks {
        results.insert(bank.alg, HashMap::new());
    }

    while !is_selection_empty(&remaining_selection) {
        let cmd = TpmPcrReadCommand {
            pcr_selection_in: remaining_selection,
            handles: [],
        };

        let (resp, _) = task_state.execute(device, &cmd, &[])?;
        let pcr_resp = resp
            .PcrRead()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::PcrRead))?;

        let mut value_iter = pcr_resp.pcr_values.iter();
        for selection_out in pcr_resp.pcr_selection_out.iter() {
            let bank_store = results
                .get_mut(&selection_out.hash)
                .ok_or(PcrError::InvalidAlgorithm(selection_out.hash))?;

            for (byte_idx, &byte) in selection_out.pcr_select.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte >> bit_idx) & 1 == 1 {
                        let pcr_idx = u32::try_from(byte_idx * 8 + bit_idx)
                            .map_err(|_| PcrError::CapacityExceeded)?;
                        let digest = value_iter
                            .next()
                            .ok_or_else(|| PcrError::InvalidPcrSelection("Missing value".into()))?;

                        bank_store.insert(pcr_idx, *digest);
                    }
                }
            }
        }

        update_remaining_selection(&mut remaining_selection, &pcr_resp.pcr_selection_out)?;
    }

    Ok(results)
}

fn is_selection_empty(selection: &TpmlPcrSelection) -> bool {
    selection
        .iter()
        .all(|s| s.pcr_select.iter().all(|&b| b == 0))
}

fn update_remaining_selection(
    remaining: &mut TpmlPcrSelection,
    read: &TpmlPcrSelection,
) -> Result<(), PcrError> {
    let mut new_list = TpmlPcrSelection::new();

    for target_sel in remaining.iter() {
        let mut mask_bytes = target_sel.pcr_select.to_vec();

        if let Some(read_sel) = read.iter().find(|s| s.hash == target_sel.hash) {
            for (i, &byte) in read_sel.pcr_select.iter().enumerate() {
                if i < mask_bytes.len() {
                    mask_bytes[i] &= !byte;
                }
            }
        }

        let new_select = TpmsPcrSelect::try_from(mask_bytes.as_slice())
            .map_err(|_| PcrError::CapacityExceeded)?;

        new_list
            .try_push(TpmsPcrSelection {
                hash: target_sel.hash,
                pcr_select: new_select,
            })
            .map_err(|_| PcrError::CapacityExceeded)?;
    }

    *remaining = new_list;
    Ok(())
}
