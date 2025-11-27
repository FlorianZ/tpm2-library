// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Abstractions and logic for handling Platform Configuration Registers (PCRs).

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
    #[error("crypto: {0}")]
    Crypto(#[from] TpmCryptoError),
    #[error("device: {0}")]
    Device(#[from] TpmDeviceError),
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("PCR digest missing")]
    PcrDigestMissing,
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
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
    device: &mut TpmDevice,
) -> Result<HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>>, PcrError> {
    let (algs, common_mask) = device.fetch_pcr_bank_list()?;
    let mut remaining_selection = TpmlPcrSelection::new();

    for alg in &algs {
        remaining_selection
            .try_push(TpmsPcrSelection {
                hash: *alg,
                pcr_select: common_mask,
            })
            .map_err(|_| PcrError::CapacityExceeded)?;
    }

    let mut results: HashMap<TpmAlgId, HashMap<u32, Tpm2bDigest>> = HashMap::new();
    for alg in algs {
        results.insert(alg, HashMap::new());
    }

    while !is_selection_empty(&remaining_selection) {
        let cmd = TpmPcrReadCommand {
            pcr_selection_in: remaining_selection,
            handles: [],
        };

        let (resp, _) = device.transmit(&cmd, &[])?;
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
                        let digest = value_iter.next().ok_or(PcrError::PcrDigestMissing)?;

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

        let new_select = TpmsPcrSelect::try_from(mask_bytes.as_slice()).unwrap();

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
