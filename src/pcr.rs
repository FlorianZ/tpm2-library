// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Abstractions and logic for handling Platform Configuration Registers (PCRs).

use crate::device::{Device, DeviceError};
use thiserror::Error;
use tpm2_crypto::{digest as crypto_digest, CryptoError};
pub use tpm2_policy_language::PcrSelection;
use tpm2_protocol::{
    constant::TPM_PCR_SELECT_MAX,
    data::{
        TpmAlgId, TpmCap, TpmCc, TpmlPcrSelection, TpmsPcrSelect, TpmsPcrSelection,
        TpmuCapabilities,
    },
    message::TpmPcrReadCommand,
    TpmError,
};

#[derive(Debug, Error)]
pub enum PcrError {
    #[error("device: {0}")]
    Device(#[from] DeviceError),
    #[error("invalid algorithm: {0:?}")]
    InvalidAlgorithm(TpmAlgId),
    #[error("invalid PCR selection: {0}")]
    InvalidPcrSelection(String),
    #[error("TPM: {0}")]
    Tpm(TpmError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
}

impl From<TpmError> for PcrError {
    fn from(err: TpmError) -> Self {
        Self::Tpm(err)
    }
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

/// Converts a vector of `PcrSelection` into the low-level `TpmlPcrSelection`
/// format.
///
/// # Errors
///
/// Returns a `PcrError` if a selected algorithm is not present in the provided
/// list of banks, or if a selected PCR index is out of bounds for its bank.
pub fn pcr_selection_vec_to_tpml(
    selections: &[PcrSelection],
    banks: &[PcrBank],
) -> Result<TpmlPcrSelection, PcrError> {
    let mut list = TpmlPcrSelection::new();
    for selection in selections {
        let bank = banks
            .iter()
            .find(|b| b.alg == selection.alg)
            .ok_or_else(|| {
                PcrError::InvalidPcrSelection(format!(
                    "PCR bank for algorithm {:?} not found or supported by TPM",
                    selection.alg
                ))
            })?;
        let pcr_select_size = bank.count.div_ceil(8);
        if pcr_select_size > TPM_PCR_SELECT_MAX {
            return Err(PcrError::InvalidPcrSelection(format!(
                "invalid select size {pcr_select_size} (> {TPM_PCR_SELECT_MAX})"
            )));
        }
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &selection.indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= bank.count {
                return Err(PcrError::InvalidPcrSelection(format!(
                    "invalid index {pcr_index} for {:?} bank (max is {})",
                    bank.alg,
                    bank.count - 1
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: selection.alg,
            pcr_select: TpmsPcrSelect::try_from(pcr_select_bytes.as_slice())?,
        })?;
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
    device: &mut Device,
    pcr_selection_in: &TpmlPcrSelection,
) -> Result<(Vec<Pcr>, u32), PcrError> {
    let cmd = TpmPcrReadCommand {
        pcr_selection_in: *pcr_selection_in,
    };
    let (resp, _) = device.execute(&cmd, &[])?;
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
    Ok(crypto_digest(alg, &digests)?)
}
