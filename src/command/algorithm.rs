// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Task, command::CommandError, task::TaskState};
use clap::Args;
use std::collections::HashSet;
use tpm2_crypto::{TpmEllipticCurve, TpmHash};
use tpm2_device::{with_device, TpmDevice, TpmDeviceError};
use tpm2_protocol::{
    basic::TpmUint16,
    data::{TpmAlgId, TpmRcBase, TpmsRsaParms, TpmtPublicParms, TpmuPublicParms},
    frame::TpmTestParmsCommand,
};

const RSA_KEY_SIZES: [u16; 3] = [2048, 3072, 4096];

/// Lists available algorithms supported by the chip.
#[derive(Args, Debug)]
pub struct Algorithm;

impl Algorithm {
    /// Checks if the TPM supports a given set of RSA parameters.
    fn test_rsa_parms(device: &mut TpmDevice, key_bits: u16) -> Result<(), TpmDeviceError> {
        let key_bits = TpmUint16(key_bits);
        let cmd = TpmTestParmsCommand {
            parameters: TpmtPublicParms {
                object_type: TpmAlgId::Rsa,
                parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                    key_bits,
                    ..Default::default()
                }),
            },
            handles: [],
        };
        let sessions = vec![];
        device.transmit(&cmd, &sessions).map(|(_, _)| ())
    }

    /// Identifies which RSA key sizes from the standard set are supported.
    fn fetch_supported_rsa_sizes(device: &mut TpmDevice) -> Result<Vec<u16>, CommandError> {
        let mut supported = Vec::new();
        for &bits in &RSA_KEY_SIZES {
            match Self::test_rsa_parms(device, bits) {
                Ok(()) => supported.push(bits),
                Err(TpmDeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::Value => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(supported)
    }

    fn format_rsa_alg(bits: u16, hash: TpmAlgId) -> String {
        format!("rsa-{}:{}", bits, TpmHash::from(hash))
    }

    fn format_ecc_alg(curve: TpmEllipticCurve, hash: TpmAlgId) -> String {
        format!("ecc-{}:{}", curve, TpmHash::from(hash))
    }

    fn fetch_key_algorithms(device: &mut TpmDevice) -> Result<Vec<String>, CommandError> {
        let mut results: Vec<String> = Vec::new();
        let all_alg_props = device.fetch_algorithm_properties()?;
        let all_algs: HashSet<TpmAlgId> = all_alg_props.into_iter().map(|p| p.alg).collect();

        let name_algs: Vec<TpmAlgId> = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512]
            .into_iter()
            .filter(|alg| all_algs.contains(alg))
            .collect();

        if all_algs.contains(&TpmAlgId::Rsa) {
            for bits in Self::fetch_supported_rsa_sizes(device)? {
                for &hash in &name_algs {
                    results.push(Self::format_rsa_alg(bits, hash));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            let supported_curves = device.fetch_ecc_curves()?;
            for curve_id in supported_curves {
                for &hash in &name_algs {
                    results.push(Self::format_ecc_alg(TpmEllipticCurve::from(curve_id), hash));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &hash in &name_algs {
                results.push(format!("keyedhash:{}", TpmHash::from(hash)));
            }
        }
        Ok(results)
    }
}

impl Task for Algorithm {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let mut results: Vec<String> = Vec::new();
            results.extend(Algorithm::fetch_key_algorithms(device)?);
            results.sort();
            for alg in results {
                writeln!(writer, "{alg}")?;
            }
            Ok(())
        })
    }
}
