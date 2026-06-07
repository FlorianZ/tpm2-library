// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Task, command::CommandError, task::TaskState};
use argh::FromArgs;
use std::collections::HashSet;
use tpm2_crypto::{TpmEllipticCurve, TpmHash};
use tpm2_device::{with_device, TpmDevice, TpmDeviceError};
use tpm2_protocol::{
    basic::TpmUint16,
    data::{
        TpmAlgId, TpmRcBase, TpmsKeyedhashParms, TpmsRsaParms, TpmsSchemeHash, TpmsSchemeXor,
        TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublicParms, TpmuKdfScheme, TpmuKeyedhashScheme,
        TpmuPublicParms,
    },
    frame::TpmTestParmsCommand,
};

const RSA_KEY_SIZES: [u16; 3] = [2048, 3072, 4096];

/// Lists available algorithms supported by the chip.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "algorithm", help_triggers("-h", "--help", "help"))]
pub struct Algorithm {}

impl Algorithm {
    /// Checks if the TPM supports a given set of RSA parameters.
    fn test_rsa_parms(device: &mut TpmDevice, key_bits: u16) -> Result<(), TpmDeviceError> {
        let key_bits = TpmUint16::new(key_bits);
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
        device.transmit(&cmd, &sessions).map(|_| ())
    }

    /// Checks if the TPM supports a given set of KeyedHash parameters.
    fn test_keyedhash_parms(
        device: &mut TpmDevice,
        scheme: TpmAlgId,
        hash_alg: TpmAlgId,
    ) -> Result<(), CommandError> {
        let details = match scheme {
            TpmAlgId::Null => TpmuKeyedhashScheme::Null,
            TpmAlgId::Hmac => TpmuKeyedhashScheme::Hmac(TpmsSchemeHash { hash_alg }),
            TpmAlgId::Xor => TpmuKeyedhashScheme::Xor(TpmsSchemeXor {
                hash_alg,
                kdf: TpmtKdfScheme {
                    scheme: TpmAlgId::Kdf1Sp800_108,
                    details: TpmuKdfScheme::Null,
                },
            }),
            _ => return Err(CommandError::InvalidAlgorithm(scheme)),
        };

        let cmd = TpmTestParmsCommand {
            parameters: TpmtPublicParms {
                object_type: TpmAlgId::KeyedHash,
                parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtKeyedhashScheme { scheme, details },
                }),
            },
            handles: [],
        };
        let sessions = vec![];
        device
            .transmit(&cmd, &sessions)
            .map(|_| ())
            .map_err(CommandError::from)
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

    fn format_hash(hash: TpmAlgId) -> String {
        TpmHash::try_from(hash).map_or_else(|_| format!("{hash:?}"), |hash| hash.to_string())
    }

    fn format_rsa_alg(bits: u16, hash: TpmAlgId) -> String {
        format!("rsa-{}:{}", bits, Self::format_hash(hash))
    }

    fn format_ecc_alg(curve: TpmEllipticCurve, hash: TpmAlgId) -> String {
        format!("ecc-{}:{}", curve, Self::format_hash(hash))
    }

    fn fetch_rsa_algs(
        device: &mut TpmDevice,
        name_algs: &[TpmAlgId],
    ) -> Result<Vec<String>, CommandError> {
        let mut results = Vec::new();
        for bits in Self::fetch_supported_rsa_sizes(device)? {
            for &hash in name_algs {
                results.push(Self::format_rsa_alg(bits, hash));
            }
        }
        Ok(results)
    }

    fn fetch_ecc_algs(
        device: &mut TpmDevice,
        name_algs: &[TpmAlgId],
    ) -> Result<Vec<String>, CommandError> {
        let mut results = Vec::new();
        let supported_curves = device.fetch_ecc_curves()?;
        for curve_id in supported_curves {
            if let Ok(curve) = TpmEllipticCurve::try_from(curve_id) {
                for &hash in name_algs {
                    results.push(Self::format_ecc_alg(curve, hash));
                }
            }
        }
        Ok(results)
    }

    fn fetch_keyedhash_algs(device: &mut TpmDevice, name_algs: &[TpmAlgId]) -> Vec<String> {
        let mut results = Vec::new();
        if Self::test_keyedhash_parms(device, TpmAlgId::Null, TpmAlgId::Null).is_ok() {
            for &hash in name_algs {
                results.push(format!("keyedhash-null:{}", Self::format_hash(hash)));
            }
        }

        for &hash in name_algs {
            if Self::test_keyedhash_parms(device, TpmAlgId::Hmac, hash).is_ok() {
                results.push(format!("keyedhash-hmac:{}", Self::format_hash(hash)));
            }
            if Self::test_keyedhash_parms(device, TpmAlgId::Xor, hash).is_ok() {
                results.push(format!("keyedhash-xor:{}", Self::format_hash(hash)));
            }
        }
        results
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
            results.extend(Self::fetch_rsa_algs(device, &name_algs)?);
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            results.extend(Self::fetch_ecc_algs(device, &name_algs)?);
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            results.extend(Self::fetch_keyedhash_algs(device, &name_algs));
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
