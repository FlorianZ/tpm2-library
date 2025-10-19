// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    device::{test_rsa_parms, with_device, Device, DeviceError},
    job::Job,
    key::{Tpm2shAlgId, Tpm2shEccCurve},
};
use clap::Args;
use strum::{Display, EnumString};
use tabled::Tabled;
use tpm2_protocol::{
    constant::MAX_HANDLES,
    data::{TpmAlgId, TpmCap, TpmRcBase, TpmuCapabilities},
    tpm_hash_size,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum AlgorithmType {
    Key,
    Name,
}

#[derive(Tabled)]
struct AlgorithmRow {
    #[tabled(rename = "ALGORITHM")]
    algorithm: String,
    #[tabled(rename = "TYPE")]
    algorithm_type: String,
}

/// Lists available algorithms supported by the chip.
#[derive(Args, Debug)]
pub struct Algorithm {
    /// Algorithm type: 'key' or 'name'
    #[arg(long = "type")]
    pub algorithm_type: Option<AlgorithmType>,
}

impl Algorithm {
    fn fetch_hash_algorithms(device: &mut Device) -> Result<Vec<String>, CommandError> {
        let all_algs = device.fetch_algorithm_properties()?;
        let hashes: Vec<String> = all_algs
            .iter()
            .map(|prop| prop.alg)
            .filter(|p| tpm_hash_size(p).is_some())
            .map(|p| Tpm2shAlgId(p).to_string())
            .collect();
        Ok(hashes)
    }

    fn fetch_algorithms(device: &mut Device) -> Result<Vec<(String, AlgorithmType)>, CommandError> {
        let mut results: Vec<(String, AlgorithmType)> = Vec::new();
        let all_alg_props = device.fetch_algorithm_properties()?;
        let all_algs: std::collections::HashSet<TpmAlgId> =
            all_alg_props.into_iter().map(|p| p.alg).collect();

        let name_algs: Vec<TpmAlgId> = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512]
            .into_iter()
            .filter(|alg| all_algs.contains(alg))
            .collect();

        if all_algs.contains(&TpmAlgId::Rsa) {
            let rsa_key_sizes = [2048, 3072, 4096];
            for key_bits in rsa_key_sizes {
                match test_rsa_parms(device, key_bits) {
                    Ok(()) => {
                        for &name_alg in &name_algs {
                            results.push((
                                format!("rsa-{}:{}", key_bits, Tpm2shAlgId(name_alg)),
                                AlgorithmType::Key,
                            ));
                        }
                    }
                    Err(DeviceError::TpmRc(rc)) => {
                        if rc.base() != TpmRcBase::Value {
                            return Err(DeviceError::TpmRc(rc).into());
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            let supported_curves = device.get_capability(
                TpmCap::EccCurves,
                0,
                u32::try_from(MAX_HANDLES)?,
                |caps| match caps {
                    TpmuCapabilities::EccCurves(curves) => Ok(curves),
                    _ => Err(DeviceError::CapabilityMissing(TpmCap::EccCurves)),
                },
                |last| *last as u32 + 1,
            )?;
            for curve_id in supported_curves {
                for &name_alg in &name_algs {
                    results.push((
                        format!(
                            "ecc-{}:{}",
                            Tpm2shEccCurve::from(curve_id),
                            Tpm2shAlgId(name_alg)
                        ),
                        AlgorithmType::Key,
                    ));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &name_alg in &name_algs {
                results.push((
                    format!("keyedhash:{}", Tpm2shAlgId(name_alg)),
                    AlgorithmType::Key,
                ));
            }
        }
        Ok(results)
    }
}

impl SubCommand for Algorithm {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let mut results: Vec<(String, AlgorithmType)> = Vec::new();

            let fetch_keys =
                self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Key);
            let fetch_names =
                self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Name);

            if fetch_keys {
                results.extend(Algorithm::fetch_algorithms(device)?);
            }

            if fetch_names {
                let hashes = Self::fetch_hash_algorithms(device)?
                    .into_iter()
                    .map(|name| (name, AlgorithmType::Name));
                results.extend(hashes);
            }

            results.sort_by(|a, b| a.0.cmp(&b.0));

            let rows: Vec<AlgorithmRow> = results
                .into_iter()
                .map(|(algorithm, algorithm_type)| AlgorithmRow {
                    algorithm,
                    algorithm_type: algorithm_type.to_string(),
                })
                .collect();
            print_table(&mut job.key_cache.writer, rows)?;
            Ok(())
        })
    }
}
