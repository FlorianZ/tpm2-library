// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen
use crate::{
    cli::SubCommand,
    command::{deny_too_many_auths, CommandError},
    crypto::crypto_hash_size,
    device::{test_rsa_parms, with_device, Device, DeviceError},
    job::Job,
    key::{Tpm2shAlgId, Tpm2shEccCurve},
};
use clap::{Args, ValueEnum};
use strum::{Display, EnumString};
use tpm2_protocol::{
    constant::MAX_HANDLES,
    data::{TpmAlgId, TpmCap, TpmRcBase, TpmuCapabilities},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum AlgorithmType {
    Key,
    Name,
}

/// Lists available algorithms supported by the chip.
#[derive(Args, Debug)]
pub struct Algorithm {
    /// Algorithm type: 'key' or 'name'
    #[arg(short = 't', long = "type", value_enum)]
    pub algorithm_type: Option<AlgorithmType>,
}

impl Algorithm {
    fn fetch_key_algorithms(device: &mut Device) -> Result<Vec<String>, CommandError> {
        let mut results: Vec<String> = Vec::new();
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
                            results.push(format!("rsa-{}:{}", key_bits, Tpm2shAlgId(name_alg)));
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
                    results.push(format!(
                        "ecc-{}:{}",
                        Tpm2shEccCurve::from(curve_id),
                        Tpm2shAlgId(name_alg)
                    ));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &name_alg in &name_algs {
                results.push(format!("keyedhash:{}", Tpm2shAlgId(name_alg)));
            }
        }
        Ok(results)
    }
}

impl SubCommand for Algorithm {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        deny_too_many_auths(job.auth_list, 0)?;
        with_device(job.device.clone(), |device| {
            let mut results: Vec<String> = Vec::new();

            let fetch_keys =
                self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Key);
            let fetch_names =
                self.algorithm_type.is_none() || self.algorithm_type == Some(AlgorithmType::Name);

            if fetch_keys {
                results.extend(Algorithm::fetch_key_algorithms(device)?);
            }

            if fetch_names {
                let all_algs = device.fetch_algorithm_properties()?;
                let hashes: Vec<String> = all_algs
                    .iter()
                    .map(|prop| prop.alg)
                    .filter(|p| crypto_hash_size(*p).is_ok())
                    .map(|p| Tpm2shAlgId(p).to_string())
                    .collect();
                results.extend(hashes);
            }

            results.sort();

            for alg in results {
                writeln!(job.writer, "{alg}")?;
            }

            Ok(())
        })
    }
}
