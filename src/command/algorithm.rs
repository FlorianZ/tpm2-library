//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen
use crate::{
    cli::Job,
    command::CommandError,
    device::{with_device, Device, DeviceError},
    key::{Tpm2shAlgId, Tpm2shEccCurve},
    session::Session,
};
use clap::Args;
use tpm2_protocol::{
    constant::MAX_HANDLES,
    data::{
        TpmAlgId, TpmCap, TpmRcBase, TpmsRsaParms, TpmtPublicParms, TpmuCapabilities,
        TpmuPublicParms,
    },
    frame::TpmTestParmsCommand,
};

/// Lists available algorithms supported by the chip.
#[derive(Args, Debug)]
pub struct Algorithm {}

impl Algorithm {
    /// Checks if the TPM supports a given set of RSA parameters.
    fn test_rsa_parms(device: &mut Device, key_bits: u16) -> Result<(), DeviceError> {
        let cmd = TpmTestParmsCommand {
            parameters: TpmtPublicParms {
                object_type: TpmAlgId::Rsa,
                parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                    key_bits,
                    ..Default::default()
                }),
            },
        };
        let sessions = vec![];
        device.execute(&cmd, &sessions).map(|(_, _)| ())
    }

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
                match Self::test_rsa_parms(device, key_bits) {
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

impl Job for Algorithm {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let mut results: Vec<String> = Vec::new();
            results.extend(Algorithm::fetch_key_algorithms(device)?);
            results.sort();
            for alg in results {
                writeln!(job.writer, "{alg}")?;
            }
            Ok(())
        })
    }
}
