//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    command::{CommandError, OutputEncoding},
    device::TpmDevice,
};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bDigest, Tpm2bName, TpmCc},
    frame::{TpmAuthCommands, TpmCommand},
    TpmHandle, TpmMarshal, TpmUnmarshal, TpmWriter,
};
use tpm2_tpmkey::{Error as TpmKeyError, TpmKey, TpmPolicy, TpmPolicyCommand};

/// Reads data from a file path or from stdin if the path is not provided.
///
/// # Errors
///
/// Returns a `std::io::Error` on failure.
pub fn read_file_input(input: Option<&Path>) -> io::Result<Vec<u8>> {
    let mut input_bytes = Vec::new();
    match input {
        Some(path) => {
            input_bytes = std::fs::read(path)?;
        }
        None => {
            io::stdin().read_to_end(&mut input_bytes)?;
        }
    }
    Ok(input_bytes)
}

/// Handles the output of a `TpmKey`, choosing PEM or DER format based on the
/// URI.
///
/// It will either save it to a file or print it to stdout as PEM, based on the
/// provided output string.
///
/// # Errors
///
/// Returns `CommandError` on failure.
pub fn write_key_data(
    writer: &mut dyn Write,
    tpm_key: &TpmKey,
    output: Option<&Path>,
    encoding: OutputEncoding,
) -> Result<(), CommandError> {
    let output_bytes = match encoding {
        OutputEncoding::Der => tpm_key.to_der().map_err(AlgError::from)?,
        OutputEncoding::Pem => tpm_key.to_pem().map_err(AlgError::from)?.into_bytes(),
    };

    write_data(writer, output, &output_bytes)
}

fn write_data(
    writer: &mut dyn Write,
    output_path: Option<&Path>,
    data: &[u8],
) -> Result<(), CommandError> {
    if let Some(path) = output_path {
        fs::write(path, data)?;
        writeln!(writer, "file:{}", path.to_string_lossy())?;
    } else {
        writer.write_all(data)?;
    }
    Ok(())
}

/// Converts a "live" `TpmCommandList` into a "storable" `TpmPolicy`.
///
/// This performs the "second pass" for `PolicySecret`, converting the
/// `auth_handle` into a `Tpm2bName` for durable storage.
///
/// # Errors
///
/// Returns [`Key`](CommandError::Key) if the command conversion fails.
/// Returns [`Device`](CommandError::Device) if reading the public handle name fails.
pub fn tpm_key_to_blob(
    device: &mut TpmDevice,
    commands: &[(TpmCommand, TpmAuthCommands)],
) -> Result<TpmPolicy, CommandError> {
    let mut policy = Vec::new();
    for (cmd, auths) in commands {
        let step = match cmd {
            TpmCommand::PolicySecret(inner) => {
                let (_, name) = device.read_public(inner.auth_handle)?;
                TpmPolicyCommand::from_policy_secret(inner, &name)
                    .map_err(|e| CommandError::Key(AlgError::TpmKey(e)))?
            }
            _ => TpmPolicyCommand::from_command(cmd, auths)
                .map_err(|e| CommandError::Key(AlgError::TpmKey(e)))?,
        };
        policy.push(step);
    }
    Ok(TpmPolicy { name: None, policy })
}

/// Converts a "storable" `TpmPolicy` (from a `TpmKey` file) into the
/// custom binary cache format.
///
/// # Errors
///
/// Returns [`IntDecode`](CommandError::IntDecode) if the policy command count exceeds `u32::MAX`.
/// Returns [`Protocol`](CommandError::Protocol) if marshalling fails or the policy body is too large.
/// Returns [`Key`](CommandError::Key) if the policy blob is malformed.
pub fn tpm_key_from_blob(policy: &TpmPolicy) -> Result<Vec<u8>, CommandError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        let count = u32::try_from(policy.policy.len())?;
        count.marshal(&mut writer)?;

        for cmd in &policy.policy {
            cmd.code().marshal(&mut writer)?;

            if cmd.code() == TpmCc::PolicySecret {
                let (handle, rest) = TpmHandle::unmarshal(cmd.body())
                    .map_err(|_| CommandError::Key(AlgError::TpmKey(TpmKeyError::InvalidPolicy)))?;
                let (name, rest) = Tpm2bName::unmarshal(rest)
                    .map_err(|_| CommandError::Key(AlgError::TpmKey(TpmKeyError::InvalidPolicy)))?;
                let (digest, _) = Tpm2bDigest::unmarshal(rest)
                    .map_err(|_| CommandError::Key(AlgError::TpmKey(TpmKeyError::InvalidPolicy)))?;

                handle.marshal(&mut writer)?;
                name.marshal(&mut writer)?;
                digest.marshal(&mut writer)?;
            } else {
                TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(cmd.body())?
                    .marshal(&mut writer)?;
            }
        }
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}
