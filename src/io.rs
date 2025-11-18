//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    command::{CommandError, OutputEncoding},
};

use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

use tpm2_device::TpmDevice;
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    frame::{TpmAuthCommands, TpmCommand},
    TpmMarshal, TpmProtocolError, TpmWriter,
};
use tpm2_tpmkey::{TpmKey, TpmPolicy, TpmPolicyCommand};

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
            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(cmd.body())?
                .marshal(&mut writer)?;
        }
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError` if the object cannot be serialized into the buffer.
pub fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmProtocolError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.marshal(&mut writer)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// Parses a hexadecimal string with an optional "0x" prefix into a `u32`.
///
/// # Errors
///
/// Returns an error if the string is not a valid hexadecimal number.
pub fn parse_hex_u32(hex_str: &str) -> Result<u32, std::num::ParseIntError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u32::from_str_radix(hex_str, 16)
}
