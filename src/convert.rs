// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{CommandError, OutputEncoding},
    key::TpmKey,
    key_cache::KeyCache,
};
use std::{
    io::{self, Read},
    path::Path,
};
use tpm2_protocol::{constant::TPM_MAX_COMMAND_SIZE, TpmBuild, TpmError, TpmHandle, TpmWriter};

/// Parses a 16 character hex string with an optional `0x` prefix into
/// `TpmHandle`.
///
/// # Errors
///
/// Returns `String` with `ParseIntError` converted to string.
pub fn from_str_to_handle(input: &str) -> Result<TpmHandle, String> {
    let input = match input.strip_prefix("0x") {
        Some(input) => input,
        None => input,
    };
    u32::from_str_radix(input, 16)
        .map(TpmHandle)
        .map_err(|e| e.to_string())
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError` if the object cannot be serialized into the buffer.
pub fn from_tpm_object_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// Reads data from a file path or from stdin if the path is not provided.
///
/// # Errors
///
/// Returns a `std::io::Error` on failure.
pub fn from_input_to_bytes(input: Option<&Path>) -> io::Result<Vec<u8>> {
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

/// Handles the output logic for a command that produces a `TpmKey`.
///
/// This function will either save it to a file or print it to stdout as PEM,
/// based on the provided output string.
///
/// # Errors
///
/// Returns `CommandError` on failure.
pub fn from_tpm_key_to_output(
    key_cache: &mut KeyCache,
    tpm_key: &TpmKey,
    output: Option<&Path>,
    encoding: OutputEncoding,
) -> Result<(), CommandError> {
    if let Some(path) = output {
        key_cache.write_key_data(Some(path), tpm_key, encoding)?;
    } else {
        key_cache.write_key_data(None, tpm_key, encoding)?;
    }
    Ok(())
}
