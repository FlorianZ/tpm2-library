// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::CommandError,
    context::ContextCache,
    key::{Alg, KeyError, TpmKey},
    uri::Uri,
};
use std::io::{self, Read};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE, data::TpmRc, TpmBuild, TpmErrorKind, TpmHandle, TpmWriter,
};

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
/// Returns a `TpmErrorKind` if the object cannot be serialized into the buffer.
pub fn from_tpm_object_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmErrorKind> {
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
pub fn from_input_to_bytes(input: Option<&Uri>) -> io::Result<Vec<u8>> {
    let mut input_bytes = Vec::new();
    match input {
        Some(Uri::Path(path)) => {
            input_bytes = std::fs::read(path)?;
        }
        None => {
            io::stdin().read_to_end(&mut input_bytes)?;
        }
        Some(uri) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("input must be a file path, but got '{uri}'"),
            ));
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
    context: &mut ContextCache,
    tpm_key: &TpmKey,
    output: Option<&Uri>,
) -> Result<(), CommandError> {
    if let Some(output_uri) = output {
        if !matches!(output_uri, Uri::Path(_)) {
            return Err(CommandError::InvalidOutput(format!(
                "output must be a file path, but got '{output_uri}'"
            )));
        }
        context.write_key_data(Some(output_uri), tpm_key)?;
    } else {
        context.write_key_data(None, tpm_key)?;
    }
    Ok(())
}

/// Parses a string into a `TpmRc`.
///
/// # Errors
///
/// Returns a `String` error if parsing fails.
pub fn from_str_to_tpm_rc(s: &str) -> Result<TpmRc, String> {
    let s_no_prefix = s.strip_prefix("0x").unwrap_or(s);
    let raw_rc = u32::from_str_radix(s_no_prefix, 16)
        .map_err(|e| format!("Failed to parse hex u32: {e}"))?;
    TpmRc::try_from(raw_rc).map_err(|e| format!("Invalid TPM RC value '{s}': {e}"))
}

/// Parses a string into an `Alg` for a sealed object.
///
/// # Errors
///
/// Returns a `String` error if parsing fails.
pub fn from_str_to_keyedhash_alg(s: &str) -> Result<Alg, String> {
    Alg::new_keyedhash(s).map_err(|e: KeyError| e.to_string())
}
