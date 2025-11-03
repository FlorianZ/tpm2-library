//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{CommandError, OutputEncoding},
    key::KeyError,
};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};
use tpm2_policy_language::PolicyState;
use tpm2_tpmkey::TpmKey;

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
    policy_state: &PolicyState,
) -> Result<(), CommandError> {
    let output_bytes = match encoding {
        OutputEncoding::Der => tpm_key.to_der(policy_state).map_err(KeyError::from)?,
        OutputEncoding::Pem => tpm_key
            .to_pem(policy_state)
            .map_err(KeyError::from)?
            .into_bytes(),
    };

    write_data(writer, output, &output_bytes)
}

fn write_data(
    writer: &mut dyn Write,
    output_path: Option<&Path>,
    data: &[u8],
) -> Result<(), CommandError> {
    if let Some(path) = output_path {
        if path.to_str() == Some("-") {
            writer.write_all(data)?;
        } else {
            fs::write(path, data)?;
            writeln!(writer, "file:{}", path.to_string_lossy())?;
        }
    } else {
        writer.write_all(data)?;
    }
    Ok(())
}
