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

/// Handles the output logic for a command that produces a `TpmKey`.
///
/// This function will either save it to a file or print it to stdout as PEM,
/// based on the provided output string.
///
/// # Errors
///
/// Returns `CommandError` on failure.
pub fn write_file_output(
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
