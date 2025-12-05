// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::OutputEncoding, command::CommandError};

use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

use tpm2_protocol::{constant::TPM_MAX_COMMAND_SIZE, TpmMarshal, TpmProtocolError, TpmWriter};
use tpm2_tpmkey::TpmKeyFile;

/// Reads data from a file path or from stdin if the path is not provided.
///
/// # Errors
///
/// Returns `CommandError::UnexpectedEof` when no data is provided.
pub fn read_file_input(input: Option<&Path>) -> Result<Vec<u8>, CommandError> {
    let mut input_bytes = Vec::new();
    match input {
        Some(path) => {
            input_bytes = std::fs::read(path)?;
        }
        None => {
            io::stdin().read_to_end(&mut input_bytes)?;
        }
    }

    if input_bytes.is_empty() {
        Err(CommandError::UnexpectedEof)
    } else {
        Ok(input_bytes)
    }
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
    tpm_key: &TpmKeyFile,
    output: Option<&Path>,
    encoding: OutputEncoding,
) -> Result<(), CommandError> {
    let effective_encoding = if output.is_none() {
        OutputEncoding::Pem
    } else {
        encoding
    };

    let output_bytes = match effective_encoding {
        OutputEncoding::Der => tpm_key.to_der().map_err(CommandError::from)?,
        OutputEncoding::Pem => tpm_key.to_pem().map_err(CommandError::from)?.into_bytes(),
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
    } else {
        writer.write_all(data)?;
    }
    Ok(())
}

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError` if the object cannot be serialized into the buffer.
pub fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmProtocolError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.marshal(&mut writer)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

/// Parses a string as a u32, supporting decimal (default) or hexadecimal ("0x" prefix).
///
/// # Errors
///
/// Returns an error if the string is not a valid number.
pub fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    let trimmed = s.trim();
    if let Some(stripped) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(stripped, 16)
    } else {
        trimmed.parse::<u32>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn read_file_input_errors_on_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let result = read_file_input(Some(file.path()));
        assert!(matches!(result, Err(CommandError::UnexpectedEof)));
    }

    #[test]
    fn parse_u32_accepts_variants() {
        assert_eq!(parse_u32(" 42 ").unwrap(), 42);
        assert_eq!(parse_u32("0x2a").unwrap(), 42);
        assert_eq!(parse_u32("0X2A").unwrap(), 42);
    }

    #[test]
    fn read_file_input_reads_non_empty_file() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "abc").unwrap();
        file.as_file().sync_all().unwrap();

        let result = read_file_input(Some(file.path())).unwrap();
        assert_eq!(result, b"abc");
    }
}
