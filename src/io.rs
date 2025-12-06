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
/// If reading from stdin, the input is assumed to be a hex-encoded string
/// representing the binary data (DER).
///
/// # Errors
///
/// Returns `CommandError::UnexpectedEof` when no data is provided.
/// Returns `CommandError::InvalidInput` when hex decoding fails.
pub fn read_file_input(input: Option<&Path>) -> Result<Vec<u8>, CommandError> {
    if let Some(path) = input {
        let bytes = fs::read(path)?;
        if bytes.is_empty() {
            Err(CommandError::UnexpectedEof)
        } else {
            Ok(bytes)
        }
    } else {
        let mut input_str = String::new();
        io::stdin().read_to_string(&mut input_str)?;
        let trimmed = input_str.trim();
        if trimmed.is_empty() {
            return Err(CommandError::UnexpectedEof);
        }
        hex::decode(trimmed)
            .map_err(|e| CommandError::InvalidInput(format!("invalid hex input: {e}")))
    }
}

/// Handles the output of a `TpmKey`.
///
/// If `output` is provided (file path), it respects the requested encoding (PEM or DER).
/// If `output` is `None` (stdout), it forces DER encoding outputted as a hex string.
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
    if let Some(path) = output {
        let output_bytes = match encoding {
            OutputEncoding::Der => tpm_key.to_der().map_err(CommandError::from)?,
            OutputEncoding::Pem => tpm_key.to_pem().map_err(CommandError::from)?.into_bytes(),
        };
        fs::write(path, output_bytes)?;
    } else {
        let der = tpm_key.to_der().map_err(CommandError::from)?;
        let hex_str = hex::encode(der);
        writeln!(writer, "{hex_str}")?;
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
