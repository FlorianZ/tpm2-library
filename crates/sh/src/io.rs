// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use anyhow::{Result, anyhow};

use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

use tpm2_protocol::{TpmError, TpmMarshal, TpmWriter, constant::TPM_MAX_COMMAND_SIZE};
use tpm2_tpmkey::TpmKeyFile;

/// Reads data from a file path or from stdin if the path is not provided.
///
/// # Errors
///
/// Returns an error when no data is provided or on I/O failure.
pub fn read_file_input(input: Option<&Path>) -> Result<Vec<u8>> {
    let mut bytes = if let Some(path) = input {
        fs::read(path)?
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    if bytes.is_empty() {
        return Err(anyhow!("unexpected eof"));
    }

    if input.is_none()
        && let Ok(s) = std::str::from_utf8(&bytes)
    {
        bytes = s.trim().as_bytes().to_vec();
    }

    Ok(bytes)
}

/// Handles the output of a `TpmKey`.
///
/// Serializes the key to PEM format. If `output` is provided (file path),
/// writes to the file. If `output` is `None` (stdout), writes to the writer.
///
/// # Errors
///
/// Returns an error on failure.
pub fn write_key_data(
    writer: &mut dyn Write,
    tpm_key: &TpmKeyFile,
    output: Option<&Path>,
) -> Result<()> {
    let pem = tpm_key.to_pem()?;
    if let Some(path) = output {
        fs::write(path, pem.as_bytes())?;
    } else {
        write!(writer, "{pem}")?;
    }
    Ok(())
}

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError` if the object cannot be serialized into the buffer.
pub fn write_object<T: TpmMarshal>(obj: &T) -> Result<Vec<u8>, TpmError> {
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
        let err = read_file_input(Some(file.path())).unwrap_err();
        assert!(err.to_string().contains("unexpected eof"));
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
