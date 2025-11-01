// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod cli;
pub mod command;
pub mod device;
pub mod io;
pub mod key;
pub mod pcr;
pub mod policy;
pub mod print;
pub mod session;
pub mod spinner;
pub mod template;
pub mod vtpm;

/// A global flag to signal graceful teardown of the application.
///
/// Set by the Ctrl-C handler to allow the main loop to finish its current
/// operation and perform necessary teardown (e.g., flushing TPM contexts)
/// before exiting.
pub static TEARDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Serialize a type implementing `TpmMarshal` type into `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError` if the object cannot be serialized into the buffer.
pub fn write_object<T: tpm2_protocol::TpmMarshal>(
    obj: &T,
) -> Result<Vec<u8>, tpm2_protocol::TpmError> {
    let mut buf = vec![0u8; tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = tpm2_protocol::TpmWriter::new(&mut buf);
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
