// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{io::IsTerminal, vec::Vec};
use tpm2_protocol::{TpmError, TpmNotDiscriminant};

#[allow(dead_code)]
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("invalid hex size");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "invalid hex character")
}

#[allow(dead_code)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn print_ok() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[32mOK\x1B[0m");
    } else {
        println!("OK");
    }
}

pub fn print_failed() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[31mFAILED\x1B[0m");
    } else {
        println!("FAILED");
    }
}

#[allow(dead_code)]
pub fn run_test(name: &str, test_fn: impl FnOnce() + std::panic::UnwindSafe) -> bool {
    print!("Test {name} ... ");
    let result = std::panic::catch_unwind(test_fn);
    if result.is_err() {
        print_failed();
        false
    } else {
        print_ok();
        true
    }
}

#[allow(dead_code)]
fn parse_key_value_u16(part: &str, key: &str) -> Result<u16, &'static str> {
    let value_str = part
        .trim()
        .strip_prefix(key)
        .ok_or("Malformed key")?
        .trim()
        .strip_prefix(':')
        .ok_or("Malformed key-value separator")?
        .trim();
    u16::from_str_radix(value_str.strip_prefix("0x").unwrap_or(value_str), 16)
        .map_err(|_| "Invalid number format")
}

#[allow(dead_code)]
fn parse_key_value_u32(part: &str, key: &str) -> Result<u32, &'static str> {
    let value_str = part
        .trim()
        .strip_prefix(key)
        .ok_or("Malformed key")?
        .trim()
        .strip_prefix(':')
        .ok_or("Malformed key-value separator")?
        .trim();
    u32::from_str_radix(value_str.strip_prefix("0x").unwrap_or(value_str), 16)
        .map_err(|_| "Invalid number format")
}

#[allow(dead_code)]
fn parse_key_value_str<'a>(part: &'a str, key: &str) -> Result<&'a str, &'static str> {
    part.trim()
        .strip_prefix(key)
        .ok_or("Malformed key")?
        .trim()
        .strip_prefix(':')
        .ok_or("Malformed key-value separator")?
        .trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or("Malformed string value: missing quotes")
}

#[allow(dead_code)]
pub fn parse_tpm_error_kind_str(s: &str) -> Result<TpmError, &'static str> {
    match s {
        "InvalidValue" => return Ok(TpmError::InvalidValue),
        "Underflow" => return Ok(TpmError::Underflow),
        "TrailingData" => return Ok(TpmError::TrailingData),
        _ => {}
    }

    if let Some(rest) = s.strip_prefix("NotDiscriminant") {
        let content = rest
            .trim()
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .ok_or("NotDiscriminant: missing parentheses")?
            .trim();

        let mut parts = content.splitn(2, ',');
        let type_name_part = parts
            .next()
            .ok_or("NotDiscriminant: missing type_name part")?;
        let value_part = parts.next().ok_or("NotDiscriminant: missing value part")?;

        let type_name_val = type_name_part
            .trim()
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or("NotDiscriminant: malformed type_name string")?;
        let type_name = match type_name_val {
            "TpmSt" => "TpmSt",
            _ => return Err("NotDiscriminant: unsupported type_name"),
        };
        let value_str = value_part.trim();
        if let Some(num_str) = value_str
            .strip_prefix("Unsigned(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let val = u64::from_str_radix(num_str.strip_prefix("0x").unwrap_or(num_str), 16)
                .map_err(|_| "NotDiscriminant: invalid number for Unsigned")?;
            return Ok(TpmError::NotDiscriminant(
                type_name,
                TpmNotDiscriminant::Unsigned(val),
            ));
        }

        return Err("NotDiscriminant: unsupported value variant");
    }

    Err("unknown variant")
}
