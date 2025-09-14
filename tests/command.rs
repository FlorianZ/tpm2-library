// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

mod common;

use crate::common::{bytes_to_hex, hex_to_bytes, run_test};
use tpm2_protocol::{constant::TPM_MAX_COMMAND_SIZE, message::tpm_parse_command, TpmWriter};

const COMMAND_DATA: &str = include_str!("command.txt");

fn main() {
    let mut failed_count = 0;
    let mut test_count = 0;

    for (i, line) in COMMAND_DATA.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        test_count += 1;
        let test_name = format!("command_{}", i + 1);
        let success = run_test(&test_name, || {
            let original_bytes = hex_to_bytes(trimmed).unwrap();
            let (_handles, body, sessions) = tpm_parse_command(&original_bytes).unwrap();

            let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
            let built_len = {
                let mut writer = TpmWriter::new(&mut built_bytes);
                let tag = if sessions.is_empty() {
                    tpm2_protocol::data::TpmSt::NoSessions
                } else {
                    tpm2_protocol::data::TpmSt::Sessions
                };

                body.build(tag, &sessions, &mut writer).unwrap();
                writer.len()
            };
            let rebuilt_slice = &built_bytes[..built_len];

            assert_eq!(
                rebuilt_slice,
                original_bytes.as_slice(),
                "\nOriginal: {}\nRebuilt:  {}\n",
                bytes_to_hex(&original_bytes),
                bytes_to_hex(rebuilt_slice)
            );
        });
        if !success {
            failed_count += 1;
        }
    }

    eprintln!("\n{test_count} tests run.");
    if failed_count > 0 {
        eprintln!("{failed_count} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("All tests passed.");
}
