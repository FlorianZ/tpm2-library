// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

mod common;

use crate::common::{bytes_to_hex, hex_to_bytes, parse_tpm_error_kind_str, run_test};
use std::str::FromStr;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{TpmCc, TpmRc, TpmRcBase},
    message::{tpm_build_response, tpm_parse_command, tpm_parse_response, TpmStartupResponse},
    TpmWriter,
};

const MESSAGE_DATA: &str = include_str!("message.txt");

fn main() {
    let mut failed_count = 0;
    let mut test_count = 0;

    for (i, line) in MESSAGE_DATA.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        test_count += 1;
        let test_name = format!("message_{}", i + 1);
        let success = run_test(&test_name, || {
            let mut parts = trimmed.split_whitespace().collect::<Vec<&str>>();
            let dump_str = parts.pop().expect("malformed test case: missing dump");
            let type_str = parts.remove(1);
            let cc_str = parts.remove(0);
            let outcome_str = parts.join(" ");

            let cc = TpmCc::from_str(cc_str)
                .unwrap_or_else(|_| panic!("unknown command code string: {cc_str}"));
            let original_bytes = hex_to_bytes(dump_str).unwrap();

            match type_str {
                "Command" => {
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
                }
                "Response" => {
                    let parse_result = tpm_parse_response(cc, &original_bytes);

                    if outcome_str == "Success" {
                        let (body, sessions) = parse_result
                            .expect("parsing failed on a success test case")
                            .expect("expected success but got TpmRc error");

                        let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
                        let built_len = {
                            let mut writer = TpmWriter::new(&mut built_bytes);
                            let rc = TpmRc::from(TpmRcBase::Success);
                            body.build(rc, &sessions, &mut writer).unwrap();
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
                    } else if let Ok(expected_rc_base) = TpmRcBase::from_str(&outcome_str) {
                        let actual_rc = parse_result
                            .expect("parsing failed on a TpmRc test case")
                            .err()
                            .expect("expected a TpmRc error but got success");

                        let actual_rc_base = match actual_rc {
                            TpmRc::Fmt0(base) => base,
                            TpmRc::Fmt1(fmt1) => fmt1.base,
                            TpmRc::Warn(base) => base,
                        };
                        assert_eq!(actual_rc_base, expected_rc_base, "Mismatched TpmRc error");

                        let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
                        let built_len = {
                            let mut writer = TpmWriter::new(&mut built_bytes);
                            tpm_build_response(
                                &TpmStartupResponse::default(),
                                &[],
                                actual_rc,
                                &mut writer,
                            )
                            .unwrap();
                            writer.len()
                        };
                        let rebuilt_slice = &built_bytes[..built_len];
                        assert_eq!(
                            rebuilt_slice,
                            original_bytes.as_slice(),
                            "Error response did not roundtrip correctly"
                        );
                    } else {
                        let expected_err =
                            parse_tpm_error_kind_str(&outcome_str).unwrap_or_else(|e| {
                                panic!("failed to parse outcome string '{outcome_str}': {e}")
                            });
                        let actual_err = parse_result.err().expect("expected TpmErrorKind, got Ok");
                        assert_eq!(actual_err, expected_err, "mismatched parsing error type");
                    }
                }
                _ => panic!("invalid message type in test case"),
            }
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
