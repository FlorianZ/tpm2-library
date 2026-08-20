// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

#[path = "common/error_expectation.rs"]
mod error_expectation;
#[path = "common/hex.rs"]
mod hex;
#[path = "common/status.rs"]
mod status;

use crate::error_expectation::{assert_tpm_error_matches, unmarshal_tpm_error_expectation};
use crate::hex::{bytes_to_hex, hex_to_bytes};
use crate::status::{print_failed, print_ok};
use tpm2_protocol::{
    data::{TpmCc, TpmRc},
    frame::{TpmCommand, TpmResponse},
};

const MESSAGE_DATA: &str = include_str!("message.txt");

fn run_test(name: &str, test_fn: impl FnOnce() + std::panic::UnwindSafe) -> bool {
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

            let cc_u32 = u32::from_str_radix(cc_str, 16)
                .unwrap_or_else(|_| panic!("malformed command code: {cc_str}"));
            let cc = TpmCc::try_from(cc_u32)
                .unwrap_or_else(|_| panic!("invalid command code: {cc_u32}"));
            let original_bytes = hex_to_bytes(dump_str).unwrap();

            match type_str {
                "Command" => {
                    if outcome_str == "0000" {
                        let command = TpmCommand::cast(&original_bytes).unwrap();
                        command.validate().unwrap();

                        assert_eq!(
                            command.as_bytes(),
                            original_bytes.as_slice(),
                            "\nOriginal: {}\nView:     {}\n",
                            bytes_to_hex(&original_bytes),
                            bytes_to_hex(command.as_bytes())
                        );
                    } else {
                        let expected_err = unmarshal_tpm_error_expectation(&outcome_str)
                            .unwrap_or_else(|e| {
                                panic!("failed to unmarshal outcome string '{outcome_str}': {e}")
                            });
                        let actual_err = TpmCommand::cast(&original_bytes)
                            .and_then(|command| command.validate())
                            .err()
                            .expect("expected TpmError, got Ok");

                        assert_tpm_error_matches(actual_err, &expected_err);
                    }
                }
                "Response" => {
                    if let Ok(expected_rc_u32) = u32::from_str_radix(&outcome_str, 16) {
                        let response = TpmResponse::cast(&original_bytes)
                            .expect("response cast failed on a TpmRc test case");
                        if expected_rc_u32 == 0x0000 {
                            response
                                .validate(cc)
                                .expect("response validation failed on a success test case");
                            assert_eq!(response.rc().unwrap().value(), 0x0000);
                            assert_eq!(
                                response.as_bytes(),
                                original_bytes.as_slice(),
                                "\nOriginal: {}\nView:     {}\n",
                                bytes_to_hex(&original_bytes),
                                bytes_to_hex(response.as_bytes())
                            );
                        } else {
                            let expected_rc =
                                TpmRc::try_from(expected_rc_u32).unwrap_or_else(|_| {
                                    panic!("invalid expected TpmRc value in test: {outcome_str}")
                                });

                            let actual_rc = response.rc().expect("invalid TpmRc value in response");

                            assert_eq!(actual_rc, expected_rc, "Mismatched TpmRc error");
                            assert_eq!(
                                response.as_bytes(),
                                original_bytes.as_slice(),
                                "Error response view did not roundtrip correctly"
                            );
                        }
                    } else {
                        let expected_err = unmarshal_tpm_error_expectation(&outcome_str)
                            .unwrap_or_else(|e| {
                                panic!("failed to unmarshal outcome string '{outcome_str}': {e}")
                            });
                        let actual_err = TpmResponse::cast(&original_bytes)
                            .and_then(|response| response.validate(cc))
                            .err()
                            .expect("expected TpmError, got Ok");

                        assert_tpm_error_matches(actual_err, &expected_err);
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
