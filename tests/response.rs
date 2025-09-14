// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

mod common;

use crate::common::{bytes_to_hex, hex_to_bytes, parse_tpm_error_kind_str, run_test};
use std::convert::TryFrom;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{TpmCc, TpmRc, TpmRcBase},
    message::{tpm_build_response, tpm_parse_response, TpmStartupResponse},
    TpmWriter,
};

const RESPONSE_DATA: &str = include_str!("response.txt");

fn main() {
    let mut failed_count = 0;
    let mut test_count = 0;

    for (i, line) in RESPONSE_DATA.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        test_count += 1;
        let test_name = format!("response_{}", i + 1);
        let success = run_test(&test_name, || {
            let mut parts = trimmed.split_whitespace().collect::<Vec<&str>>();
            let hex_str = parts.pop().expect("malformed test case: missing dump");
            let cc_hex_str = parts.remove(0);
            let outcome_str = parts.join(" ");

            if cc_hex_str.len() != 4 {
                panic!("invalid CC format");
            }

            let cc_val = u16::from_str_radix(cc_hex_str, 16).expect("invalid CC format");
            let cc = TpmCc::try_from(cc_val as u32).expect("unknown command code");

            let original_bytes = hex_to_bytes(hex_str).unwrap();

            if outcome_str == "Success" {
                let parse_result = tpm_parse_response(cc, &original_bytes)
                    .expect("parsing failed on a success test case");

                let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
                let built_len = match parse_result {
                    Ok((body, sessions)) => {
                        let mut writer = TpmWriter::new(&mut built_bytes);
                        let rc = TpmRc::from(TpmRcBase::Success);
                        body.build(rc, &sessions, &mut writer).unwrap();
                        writer.len()
                    }
                    Err(rc) => {
                        assert!(original_bytes.len() == 10,);
                        let mut writer = TpmWriter::new(&mut built_bytes);
                        tpm_build_response(&TpmStartupResponse::default(), &[], rc, &mut writer)
                            .unwrap();
                        writer.len()
                    }
                };
                let rebuilt_slice = &built_bytes[..built_len];
                assert_eq!(
                    rebuilt_slice,
                    original_bytes.as_slice(),
                    "\nOriginal: {}\nRebuilt:  {}\n",
                    bytes_to_hex(&original_bytes),
                    bytes_to_hex(rebuilt_slice)
                );
            } else {
                let expected_err = parse_tpm_error_kind_str(&outcome_str).unwrap_or_else(|e| {
                    panic!("failed to parse outcome string '{outcome_str}': {e}")
                });

                let parse_result = tpm_parse_response(cc, &original_bytes);
                match parse_result {
                    Ok(Ok(_)) => panic!("expected a parsing error, but got success"),
                    Ok(Err(rc)) => panic!("expected a parsing error, but got TpmRc '{rc}'"),
                    Err(actual_err) => {
                        assert_eq!(actual_err, expected_err, "mismatched parsing error type");
                    }
                }
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
