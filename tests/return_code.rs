// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

mod common;

use crate::common::{print_failed, print_ok};
use std::convert::TryFrom;
use tpm2_protocol::data::TpmRc;

fn test_return_code() {
    let cases = [
        ("TPM_RC_SUCCESS", 0x0000),
        ("[TPM_RC_HANDLE, handle[1]]", 0x018B),
        ("[TPM_RC_ATTRIBUTES, handle[4]]", 0x0482),
        ("[TPM_RC_AUTH_FAIL, session[0]]", 0x088E),
        ("TPM_RC_NV_UNAVAILABLE", 0x0923),
    ];

    for (expected, rc_raw) in cases {
        let rc = TpmRc::try_from(rc_raw).unwrap();
        assert_eq!(rc.to_string(), expected, "{expected}");
    }
}

fn main() {
    print!("Test return_code ... ");
    let result = std::panic::catch_unwind(test_return_code);
    if result.is_err() {
        print_failed();
    } else {
        print_ok();
    }
}
