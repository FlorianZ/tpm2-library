// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handle display/parse round-trip using rstest.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::str::FromStr;
use tpm2_vtpm::VtpmHandle;

#[rstest]
#[case("tpm:81000001")]
#[case("vtpm:*")]
#[case("tpm:81??????")]
#[case("tpm:81??00??")]
fn handle_roundtrip(#[case] input: &str) {
    let h1 = VtpmHandle::from_str(input).unwrap();
    let s = h1.to_string();
    let h2 = VtpmHandle::from_str(&s).unwrap();

    assert_eq!(h1, h2);
    assert_eq!(s, input);
}
