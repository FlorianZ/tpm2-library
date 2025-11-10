//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use tpm2_policy_language::PolicyState;
use tpm2_tpmkey::TpmKey;

const POLICY_1_PEM: &str = include_str!("policy_1.pem");

#[test]
fn test_complex_policy_roundtrip() {
    let context = PolicyState::default();
    let key_a = TpmKey::from_pem(POLICY_1_PEM.as_bytes(), &context).unwrap();
    let pem_b = key_a.to_pem(&context).unwrap().replace("\r\n", "\n");
    let key_b = TpmKey::from_pem(pem_b.as_bytes(), &context).unwrap();
    assert_eq!(key_a, key_b);
    assert_eq!(POLICY_1_PEM, pem_b);
}
