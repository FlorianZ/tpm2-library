//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use tpm2_policy_language::PolicyState;
use tpm2_tpmkey::TpmKey;

const PEM_ORIGINAL_STR: &str = include_str!("policy_1.key");

#[test]
fn test_complex_policy_roundtrip() {
    let context = PolicyState::default();

    let key_original = TpmKey::from_pem(PEM_ORIGINAL_STR.as_bytes(), &context)
        .expect("Failed to parse original PEM");

    let pem_saved = key_original
        .to_pem(&context)
        .expect("Failed to serialize key to PEM");

    let key_reloaded = TpmKey::from_pem(pem_saved.as_bytes(), &context)
        .expect("Failed to parse re-serialized PEM");

    assert_eq!(key_original, key_reloaded);
    assert_eq!(PEM_ORIGINAL_STR, pem_saved);
}
