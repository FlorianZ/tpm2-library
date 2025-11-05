//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use std::str;
use tpm2_policy_language::PolicyState;
use tpm2_tpmkey::TpmKey;

const PEM_ORIGINAL_BYTES: &[u8] = include_bin!("policy_1.key");

#[test]
fn test_complex_policy_roundtrip() {
    let context = PolicyState::new();
    let pem_original = str::from_utf8(PEM_ORIGINAL_BYTES).expect("policy_1.key is not valid UTF-8");

    let key_original =
        TpmKey::from_pem(PEM_ORIGINAL_BYTES, &context).expect("Failed to parse original PEM");

    let pem_saved = key_original
        .to_pem(&context)
        .expect("Failed to serialize key to PEM");

    let key_reloaded = TpmKey::from_pem(pem_saved.as_bytes(), &context)
        .expect("Failed to parse re-serialized PEM");

    assert_eq!(key_original, key_reloaded);

    assert_eq!(pem_original, pem_saved);
}
