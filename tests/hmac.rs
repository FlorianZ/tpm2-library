// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use tpm2_crypto::{hmac, hmac_verify};
use tpm2_protocol::data::TpmAlgId;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        v.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    v
}

#[test]
fn fail() {
    let key = b"key";
    let data = b"data";
    let mac = hmac(TpmAlgId::Sha256, key, &[data.as_ref()]).expect("hmac ok");
    let mut bad = mac.clone();
    bad[0] ^= 0x01;
    assert!(hmac_verify(TpmAlgId::Sha256, key, &[data.as_ref()], &bad).is_err());
}

#[test]
fn pass() {
    let key = b"key";
    let data = b"data";
    let mac = hmac(TpmAlgId::Sha256, key, &[data.as_ref()]).expect("hmac ok");
    assert!(hmac_verify(TpmAlgId::Sha256, key, &[data.as_ref()], &mac).is_ok());
    let mut bad = mac.clone();
    bad[0] ^= 0x01;
    assert!(hmac_verify(TpmAlgId::Sha256, key, &[data.as_ref()], &bad).is_err());
}

#[test]
fn rfc_4231_test_case_1() {
    let key = vec![0x0b; 20];
    let data = b"Hi There";
    let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    let mac = hmac(TpmAlgId::Sha256, &key, &[data.as_ref()]).expect("hmac ok");
    assert_eq!(mac, expected);
}
