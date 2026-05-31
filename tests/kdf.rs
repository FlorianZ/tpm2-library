// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! `KDFa` and `KDFe` tests.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use tpm2_crypto::{TpmCryptoError, TpmHash};

fn kdfa_expected(
    alg: TpmHash,
    hmac_key: &[u8],
    label: &str,
    context_a: &[u8],
    context_b: &[u8],
    key_bits: u16,
) -> Vec<u8> {
    let key_bytes = (key_bits as usize).div_ceil(8);
    let mut key_stream = Vec::with_capacity(key_bytes);

    let mut label_bytes = label.as_bytes().to_vec();
    label_bytes.push(0);

    let mut counter: u32 = 1;
    while key_stream.len() < key_bytes {
        let mut payload = Vec::new();
        payload.extend_from_slice(&counter.to_be_bytes());
        payload.extend_from_slice(&label_bytes);
        payload.extend_from_slice(context_a);
        payload.extend_from_slice(context_b);
        payload.extend_from_slice(&u32::from(key_bits).to_be_bytes());

        let block = alg.hmac(hmac_key, &[payload.as_slice()]).expect("hmac ok");
        let remaining = key_bytes - key_stream.len();
        key_stream.extend_from_slice(&block[..remaining.min(block.len())]);

        counter = counter.wrapping_add(1);
    }

    key_stream
}

fn kdfe_expected(
    alg: TpmHash,
    z: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    key_bits: u16,
) -> Vec<u8> {
    let key_bytes = (key_bits as usize).div_ceil(8);
    let mut key_stream = Vec::with_capacity(key_bytes);

    let mut label_bytes = label.as_bytes().to_vec();
    if label_bytes.last() != Some(&0) {
        label_bytes.push(0);
    }

    let other_info = [label_bytes.as_slice(), context_u, context_v].concat();

    let mut counter: u32 = 1;
    while key_stream.len() < key_bytes {
        let mut payload = Vec::new();
        payload.extend_from_slice(&counter.to_be_bytes());
        payload.extend_from_slice(z);
        payload.extend_from_slice(&other_info);

        let block = alg.digest(&[payload.as_slice()]).expect("digest ok");
        let remaining = key_bytes - key_stream.len();
        key_stream.extend_from_slice(&block[..remaining.min(block.len())]);

        counter = counter.wrapping_add(1);
    }

    key_stream
}

#[test]
fn kdfa_sha256_eq() {
    let alg = TpmHash::Sha256;
    let key = b"supersecretkey";
    let label = "LABEL";
    let ctx_a = b"A";
    let ctx_b = b"B";
    let key_bits = 256;

    let expected = kdfa_expected(alg, key, label, ctx_a, ctx_b, key_bits);
    let actual = alg
        .kdfa(key, label, ctx_a, ctx_b, key_bits)
        .expect("kdfa ok");

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), (key_bits as usize).div_ceil(8));
}

#[test]
fn kdfa_key_length_variance() {
    let alg = TpmHash::Sha256;
    let key = b"k";
    let label = "X";
    let ctx_a = b"Y";
    let ctx_b = b"Z";

    let out_13 = alg.kdfa(key, label, ctx_a, ctx_b, 13).expect("kdfa 13");
    let out_13_ref = kdfa_expected(alg, key, label, ctx_a, ctx_b, 13);
    assert_eq!(out_13.len(), 2);
    assert_eq!(out_13, out_13_ref);

    let out_257 = alg.kdfa(key, label, ctx_a, ctx_b, 257).expect("kdfa 257");
    let out_257_ref = kdfa_expected(alg, key, label, ctx_a, ctx_b, 257);
    assert_eq!(out_257.len(), 33);
    assert_eq!(out_257, out_257_ref);
}

#[test]
fn kdfa_input_sensitivity() {
    let alg = TpmHash::Sha256;
    let key = b"key";
    let label = "LBL";
    let ctx_a = b"AAA";
    let ctx_b = b"BBB";

    let base = alg.kdfa(key, label, ctx_a, ctx_b, 128).expect("base");
    let diff_label = alg.kdfa(key, "LBL2", ctx_a, ctx_b, 128).expect("label");
    let diff_a = alg.kdfa(key, label, b"AAAA", ctx_b, 128).expect("a");
    let diff_b = alg.kdfa(key, label, ctx_a, b"BBBB", 128).expect("b");
    let diff_key = alg.kdfa(b"key2", label, ctx_a, ctx_b, 128).expect("key");

    assert_ne!(base, diff_label);
    assert_ne!(base, diff_a);
    assert_ne!(base, diff_b);
    assert_ne!(base, diff_key);
}

#[test]
fn kdfa_into_matches_kdfa() {
    let alg = TpmHash::Sha256;
    let key = b"k";
    let label = "X";
    let ctx_a = b"Y";
    let ctx_b = b"Z";
    let key_bits = 257;
    let expected = alg
        .kdfa(key, label, ctx_a, ctx_b, key_bits)
        .expect("kdfa ok");
    let mut output = [0xa5; 64];

    let len = alg
        .kdfa_into(key, label, ctx_a, ctx_b, key_bits, &mut output)
        .expect("kdfa_into ok");

    assert_eq!(len, expected.len());
    assert_eq!(&output[..len], expected.as_slice());
    assert_eq!(output[len], 0xa5);
}

#[test]
fn kdfa_into_rejects_short_buffer() {
    let alg = TpmHash::Sha256;
    let mut output = [0; 15];

    let result = alg.kdfa_into(b"key", "LBL", b"A", b"B", 128, &mut output);

    assert!(matches!(
        result,
        Err(TpmCryptoError::BufferTooSmall {
            expected: 16,
            actual: 15
        })
    ));
}

#[test]
fn kdfe_sha256_eq() {
    let alg = TpmHash::Sha256;
    let z = b"sharedsecretZ";
    let label = "DUPLICATE";
    let u = b"Ux";
    let v = b"Vx";
    let key_bits = 256;

    let expected = kdfe_expected(alg, z, label, u, v, key_bits);
    let actual = alg.kdfe(z, label, u, v, key_bits).expect("kdfe ok");

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), (key_bits as usize).div_ceil(8));
}

#[test]
fn kdfe_into_matches_kdfe() {
    let alg = TpmHash::Sha256;
    let z = b"sharedsecretZ";
    let label = "DUPLICATE";
    let u = b"Ux";
    let v = b"Vx";
    let key_bits = 257;
    let expected = alg.kdfe(z, label, u, v, key_bits).expect("kdfe ok");
    let mut output = [0xa5; 64];

    let len = alg
        .kdfe_into(z, label, u, v, key_bits, &mut output)
        .expect("kdfe_into ok");

    assert_eq!(len, expected.len());
    assert_eq!(&output[..len], expected.as_slice());
    assert_eq!(output[len], 0xa5);
}

#[test]
fn kdfe_into_rejects_short_buffer() {
    let alg = TpmHash::Sha256;
    let mut output = [0; 15];

    let result = alg.kdfe_into(b"Z", "LBL", b"A", b"B", 128, &mut output);

    assert!(matches!(
        result,
        Err(TpmCryptoError::BufferTooSmall {
            expected: 16,
            actual: 15
        })
    ));
}

#[test]
fn kdfe_label_null_termination_eq() {
    let alg = TpmHash::Sha256;
    let z_val = b"Z";
    let u_val = b"U";
    let v_val = b"V";

    let res_a = alg.kdfe(z_val, "LAB", u_val, v_val, 128).expect("LAB");
    let res_b = alg
        .kdfe(z_val, "LAB\u{0}", u_val, v_val, 128)
        .expect("LAB\\0");
    assert_eq!(res_a, res_b);
}

#[test]
fn kdfa_label_null_termination_diff() {
    let alg = TpmHash::Sha256;
    let key = b"K";
    let ctx_a = b"A";
    let ctx_b = b"B";

    let res_a = alg.kdfa(key, "LAB", ctx_a, ctx_b, 128).expect("LAB");
    let res_b = alg
        .kdfa(key, "LAB\u{0}", ctx_a, ctx_b, 128)
        .expect("LAB\\0");
    assert_ne!(res_a, res_b);
}
