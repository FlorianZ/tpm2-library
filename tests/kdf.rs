// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! KDFa and KDFe tests.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use tpm2_crypto::{digest, hmac, kdfa, kdfe};
use tpm2_protocol::data::TpmAlgId;

fn kdfa_expected(
    alg: TpmAlgId,
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

        let block = hmac(alg, hmac_key, &[payload.as_slice()]).expect("hmac ok");
        let remaining = key_bytes - key_stream.len();
        key_stream.extend_from_slice(&block[..remaining.min(block.len())]);

        counter = counter.wrapping_add(1);
    }

    key_stream
}

fn kdfe_expected(
    alg: TpmAlgId,
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

        let block = digest(alg, &[payload.as_slice()]).expect("digest ok");
        let remaining = key_bytes - key_stream.len();
        key_stream.extend_from_slice(&block[..remaining.min(block.len())]);

        counter = counter.wrapping_add(1);
    }

    key_stream
}

#[test]
fn kdfa_sha256_eq() {
    let alg = TpmAlgId::Sha256;
    let key = b"supersecretkey";
    let label = "LABEL";
    let ctx_a = b"A";
    let ctx_b = b"B";
    let key_bits = 256;

    let expected = kdfa_expected(alg, key, label, ctx_a, ctx_b, key_bits);
    let actual = kdfa(alg, key, label, ctx_a, ctx_b, key_bits).expect("kdfa ok");

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), (key_bits as usize).div_ceil(8));
}

#[test]
fn kdfa_key_length_variance() {
    let alg = TpmAlgId::Sha256;
    let key = b"k";
    let label = "X";
    let ctx_a = b"Y";
    let ctx_b = b"Z";

    let out_13 = kdfa(alg, key, label, ctx_a, ctx_b, 13).expect("kdfa 13");
    let out_13_ref = kdfa_expected(alg, key, label, ctx_a, ctx_b, 13);
    assert_eq!(out_13.len(), 2);
    assert_eq!(out_13, out_13_ref);

    let out_257 = kdfa(alg, key, label, ctx_a, ctx_b, 257).expect("kdfa 257");
    let out_257_ref = kdfa_expected(alg, key, label, ctx_a, ctx_b, 257);
    assert_eq!(out_257.len(), 33);
    assert_eq!(out_257, out_257_ref);
}

#[test]
fn kdfa_input_sensitivity() {
    let alg = TpmAlgId::Sha256;
    let key = b"key";
    let label = "LBL";
    let ctx_a = b"AAA";
    let ctx_b = b"BBB";

    let base = kdfa(alg, key, label, ctx_a, ctx_b, 128).expect("base");
    let diff_label = kdfa(alg, key, "LBL2", ctx_a, ctx_b, 128).expect("label");
    let diff_a = kdfa(alg, key, label, b"AAAA", ctx_b, 128).expect("a");
    let diff_b = kdfa(alg, key, label, ctx_a, b"BBBB", 128).expect("b");
    let diff_key = kdfa(alg, b"key2", label, ctx_a, ctx_b, 128).expect("key");

    assert_ne!(base, diff_label);
    assert_ne!(base, diff_a);
    assert_ne!(base, diff_b);
    assert_ne!(base, diff_key);
}

#[test]
fn kdfe_sha256_eq() {
    let alg = TpmAlgId::Sha256;
    let z = b"sharedsecretZ";
    let label = "DUPLICATE";
    let u = b"Ux";
    let v = b"Vx";
    let key_bits = 256;

    let expected = kdfe_expected(alg, z, label, u, v, key_bits);
    let actual = kdfe(alg, z, label, u, v, key_bits).expect("kdfe ok");

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), (key_bits as usize).div_ceil(8));
}

#[test]
fn kdfe_label_null_termination_eq() {
    let alg = TpmAlgId::Sha256;
    let z = b"Z";
    let u = b"U";
    let v = b"V";

    let a = kdfe(alg, z, "LAB", u, v, 128).expect("LAB");
    let b = kdfe(alg, z, "LAB\u{0}", u, v, 128).expect("LAB\\0");
    assert_eq!(a, b);
}

#[test]
fn kdfa_label_null_termination_diff() {
    let alg = TpmAlgId::Sha256;
    let key = b"K";
    let ctx_a = b"A";
    let ctx_b = b"B";

    let a = kdfa(alg, key, "LAB", ctx_a, ctx_b, 128).expect("LAB");
    let b = kdfa(alg, key, "LAB\u{0}", ctx_a, ctx_b, 128).expect("LAB\\0");
    assert_ne!(a, b);
}
