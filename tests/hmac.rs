// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use tpm2_crypto::TpmHash;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s_no_whitespace: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(s_no_whitespace).expect("invalid hex string")
}

#[test]
fn fail() {
    let key = b"key";
    let data = b"data";
    let alg = TpmHash::Sha256;
    let mac = alg.hmac(key, &[data.as_ref()]).expect("hmac ok");
    let mut bad = mac.clone();
    bad[0] ^= 0x01;
    assert!(alg.hmac_verify(key, &[data.as_ref()], &bad).is_err());
}

#[test]
fn pass() {
    let key = b"key";
    let data = b"data";
    let alg = TpmHash::Sha256;
    let mac = alg.hmac(key, &[data.as_ref()]).expect("hmac ok");
    assert!(alg.hmac_verify(key, &[data.as_ref()], &mac).is_ok());
    let mut bad = mac.clone();
    bad[0] ^= 0x01;
    assert!(alg.hmac_verify(key, &[data.as_ref()], &bad).is_err());
}

#[test]
fn rfc_4231_test_case_1() {
    let key = vec![0x0b; 20];
    let data = b"Hi There";
    let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    let alg = TpmHash::Sha256;
    let mac = alg.hmac(&key, &[data.as_ref()]).expect("hmac ok");
    assert_eq!(mac, expected);
}

#[test]
fn sm3_digest() {
    let input = hex_to_bytes(
        "0090414C494345313233405941484F4F2E434F4D
         787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
         63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
         421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
         0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
         0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A
         7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
    );
    let expected = hex_to_bytes("F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A");
    let alg = TpmHash::Sm3_256;
    let output = alg.digest(&[&input]).expect("digest ok");
    assert_eq!(output, expected);
}

#[test]
fn sha3_512_digest_abc() {
    let input = b"abc";
    let expected = hex_to_bytes(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    );
    let alg = TpmHash::Sha3_512;
    let output = alg.digest(&[input.as_ref()]).expect("digest ok");
    assert_eq!(output.len(), 64);
    assert_eq!(output, expected);
}

#[test]
fn sm3_and_sha3_512_differ() {
    let input = b"abc";
    let sm3 = TpmHash::Sm3_256
        .digest(&[input.as_ref()])
        .expect("sm3 digest ok");
    let sha3 = TpmHash::Sha3_512
        .digest(&[input.as_ref()])
        .expect("sha3-512 digest ok");

    assert_eq!(sm3.len(), 32);
    assert_eq!(sha3.len(), 64);
    assert_ne!(sm3, sha3);
}
