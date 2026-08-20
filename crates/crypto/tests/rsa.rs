//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//!
//! RSA-related tests.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::{pkey::PKey, rsa::Rsa};
use tpm2_crypto::{TpmExternalKey, TpmHash, TpmRsaExternalKey};

#[test]
fn rsa_to_seed_with_default_exponent() {
    let rsa = Rsa::generate(2048).expect("rsa generate");
    let pkey = PKey::from_rsa(rsa).expect("pkey");
    let der = pkey.private_key_to_der().expect("der");

    let (ext_key, private) = TpmRsaExternalKey::from_der(&der).expect("from_der");
    assert_eq!(u32::from(ext_key.exponent()), 0);
    assert_eq!(private.as_ref().len(), 128);

    let alg = TpmHash::Sha256;
    let (seed, encrypted) = ext_key.to_seed(alg).expect("to_seed");

    assert_eq!(seed.len(), alg.size());

    let key_bits = u16::from(ext_key.key_bits());
    let encrypted_len = encrypted.as_ref().len();
    assert_eq!(encrypted_len, usize::from(key_bits / 8));
}
