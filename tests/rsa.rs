//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//!
//! RSA-related tests.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::{pkey::PKey, rsa::Rsa};
use rand::{SeedableRng, rngs::StdRng};
use tpm2_crypto::{TpmExternalKey, TpmHash, TpmRsaExternalKey};

#[test]
fn rsa_to_seed_with_default_exponent() {
    let rsa = Rsa::generate(2048).expect("rsa generate");
    let pkey = PKey::from_rsa(rsa).expect("pkey");
    let der = pkey.private_key_to_der().expect("der");

    let (ext_key, private) = TpmRsaExternalKey::from_der(&der).expect("from_der");
    assert_eq!(u32::from(ext_key.exponent()), 0);
    assert_eq!(private.as_ref().len(), 128);

    let mut rng = rand::rng();
    let alg = TpmHash::Sha256;
    let (seed, encrypted) = ext_key.to_seed(alg, &mut rng).expect("to_seed");

    assert_eq!(seed.len(), alg.size());

    let key_bits = u16::from(ext_key.key_bits());
    let encrypted_len = encrypted.as_ref().len();
    assert_eq!(encrypted_len, usize::from(key_bits / 8));
}

#[test]
fn rsa_to_seed_uses_supplied_rng() {
    let rsa = Rsa::generate(2048).expect("rsa generate");
    let pkey = PKey::from_rsa(rsa).expect("pkey");
    let der = pkey.private_key_to_der().expect("der");

    let (ext_key, _private) = TpmRsaExternalKey::from_der(&der).expect("from_der");

    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(42);
    let mut rng3 = StdRng::seed_from_u64(7);

    let alg = TpmHash::Sha256;

    let (seed1, _) = ext_key.to_seed(alg, &mut rng1).expect("to_seed 1");
    let (seed2, _) = ext_key.to_seed(alg, &mut rng2).expect("to_seed 2");
    let (seed3, _) = ext_key.to_seed(alg, &mut rng3).expect("to_seed 3");

    assert_eq!(seed1, seed2);
    assert_ne!(seed1, seed3);
}
