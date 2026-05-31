//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen
//!
//! ECC-related tests.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::{ec::EcGroup, ec::EcKey, nid::Nid, pkey::PKey};
use tpm2_crypto::{TpmEccExternalKey, TpmEllipticCurve, TpmExternalKey};

#[test]
fn ecc_from_der_returns_bounded_sensitive() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("group");
    let ec_key = EcKey::generate(&group).expect("ec key");
    let pkey = PKey::from_ec_key(ec_key).expect("pkey");
    let der = pkey.private_key_to_der().expect("der");

    let (ext_key, private) = TpmEccExternalKey::from_der(&der).expect("from_der");

    assert_eq!(ext_key.curve(), TpmEllipticCurve::NistP256);
    assert!(!private.as_ref().is_empty());
}
