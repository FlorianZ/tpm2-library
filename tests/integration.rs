//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    rsa::Rsa,
};
use std::path::Path;
use tempfile::TempDir;

const TPM2SH_PATH: &str = env!("CARGO_BIN_EXE_tpm2sh");
const SEALED_DATA: &str = "deadbeef";

fn tpm2sh(cache_dir: &Path, args: &[&str]) -> duct::Expression {
    duct::cmd(TPM2SH_PATH, args)
        .env("TPM2SH_CACHE_PATH", cache_dir)
        .stderr_to_stdout()
}

#[test]
fn integration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache_path = temp_dir.path();

    tpm2sh(cache_path, &["delete", "vtpm:*"]).run().unwrap();

    let primary_handle = tpm2sh(
        cache_path,
        &["create-primary", "-H", "owner", "ecc-nist-p256:sha256"],
    )
    .read()
    .unwrap();

    let primary_handle = primary_handle.trim();
    assert!(primary_handle.starts_with("vtpm:"),);
    eprintln!("Primary handle: {primary_handle}");

    let create_args = [
        "create",
        primary_handle,
        "keyedhash:sha256",
        "--data",
        SEALED_DATA,
        "--policy",
        "secret(tpm:81000001)",
    ];

    let sealed_handle = tpm2sh(cache_path, &create_args)
        .pipe(tpm2sh(cache_path, &["load"]))
        .read()
        .unwrap();
    let sealed_handle = sealed_handle.trim();

    println!("Sealed secret handle: {sealed_handle}");

    let unseal_output = tpm2sh(cache_path, &["unseal", "--hex", sealed_handle])
        .read()
        .unwrap();

    assert_eq!(unseal_output.trim(), SEALED_DATA);

    let create_pcr_args = [
        "create",
        primary_handle,
        "keyedhash:sha256",
        "--data",
        SEALED_DATA,
        "--policy",
        "pcr(sha256:7) or pcr(sha256:15)",
    ];

    let sealed_handle_pcr = tpm2sh(cache_path, &create_pcr_args)
        .pipe(tpm2sh(cache_path, &["load"]))
        .read()
        .unwrap();
    let sealed_handle_pcr = sealed_handle_pcr.trim();

    println!("Sealed PCRs handle: {sealed_handle_pcr}");

    let unseal_pcr_output = tpm2sh(cache_path, &["unseal", "--hex", sealed_handle_pcr])
        .read()
        .unwrap();

    assert_eq!(unseal_pcr_output.trim(), SEALED_DATA);

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let ec_pem = ec_key.private_key_to_pem().unwrap();
    let ecc_handle = tpm2sh(cache_path, &["convert", primary_handle])
        .stdin_bytes(ec_pem)
        .pipe(tpm2sh(cache_path, &["load"]))
        .read()
        .unwrap();
    let ecc_handle = ecc_handle.trim();

    assert!(ecc_handle.starts_with("vtpm:"),);
    println!("External ECC handle: {ecc_handle}");

    let rsa = Rsa::generate(2048).unwrap();
    let rsa_pem = rsa.private_key_to_pem().unwrap();
    let rsa_handle = tpm2sh(cache_path, &["convert", primary_handle])
        .stdin_bytes(rsa_pem)
        .pipe(tpm2sh(cache_path, &["load"]))
        .read()
        .unwrap();
    let rsa_handle = rsa_handle.trim();

    assert!(rsa_handle.starts_with("vtpm:"),);
    println!("External RSA handle: {rsa_handle}");

    let delete_output = tpm2sh(cache_path, &["delete", "vtpm:*"]).read().unwrap();

    assert!(delete_output.contains(primary_handle.trim().strip_prefix("vtpm:").unwrap()),);
    assert!(delete_output.contains(sealed_handle.trim().strip_prefix("vtpm:").unwrap()),);
}
