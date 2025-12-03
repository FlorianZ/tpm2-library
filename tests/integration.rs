// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::rsa::Rsa;
use rstest::rstest;
use std::path::Path;
use tempfile::TempDir;

const TPM2SH_PATH: &str = env!("CARGO_BIN_EXE_tpm2sh");
const SEALED_DATA: &str = "deadbeef";

fn tpm2sh(cache_dir: &Path, args: &[&str]) -> duct::Expression {
    duct::cmd(TPM2SH_PATH, args).env("TPM2SH_CACHE_PATH", cache_dir)
}

fn new_cache_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp dir")
}

fn handle_auth_arg(handle: &str, password_hex: &str) -> String {
    format!("{handle}:{password_hex}")
}

#[test]
fn auth_with_value() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    let primary_handle = create_primary_ecc_sha256(cache_path, Some("deadbeef"));
    let primary_handle_str = primary_handle.as_str();

    let parent_auth_arg = handle_auth_arg(primary_handle_str, "deadbeef");

    let native_child_output = tpm2sh(
        cache_path,
        &[
            "seal",
            primary_handle_str,
            "--data",
            SEALED_DATA,
            "--auth",
            parent_auth_arg.as_str(),
            "--password",
            "deadbeef",
        ],
    )
    .pipe(tpm2sh(
        cache_path,
        &[
            "load",
            primary_handle_str,
            "--auth",
            parent_auth_arg.as_str(),
        ],
    ))
    .read()
    .expect("Failed to create native child");
    let native_child = native_child_output.trim().to_string();

    let child_auth_arg = handle_auth_arg(native_child.as_str(), "deadbeef");

    tpm2sh(
        cache_path,
        &[
            "unseal",
            native_child.as_str(),
            "--auth",
            child_auth_arg.as_str(),
        ],
    )
    .run()
    .expect("Failed to unseal with correct auth");

    let rsa = Rsa::generate(2048).unwrap();
    let rsa_pem = rsa.private_key_to_pem().unwrap();

    let _ = tpm2sh(
        cache_path,
        &[
            "import",
            primary_handle_str,
            "--auth",
            parent_auth_arg.as_str(),
            "--password",
            "deadbeef",
        ],
    )
    .stdin_bytes(rsa_pem)
    .pipe(tpm2sh(
        cache_path,
        &[
            "load",
            primary_handle_str,
            "--auth",
            parent_auth_arg.as_str(),
        ],
    ))
    .read()
    .expect("Failed to import external key");
}

#[test]
fn auth_policy_secret_with_value() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    let primary_handle = create_primary_ecc_sha256(cache_path, Some("deadbeef"));
    let primary_handle_str = primary_handle.as_str();
    let parent_auth = handle_auth_arg(primary_handle_str, "deadbeef");

    let policy_str = format!("secret({primary_handle_str})");

    let create_args = [
        "seal",
        primary_handle_str,
        "--data",
        SEALED_DATA,
        "--auth",
        parent_auth.as_str(),
        "--policy",
        policy_str.as_str(),
    ];

    let sealed_output = tpm2sh(cache_path, &create_args)
        .pipe(tpm2sh(
            cache_path,
            &["load", primary_handle_str, "--auth", parent_auth.as_str()],
        ))
        .read()
        .expect("Failed to create and load policy-protected object");
    let sealed_handle = sealed_output.trim().to_string();

    let unseal_args_with_auth = [
        "unseal",
        sealed_handle.as_str(),
        "--auth",
        parent_auth.as_str(),
    ];

    let output = tpm2sh(cache_path, &unseal_args_with_auth)
        .read()
        .expect("Failed to unseal with policy and auth");
    assert_eq!(output.trim(), SEALED_DATA);
}

#[test]
fn auth_with_policy() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    tpm2sh(cache_path, &["delete", "80*"]).run().unwrap();

    let primary_handle = create_primary_ecc_sha256(cache_path, None);
    let primary_handle_str = primary_handle.as_str();

    let policy_str = format!("secret({primary_handle_str})");

    let create_args = [
        "seal",
        primary_handle_str,
        "--data",
        SEALED_DATA,
        "--policy",
        policy_str.as_str(),
    ];

    let sealed_output = tpm2sh(cache_path, &create_args)
        .pipe(tpm2sh(cache_path, &["load", primary_handle_str]))
        .read()
        .unwrap();
    let sealed_handle = sealed_output.trim().to_string();

    let unseal_output = tpm2sh(cache_path, &["unseal", sealed_handle.as_str()])
        .read()
        .unwrap();

    assert_eq!(unseal_output.trim(), SEALED_DATA);

    let create_pcr_args = [
        "seal",
        primary_handle_str,
        "--data",
        SEALED_DATA,
        "--policy",
        "pcr(sha256:7) or pcr(sha256:15)",
    ];

    let sealed_pcr_output = tpm2sh(cache_path, &create_pcr_args)
        .pipe(tpm2sh(cache_path, &["load", primary_handle_str]))
        .read()
        .unwrap();
    let sealed_handle_pcr = sealed_pcr_output.trim().to_string();

    let unseal_pcr_output = tpm2sh(cache_path, &["unseal", sealed_handle_pcr.as_str()])
        .read()
        .unwrap();

    assert_eq!(unseal_pcr_output.trim(), SEALED_DATA);

    let delete_output = tpm2sh(cache_path, &["delete", "80*"]).read().unwrap();

    assert!(delete_output.contains(
        primary_handle_str
            .strip_prefix("80")
            .expect("primary handle did not start with 80")
    ));
    assert!(delete_output.contains(
        sealed_handle
            .as_str()
            .strip_prefix("80")
            .expect("sealed handle did not start with 80")
    ));
}

#[test]
fn create_primary_valid_policy() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    let output = tpm2sh(
        cache_path,
        &[
            "create-primary",
            "-H",
            "owner",
            "ecc-nist-p256:sha256",
            "--policy",
            "pcr(sha256:7)",
        ],
    )
    .read()
    .expect("Failed to create primary key with valid policy");

    let handle = output.trim();
    assert!(handle.starts_with("80"));
}

#[test]
fn create_primary_invalid_policy() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    let output = tpm2sh(
        cache_path,
        &[
            "create-primary",
            "-H",
            "owner",
            "ecc-nist-p256:sha256",
            "--policy",
            "pcr(7:sha256)",
        ],
    )
    .stderr_capture()
    .unchecked()
    .run()
    .expect("Failed to run command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("policy: invalid PCR digest algorithm"));
}

fn create_primary_ecc_sha256(cache_dir: &Path, password_hex: Option<&str>) -> String {
    let mut args = vec!["create-primary", "-H", "owner", "ecc-nist-p256:sha256"];

    if let Some(password) = password_hex {
        args.push("--password");
        args.push(password);
    }

    let output = tpm2sh(cache_dir, &args)
        .read()
        .expect("Failed to create primary key");
    let handle = output.trim().to_string();
    assert!(handle.starts_with("80"));
    handle
}

#[test]
fn create_keyedhash_hmac() {
    let temp = new_cache_dir();
    let parent = create_primary_ecc_sha256(temp.path(), None);
    let output = tpm2sh(temp.path(), &["create", &parent, "keyedhash:sha256"])
        .pipe(tpm2sh(temp.path(), &["load", &parent]))
        .read()
        .expect("Failed to create and load HMAC key");
    assert!(output.trim().starts_with("80"));
}

#[rstest]
#[case::rsa("genrsa -out private.pem 2048")]
#[case::ecc("ecparam -name prime256v1 -genkey -noout -out private.pem")]
fn load_external_key(#[case] openssl_args: &str) {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();
    let private_key_path = temp_dir.path().join("private.pem");

    let args: Vec<&str> = openssl_args.split_whitespace().collect();
    let openssl_status = std::process::Command::new("openssl")
        .args(&args)
        .current_dir(temp_dir.path())
        .status()
        .expect("Failed to execute openssl");
    assert!(openssl_status.success());

    let primary_handle = create_primary_ecc_sha256(cache_path, None);
    let primary_handle_str = primary_handle.as_str();

    let import_args = [
        "import",
        primary_handle_str,
        "-I",
        private_key_path.to_str().unwrap(),
    ];

    let load_output_importable = tpm2sh(cache_path, &import_args)
        .pipe(tpm2sh(cache_path, &["load", primary_handle_str]))
        .read()
        .expect("Failed to import and load importable key");

    let loaded_handle_importable = load_output_importable.trim();
    assert!(loaded_handle_importable.starts_with("80"));

    let import_loadable_args = [
        "import",
        "--loadable",
        primary_handle_str,
        "-I",
        private_key_path.to_str().unwrap(),
    ];

    let load_output_loadable = tpm2sh(cache_path, &import_loadable_args)
        .pipe(tpm2sh(cache_path, &["load", primary_handle_str]))
        .read()
        .expect("Failed to import and load loadable key");

    let loaded_handle_loadable = load_output_loadable.trim();
    assert!(loaded_handle_loadable.starts_with("80"));
}

#[test]
fn load_multi_level_hierarchy() {
    let temp_dir = new_cache_dir();
    let cache_path = temp_dir.path();

    let l1 = create_primary_ecc_sha256(cache_path, None);
    let l1_handle = l1.as_str();

    let l2_output = tpm2sh(cache_path, &["create", l1_handle, "rsa-2048:sha256"])
        .pipe(tpm2sh(cache_path, &["load", l1_handle]))
        .read()
        .unwrap();
    let l2_handle = l2_output.trim().to_string();

    let deep_data = hex::encode("deep-secret");

    let l3_output = tpm2sh(
        cache_path,
        &["seal", l2_handle.as_str(), "--data", &deep_data],
    )
    .pipe(tpm2sh(cache_path, &["load", l2_handle.as_str()]))
    .read()
    .unwrap();
    let l3_handle = l3_output.trim().to_string();

    let output = tpm2sh(cache_path, &["unseal", l3_handle.as_str()])
        .read()
        .expect("Failed to unseal deep object");

    assert_eq!(output.trim(), deep_data);
}
