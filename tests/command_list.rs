// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Integration tests for command list generation and parsing.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_crypto::TpmHash;
use tpm2_policy_language::{TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::{
    data::{Tpm2bDigest, Tpm2bName, TpmAlgId, TpmCc},
    frame::TpmCommand,
};

#[rstest]
#[case(
    "pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(tpm:81000001, copy_ref:))"
)]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or pcr(sha256:15:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)"
)]
#[case("pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)")]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(tpm:81000001, copy_ref:010203))"
)]
/// Verifies that parsing a policy string, converting it to a command list, and
/// parsing that command list back results in a correctly sanitized policy AST.
fn command_list_roundtrip(#[case] input: &str) {
    let mut names = HashMap::new();
    names.insert(
        0x8100_0001,
        Tpm2bName::try_from(
            hex::decode("000b0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
    );
    let policy_state = TpmPolicyState {
        pcr_count: 24,
        pcr_banks: vec![TpmAlgId::Sha256],
        names,
    };

    let original_ast = TpmPolicyExpression::new(input, &policy_state).unwrap();

    let (command_list, _digest) = original_ast
        .to_command_list(TpmAlgId::Sha256, &policy_state)
        .unwrap();
    let roundtripped_ast = TpmPolicyExpression::from_command_list(&command_list).unwrap();

    let expected_ast = original_ast.clone();

    assert_eq!(roundtripped_ast, expected_ast);
    assert_eq!(roundtripped_ast.to_string(), expected_ast.to_string());
}

#[rstest]
#[case("secret(tpm:81000001, copy_ref:)")]
#[case("secret(tpm:81000001)")]
#[case("secret(tpm:81000001, copy_ref:010203)")]
fn policy_secret_digest_matches_reference(#[case] input: &str) {
    let mut names = HashMap::new();
    names.insert(
        0x8100_0001,
        Tpm2bName::try_from(
            hex::decode("000b0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
    );
    let policy_state = TpmPolicyState {
        pcr_count: 24,
        pcr_banks: vec![TpmAlgId::Sha256],
        names,
    };

    let expr = TpmPolicyExpression::new(input, &policy_state).unwrap();
    let (command_list, digest) = expr
        .to_command_list(TpmAlgId::Sha256, &policy_state)
        .unwrap();

    assert_eq!(command_list.len(), 1);

    let (cmd, _auth) = &command_list[0];
    let secret_cmd = match cmd {
        TpmCommand::PolicySecret(c) => c,
        other => panic!("expected PolicySecret, got {other:?}"),
    };

    let hash = TpmHash::from(TpmAlgId::Sha256);
    let digest_size = hash.size();
    let zero_digest = Tpm2bDigest::try_from(vec![0u8; digest_size].as_slice()).unwrap();

    let name = policy_state.names.get(&0x8100_0001).unwrap();
    let cc_bytes = (TpmCc::PolicySecret as u32).to_be_bytes();

    let first_chunks: Vec<&[u8]> = vec![zero_digest.as_ref(), &cc_bytes, name.as_ref()];
    let first_digest_bytes = hash.digest(&first_chunks).unwrap();
    let first_digest = Tpm2bDigest::try_from(first_digest_bytes.as_slice()).unwrap();

    let second_chunks: Vec<&[u8]> = vec![first_digest.as_ref(), secret_cmd.policy_ref.as_ref()];
    let second_digest_bytes = hash.digest(&second_chunks).unwrap();
    let reference_digest = Tpm2bDigest::try_from(second_digest_bytes.as_slice()).unwrap();

    assert_eq!(digest, reference_digest);
}
