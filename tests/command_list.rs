// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Integration tests for command list generation and parsing.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_crypto::TpmHash;
use tpm2_policy_language::{TpmPolicyError, TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::{
    basic::TpmHandle,
    data::{Tpm2bDigest, Tpm2bName, TpmAlgId, TpmCc},
    frame::TpmCommandValue as TpmCommand,
};

#[rstest]
#[case(
    "pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(81000001, copy_ref:))"
)]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or pcr(sha256:15:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)"
)]
#[case("pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)")]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(81000001, copy_ref:010203))"
)]
/// Verifies that parsing a policy string, converting it to a command list, and
/// parsing that command list back results in a correctly sanitized policy AST.
fn command_list_roundtrip(#[case] input: &str) {
    let handle = TpmHandle::from(0x8100_0001);

    let mut names = HashMap::new();
    names.insert(
        handle,
        Tpm2bName::try_from(
            hex::decode("000b0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
    );

    let mut pcrs = HashMap::new();
    let mut bank_map = HashMap::new();
    for i in 0..24 {
        bank_map.insert(i, Tpm2bDigest::try_from(vec![0u8; 32].as_slice()).unwrap());
    }
    pcrs.insert(TpmAlgId::Sha256, bank_map);

    let policy_state = TpmPolicyState::new(names, pcrs).unwrap();
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
#[case("secret(81000001, copy_ref:)")]
#[case("secret(81000001)")]
#[case("secret(81000001, copy_ref:010203)")]
fn policy_secret_digest_matches_reference(#[case] input: &str) {
    let handle = TpmHandle::from(0x8100_0001);

    let mut names = HashMap::new();
    names.insert(
        handle,
        Tpm2bName::try_from(
            hex::decode("000b0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        )
        .unwrap(),
    );

    let mut pcrs = HashMap::new();
    let mut bank_map = HashMap::new();
    for i in 0..24 {
        bank_map.insert(i, Tpm2bDigest::try_from(vec![0u8; 32].as_slice()).unwrap());
    }
    pcrs.insert(TpmAlgId::Sha256, bank_map);

    let policy_state = TpmPolicyState::new(names, pcrs).unwrap();

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

    let hash = TpmHash::try_from(TpmAlgId::Sha256).unwrap();
    let digest_size = hash.size();
    let zero_digest = Tpm2bDigest::try_from(vec![0u8; digest_size].as_slice()).unwrap();

    let name = policy_state.names().get(&handle).unwrap();
    let cc_bytes = (TpmCc::PolicySecret as u32).to_be_bytes();

    let first_chunks: Vec<&[u8]> = vec![zero_digest.as_ref(), &cc_bytes, name.as_ref()];
    let first_digest_bytes = hash.digest(&first_chunks).unwrap();
    let first_digest = Tpm2bDigest::try_from(first_digest_bytes.as_slice()).unwrap();

    let second_chunks: Vec<&[u8]> = vec![first_digest.as_ref(), secret_cmd.policy_ref.as_ref()];
    let second_digest_bytes = hash.digest(&second_chunks).unwrap();
    let reference_digest = Tpm2bDigest::try_from(second_digest_bytes.as_slice()).unwrap();

    assert_eq!(digest, reference_digest);
}

#[test]
fn invalid_handle_literal_is_rejected() {
    let policy_state = TpmPolicyState::default();
    let result = TpmPolicyExpression::new("1234", &policy_state);

    assert!(matches!(result, Err(TpmPolicyError::InvalidToken(_))));
}

#[test]
fn invalid_handle_type_is_rejected() {
    let policy_state = TpmPolicyState::default();
    let result = TpmPolicyExpression::new("ff000001", &policy_state);

    assert!(matches!(
        result,
        Err(TpmPolicyError::InvalidHandleType(0xff_u8))
    ));
}
