// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Integration tests for command list generation and parsing.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_crypto::TpmHash;
use tpm2_policy_language::{TpmPolicyContext, TpmPolicyError, TpmPolicyExpression};
use tpm2_protocol::{
    basic::TpmHandle,
    data::{Tpm2bDigest, Tpm2bName, TpmAlgId, TpmCc, TpmlDigest},
    frame::{TpmCommandValue as TpmCommand, TpmPolicyOrCommand, TpmPolicyRestartCommand},
};

fn test_context() -> TpmPolicyContext {
    let handle = TpmHandle::from(0x8100_0001);
    let name = Tpm2bName::try_from(
        hex::decode("000b0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let mut bank_map = HashMap::new();
    for i in 0..24 {
        bank_map.insert(i, Tpm2bDigest::try_from(vec![0u8; 32].as_slice()).unwrap());
    }

    TpmPolicyContext::builder()
        .with_name(handle, name)
        .with_pcr_bank(TpmAlgId::Sha256, bank_map)
        .build()
        .unwrap()
}

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
    let policy_context = test_context();
    let original_ast = TpmPolicyExpression::parse(input, &policy_context).unwrap();

    let compiled = original_ast
        .compile(TpmAlgId::Sha256, &policy_context)
        .unwrap();
    let roundtripped_ast =
        TpmPolicyExpression::from_commands(compiled.commands().iter().map(|(cmd, _)| cmd)).unwrap();

    let expected_ast = original_ast.clone();

    assert_eq!(roundtripped_ast, expected_ast);
    assert_eq!(roundtripped_ast.to_string(), expected_ast.to_string());
}

#[rstest]
#[case("secret(81000001, copy_ref:)")]
#[case("secret(81000001)")]
#[case("secret(81000001, copy_ref:010203)")]
fn policy_secret_digest_matches_reference(#[case] input: &str) {
    let policy_context = test_context();

    let expr = TpmPolicyExpression::parse(input, &policy_context).unwrap();
    let compiled = expr.compile(TpmAlgId::Sha256, &policy_context).unwrap();
    let command_list = compiled.commands();
    let digest = compiled.digest();

    assert_eq!(command_list.len(), 1);

    let (cmd, _auth) = &command_list[0];
    let secret_cmd = match cmd {
        TpmCommand::PolicySecret(c) => c,
        other => panic!("expected PolicySecret, got {other:?}"),
    };

    let hash = TpmHash::try_from(TpmAlgId::Sha256).unwrap();
    let digest_size = hash.size();
    let zero_digest = Tpm2bDigest::try_from(vec![0u8; digest_size].as_slice()).unwrap();

    let name = policy_context.name(TpmHandle::from(0x8100_0001)).unwrap();
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
    let policy_context = TpmPolicyContext::default();
    let result = TpmPolicyExpression::parse("1234", &policy_context);

    assert!(matches!(result, Err(TpmPolicyError::InvalidToken(_))));
}

#[test]
fn invalid_handle_type_is_rejected() {
    let policy_context = TpmPolicyContext::default();
    let result = TpmPolicyExpression::parse("ff000001", &policy_context);

    assert!(matches!(
        result,
        Err(TpmPolicyError::InvalidHandleType(0xff_u8))
    ));
}

#[test]
fn policy_or_without_enough_branches_is_rejected() {
    let digest = Tpm2bDigest::try_from(vec![0u8; 32].as_slice()).unwrap();
    let mut p_hash_list = TpmlDigest::new();
    p_hash_list.try_push(digest).unwrap();
    p_hash_list.try_push(digest).unwrap();
    let command = TpmCommand::PolicyOr(TpmPolicyOrCommand {
        handles: [0.into()],
        p_hash_list,
    });

    let result = TpmPolicyExpression::from_commands(&[command]);

    assert!(matches!(
        result,
        Err(TpmPolicyError::CommandStreamBranchUnderflow)
    ));
}

#[test]
fn unmerged_command_branches_are_rejected() {
    let command = TpmCommand::PolicyRestart(TpmPolicyRestartCommand {
        handles: [0.into()],
    });

    let result = TpmPolicyExpression::from_commands(&[command]);

    assert!(matches!(
        result,
        Err(TpmPolicyError::CommandStreamUnbalancedBranches)
    ));
}
