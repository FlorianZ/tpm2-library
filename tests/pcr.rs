// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! PCR parsing tests for comma-separated indices and multi-bank selections using rstest.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_policy_language::{TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::data::TpmAlgId;

#[rstest]
#[case(
    "pcr(sha256:0,1,2:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    24,
    vec![TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
#[case(
    "pcr(sha1:0+sha256:7,9,12:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    24,
    vec![TpmAlgId::Sha1, TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
#[case(
    "pcr(sha256:0,1,2:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    24,
    vec![TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
fn pcr_roundtrip(
    #[case] input: &str,
    #[case] pcr_count: usize,
    #[case] pcr_banks: Vec<TpmAlgId>,
    #[case] session_alg: TpmAlgId,
) {
    let policy_state = TpmPolicyState {
        pcr_count,
        pcr_banks,
        names: HashMap::new(),
    };

    let original_ast = TpmPolicyExpression::new(input, &policy_state).unwrap();
    let (cmds, _) = original_ast
        .to_command_list(session_alg, &policy_state)
        .unwrap();
    let roundtripped_ast = TpmPolicyExpression::from_command_list(&cmds).unwrap();

    assert_eq!(roundtripped_ast, original_ast);
    assert_eq!(roundtripped_ast.to_string(), original_ast.to_string());
}
