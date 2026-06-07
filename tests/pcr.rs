// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! PCR parsing tests for comma-separated indices and multi-bank selections using rstest.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_policy_language::{TpmPolicyContext, TpmPolicyExpression};
use tpm2_protocol::data::{Tpm2bDigest, TpmAlgId};

#[rstest]
#[case(
    "pcr(sha256:0,1,2:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    vec![TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
#[case(
    "pcr(sha1:0+sha256:7,9,12:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    vec![TpmAlgId::Sha1, TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
#[case(
    "pcr(sha256:0,1,2:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)",
    vec![TpmAlgId::Sha256],
    TpmAlgId::Sha256
)]
fn pcr_roundtrip(
    #[case] input: &str,
    #[case] pcr_banks: Vec<TpmAlgId>,
    #[case] session_alg: TpmAlgId,
) {
    let mut context_builder = TpmPolicyContext::builder();
    for alg in pcr_banks {
        let mut bank_map = HashMap::new();
        for i in 0..24 {
            bank_map.insert(i, Tpm2bDigest::try_from(vec![0u8; 32].as_slice()).unwrap());
        }
        context_builder = context_builder.pcr_bank(alg, bank_map);
    }

    let policy_context = context_builder.build().unwrap();
    let original_ast = TpmPolicyExpression::parse(input, &policy_context).unwrap();
    let compiled = original_ast.compile(session_alg, &policy_context).unwrap();
    let commands: Vec<_> = compiled
        .commands()
        .iter()
        .map(|(command, _auth)| command.clone())
        .collect();
    let roundtripped_ast = TpmPolicyExpression::from_commands(&commands).unwrap();

    assert_eq!(roundtripped_ast, original_ast);
    assert_eq!(roundtripped_ast.to_string(), original_ast.to_string());
}
