//! Integration tests for command list generation and parsing.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use std::collections::HashMap;
use tpm2_policy_language::{Auth, Expression, PcrBank, PolicyState};
use tpm2_protocol::data::{Tpm2bName, TpmAlgId};

/// Recursively traverses an AST and replaces any password bytes with a
/// zero-filled vector of the same length.
fn sanitize_ast(expr: &mut Expression) {
    match expr {
        Expression::Secret { password, .. } => {
            if let Some(p) = password {
                if let Expression::Auth(Auth::Password(bytes)) = &mut **p {
                    let len = bytes.len();
                    *bytes = vec![0; len];
                }
            }
        }
        Expression::And(children) | Expression::Or(children) => {
            for child in children {
                sanitize_ast(child);
            }
        }
        _ => {}
    }
}

#[rstest]
#[case(
    "pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(tpm:81000001))"
)]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or pcr(sha256:15:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)"
)]
#[case("pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962)")]
#[case(
    "pcr(sha256:7:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) or (pcr(sha256:16:01d4c1a1d5c7d49e2781a96d00ebcc6616492a09f196598f7d0c9dee21b94962) and secret(tpm:81000001, password:010203))"
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
    let policy_state = PolicyState {
        banks: vec![PcrBank {
            alg: TpmAlgId::Sha256,
            count: 24,
        }],
        names,
    };

    let original_ast = Expression::new(input).unwrap();

    let (command_list, _digest) = original_ast
        .to_command_list(TpmAlgId::Sha256, &policy_state)
        .unwrap();
    let roundtripped_ast = Expression::from_command_list(&command_list).unwrap();

    let mut expected_ast = original_ast.clone();
    sanitize_ast(&mut expected_ast);

    assert_eq!(roundtripped_ast, expected_ast);
    assert_eq!(roundtripped_ast.to_string(), expected_ast.to_string());
}
