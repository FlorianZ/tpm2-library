// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use tpm2_protocol::{
    TpmError, TpmField,
    data::{TpmSt, TpmsAttest, TpmuAttestView},
};

const VALID_ATTEST: &[u8] = &[
    0xff, 0x54, 0x43, 0x47, // magic = TPM_GENERATED_VALUE
    0x80, 0x16, // attest_type = TPM_ST_ATTEST_SESSION_AUDIT
    0x00, 0x00, // qualified_signer (empty)
    0x00, 0x00, // extra_data (empty)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // clock_info.clock
    0x00, 0x00, 0x00, 0x00, // clock_info.reset_count
    0x00, 0x00, 0x00, 0x00, // clock_info.restart_count
    0x00, // clock_info.safe
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // firmware_version
    0x00, // attested.exclusive_session
    0x00, 0x00, // attested.session_digest (empty)
];

#[test]
fn attest_view_parses_validated_body() {
    let (view, rest) = <TpmsAttest as TpmField>::cast_prefix_field(VALID_ATTEST).unwrap();

    assert_eq!(view.attest_type, TpmSt::AttestSessionAudit);
    assert_eq!(view.firmware_version, 0);
    assert!(matches!(view.attested, TpmuAttestView::SessionAudit(_)));
    assert!(rest.is_empty());
}

#[test]
fn attest_view_rejects_wrong_magic() {
    let mut buf = VALID_ATTEST.to_vec();
    buf[0] = 0x00;

    let err = <TpmsAttest as TpmField>::cast_prefix_field(&buf)
        .err()
        .unwrap();

    assert_eq!(
        err,
        TpmError::InvalidMagicNumber {
            offset: 0,
            value: 0x0054_4347,
        }
    );
}
