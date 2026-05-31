// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use tpm2_protocol::{
    TpmError, TpmErrorValue,
    basic::{Tpm2b, Tpml},
    data::TpmSt,
    frame::{TpmCommand, TpmResponse},
};

#[test]
fn short_frame_header_reports_size() {
    let err = TpmCommand::cast(&[0; 4]).err().unwrap();

    assert_eq!(
        err,
        TpmError::UnexpectedEnd(TpmErrorValue::new(0).size(10, 4))
    );
}

#[test]
fn invalid_command_tag_reports_raw_value() {
    let frame = [0xff, 0xff, 0, 0, 0, 10, 0, 0, 1, 0x44];
    let err = TpmCommand::cast(&frame).err().unwrap();

    assert_eq!(
        err,
        TpmError::InvalidTag(TpmErrorValue::new(0).value(0xffff))
    );
}

#[test]
fn invalid_response_code_reports_raw_value() {
    let frame = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 2];
    let err = TpmResponse::cast(&frame).err().unwrap();

    assert_eq!(err, TpmError::InvalidRc(TpmErrorValue::new(6).value(2)));
}

#[test]
fn tpm2b_capacity_error_reports_limit() {
    let err = Tpm2b::<1>::cast(&[0, 2, 0xaa, 0xbb]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyBytes(TpmErrorValue::new(0).limit(1, 2))
    );
}

#[test]
fn tpml_capacity_error_reports_limit() {
    let err = Tpml::<1>::cast(&[0, 0, 0, 2]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyItems(TpmErrorValue::new(0).limit(1, 2))
    );
}

#[test]
fn invalid_enum_reports_raw_value() {
    let err = TpmSt::try_from(0xffff).unwrap_err();

    assert_eq!(
        err,
        TpmError::VariantNotAvailable(TpmErrorValue::new(0).value(0xffff))
    );
}

#[test]
fn display_includes_error_value_fields() {
    let err = TpmError::UnexpectedEnd(TpmErrorValue::new(4).size(10, 2));

    assert_eq!(
        err.to_string(),
        "unexpected end at offset 4, needed=10, available=2"
    );
}
