// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use tpm2_protocol::{
    TpmError, TpmErrorValue, TpmWireBytes,
    basic::{Tpm2b, TpmUint16, Tpml},
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
fn tpm2b_prefix_returns_payload_and_remainder() {
    let (value, rest) = Tpm2b::<4>::cast_prefix(&[0, 2, 0xaa, 0xbb, 0xcc]).unwrap();

    assert_eq!(value.payload(), &[0xaa, 0xbb]);
    assert_eq!(rest, &[0xcc]);
}

#[test]
fn tpm2b_rejects_trailing_data() {
    let err = Tpm2b::<4>::cast(&[0, 1, 0xaa, 0xbb]).err().unwrap();

    assert_eq!(err, TpmError::TrailingData(TpmErrorValue::new(3).actual(1)));
}

#[test]
fn tpm2b_rejects_short_payload() {
    let err = Tpm2b::<4>::cast(&[0, 2, 0xaa]).err().unwrap();

    assert_eq!(
        err,
        TpmError::UnexpectedEnd(TpmErrorValue::new(2).size(2, 1))
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
fn tpml_rejects_max_count_over_capacity() {
    let err = Tpml::<4>::cast(&[0xff, 0xff, 0xff, 0xff]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyItems(TpmErrorValue::new(0).limit(4, usize::try_from(u32::MAX).unwrap()))
    );
}

#[test]
fn tpml_typed_prefix_returns_items_and_remainder() {
    let (list, rest) =
        Tpml::<4>::cast_prefix_items::<TpmUint16>(&[0, 0, 0, 2, 0x12, 0x34, 0x56, 0x78, 0x9a])
            .unwrap();
    let mut items = list.items::<TpmUint16>();

    assert_eq!(list.as_bytes(), &[0, 0, 0, 2, 0x12, 0x34, 0x56, 0x78]);
    assert_eq!(list.items_bytes(), &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(items.next().unwrap().unwrap().get(), 0x1234);
    assert_eq!(items.next().unwrap().unwrap().get(), 0x5678);
    assert!(items.next().is_none());
    assert_eq!(rest, &[0x9a]);
}

#[test]
fn tpml_typed_items_reject_truncated_element() {
    let err = Tpml::<4>::cast_items::<TpmUint16>(&[0, 0, 0, 2, 0x12, 0x34, 0x56])
        .err()
        .unwrap();

    assert_eq!(
        err,
        TpmError::UnexpectedEnd(TpmErrorValue::new(0).size(2, 1))
    );
}

#[test]
fn tpml_iterator_stops_after_truncated_element() {
    let list = Tpml::<4>::cast(&[0, 0, 0, 2, 0x12, 0x34, 0x56]).unwrap();
    let mut items = list.items::<TpmUint16>();

    assert_eq!(items.next().unwrap().unwrap().get(), 0x1234);
    assert_eq!(
        items.next().unwrap().err().unwrap(),
        TpmError::UnexpectedEnd(TpmErrorValue::new(0).size(2, 1))
    );
    assert!(items.next().is_none());
}

#[test]
fn tpml_typed_exact_rejects_trailing_data() {
    let err = Tpml::<4>::cast_items::<TpmUint16>(&[0, 0, 0, 1, 0x12, 0x34, 0x56])
        .err()
        .unwrap();

    assert_eq!(err, TpmError::TrailingData(TpmErrorValue::new(6).actual(1)));
}

#[test]
fn fixed_wire_prefix_returns_remainder() {
    let (wire, rest) = TpmWireBytes::<2>::cast_prefix(&[0xaa, 0xbb, 0xcc]).unwrap();

    assert_eq!(wire.as_bytes(), &[0xaa, 0xbb]);
    assert_eq!(rest, &[0xcc]);
}

#[test]
fn integer_prefix_returns_remainder() {
    let (value, rest) = TpmUint16::cast_prefix(&[0x12, 0x34, 0x56]).unwrap();

    assert_eq!(value.get(), 0x1234);
    assert_eq!(rest, &[0x56]);
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
