// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

#[path = "common/message_bytes.rs"]
mod message_bytes;

use crate::message_bytes::message_bytes;
use tpm2_protocol::{
    TpmCast, TpmError, TpmResult, TpmWireBytes, TpmWriter,
    basic::{Tpm2b, TpmUint16, Tpml},
    data::{TpmCc, TpmRc, TpmRcBase, TpmSt, TpmSu},
    frame::{
        TpmCommand, TpmStartupCommand, TpmStartupResponse, tpm_marshal_command,
        tpm_marshal_response,
    },
};

const MESSAGE_DATA: &str = include_str!("message.txt");

struct InvalidTail;

static INVALID_TAIL: InvalidTail = InvalidTail;
static INVALID_TAIL_BYTES: [u8; 1] = [0];

impl TpmCast for InvalidTail {
    fn cast(_buf: &[u8]) -> TpmResult<&Self> {
        Ok(&INVALID_TAIL)
    }

    fn cast_prefix(_buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Ok((&INVALID_TAIL, &INVALID_TAIL_BYTES))
    }

    unsafe fn cast_unchecked(_buf: &[u8]) -> &Self {
        &INVALID_TAIL
    }
}

#[test]
fn command_accessors_report_shape_changed_bounds() {
    let mut frame = message_bytes(MESSAGE_DATA, "00000144", "Command", "0000");
    let command = TpmCommand::cast_mut(&mut frame).unwrap();

    command.set_cc(TpmCc::NvRead).unwrap();
    let err = command.handles().err().unwrap();

    assert_eq!(
        err,
        TpmError::UnexpectedEnd {
            offset: 10,
            needed: 8,
            available: 2
        }
    );
}

#[test]
fn tpm2b_capacity_error_reports_limit() {
    let err = Tpm2b::<1>::cast(&[0, 2, 0xaa, 0xbb]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyBytes {
            offset: 0,
            limit: 1,
            actual: 2
        }
    );
}

#[test]
fn tpm2b_prefix_returns_payload_and_remainder() {
    let (value, rest) = Tpm2b::<4>::cast_prefix(&[0, 2, 0xaa, 0xbb, 0xcc]).unwrap();

    assert_eq!(value.data(), &[0xaa, 0xbb]);
    assert_eq!(rest, &[0xcc]);
}

#[test]
fn tpm2b_rejects_trailing_data() {
    let err = Tpm2b::<4>::cast(&[0, 1, 0xaa, 0xbb]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TrailingData {
            offset: 3,
            actual: 1
        }
    );
}

#[test]
fn tpm2b_rejects_short_payload() {
    let err = Tpm2b::<4>::cast(&[0, 2, 0xaa]).err().unwrap();

    assert_eq!(
        err,
        TpmError::UnexpectedEnd {
            offset: 2,
            needed: 2,
            available: 1
        }
    );
}

#[test]
fn tpml_capacity_error_reports_limit() {
    let err = Tpml::<1>::cast(&[0, 0, 0, 2]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyItems {
            offset: 0,
            limit: 1,
            actual: 2
        }
    );
}

#[test]
fn tpml_rejects_max_count_over_capacity() {
    let err = Tpml::<4>::cast(&[0xff, 0xff, 0xff, 0xff]).err().unwrap();

    assert_eq!(
        err,
        TpmError::TooManyItems {
            offset: 0,
            limit: 4,
            actual: usize::try_from(u32::MAX).unwrap()
        }
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
    assert_eq!(items.next().unwrap().unwrap().value(), 0x1234);
    assert_eq!(items.next().unwrap().unwrap().value(), 0x5678);
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
        TpmError::UnexpectedEnd {
            offset: 0,
            needed: 2,
            available: 1
        }
    );
}

#[test]
fn tpml_iterator_stops_after_truncated_element() {
    let list = Tpml::<4>::cast(&[0, 0, 0, 2, 0x12, 0x34, 0x56]).unwrap();
    let mut items = list.items::<TpmUint16>();

    assert_eq!(items.next().unwrap().unwrap().value(), 0x1234);
    assert_eq!(
        items.next().unwrap().err().unwrap(),
        TpmError::UnexpectedEnd {
            offset: 0,
            needed: 2,
            available: 1
        }
    );
    assert!(items.next().is_none());
}

#[test]
fn tpml_rejects_invalid_item_tail_without_panicking() {
    let err = Tpml::<1>::validate_prefix_items::<InvalidTail>(&[0, 0, 0, 1])
        .err()
        .unwrap();

    assert!(matches!(err, TpmError::IntegerTooLarge { .. }));
}

#[test]
fn tpml_typed_exact_rejects_trailing_data() {
    let err = Tpml::<4>::cast_items::<TpmUint16>(&[0, 0, 0, 1, 0x12, 0x34, 0x56])
        .err()
        .unwrap();

    assert_eq!(
        err,
        TpmError::TrailingData {
            offset: 6,
            actual: 1
        }
    );
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

    assert_eq!(value.value(), 0x1234);
    assert_eq!(rest, &[0x56]);
}

#[test]
fn invalid_enum_reports_raw_value() {
    let err = TpmSt::try_from(0xffff).unwrap_err();

    assert_eq!(
        err,
        TpmError::VariantNotAvailable {
            offset: 0,
            value: 0xffff
        }
    );
}

#[test]
fn display_renders_variant_name() {
    let err = TpmError::UnexpectedEnd {
        offset: 4,
        needed: 10,
        available: 2,
    };

    assert_eq!(err.to_string(), "unexpected end");
    assert_eq!(err.kind(), "UnexpectedEnd");
}

#[test]
fn command_marshal_writes_to_caller_buffer() {
    let expected = message_bytes(MESSAGE_DATA, "00000144", "Command", "0000");
    let command = TpmStartupCommand {
        handles: [],
        startup_type: TpmSu::Clear,
    };
    let mut storage = [0xa5; 16];
    let written_len = {
        let mut writer = TpmWriter::new(&mut storage);

        tpm_marshal_command(&command, TpmSt::NoSessions, &[], &mut writer).unwrap();
        assert_eq!(writer.as_bytes(), expected.as_slice());
        writer.len()
    };

    assert_eq!(&storage[written_len..], &[0xa5; 4]);
}

#[test]
fn response_marshal_writes_to_caller_buffer() {
    let expected = message_bytes(MESSAGE_DATA, "00000144", "Response", "0000");
    let response = TpmStartupResponse { handles: [] };
    let mut storage = [0xa5; 12];
    let written_len = {
        let mut writer = TpmWriter::new(&mut storage);

        tpm_marshal_response(&response, &[], TpmRc::Fmt0(TpmRcBase::Success), &mut writer).unwrap();
        assert_eq!(writer.as_bytes(), expected.as_slice());
        writer.len()
    };

    assert_eq!(&storage[written_len..], &[0xa5; 2]);
}

#[test]
fn command_marshal_reports_caller_buffer_overflow() {
    let command = TpmStartupCommand {
        handles: [],
        startup_type: TpmSu::Clear,
    };
    let mut storage = [0; 11];
    let mut writer = TpmWriter::new(&mut storage);
    let err = tpm_marshal_command(&command, TpmSt::NoSessions, &[], &mut writer)
        .err()
        .unwrap();

    assert_eq!(
        err,
        TpmError::BufferOverflow {
            offset: 10,
            needed: 2,
            available: 1
        }
    );
}
