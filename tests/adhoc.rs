// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{
    any::Any, collections::HashMap, convert::TryFrom, fmt::Debug, io::IsTerminal, string::ToString,
    vec::Vec,
};
use tpm2_protocol::{
    build_tpm2b,
    data::{
        Tpm2bDigest, TpmAlgId, TpmCc, TpmRc, TpmRcBase, TpmRcIndex, TpmaSession, TpmlDigest,
        TpmlPcrSelection, TpmsClockInfo, TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{tpm_build_response, tpm_parse_response, TpmPcrReadResponse},
    TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

fn test_response_parse_remainder() {
    let mut pcr_values = TpmlDigest::new();
    pcr_values
        .try_push(Tpm2bDigest::try_from(&[0xAA; 32][..]).unwrap())
        .unwrap();

    let original_body = TpmPcrReadResponse {
        pcr_update_counter: 1,
        pcr_selection_out: TpmlPcrSelection::default(),
        pcr_values,
    };

    let mut valid_full_response = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut valid_full_response);
        tpm_build_response(
            &original_body,
            &[],
            TpmRc::from(TpmRcBase::Success),
            &mut writer,
        )
        .unwrap();
        writer.len()
    };

    let trailing_data = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut response_with_trailer = valid_full_response[..len].to_vec();
    response_with_trailer.extend_from_slice(&trailing_data);

    let result = tpm_parse_response(TpmCc::PcrRead, &response_with_trailer);
    assert_eq!(result, Err(TpmErrorKind::ParseUnderflow));
}

fn test_tpm2b_build_length_too_large() {
    let large_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::NonNull::<u8>::dangling().as_ptr(),
            u16::MAX as usize + 1,
        )
    };

    let mut out_buf = [0u8; 10];
    let mut writer = TpmWriter::new(&mut out_buf);

    let result = build_tpm2b(&mut writer, large_slice);

    assert_eq!(result, Err(TpmErrorKind::BuildCapacity),);
}

fn test_tpm_buffer_slice_too_large() {
    const CAPACITY: usize = 4096;
    let data = vec![0; CAPACITY + 1];

    let result = TpmBuffer::<CAPACITY>::try_from(data.as_slice());

    assert_eq!(
        result,
        Err(TpmErrorKind::BuildCapacity),
        "Should reject creating a TpmBuffer from a slice larger than its capacity"
    );
}

fn test_tpm_rc_base_from_raw() {
    let cases = [
        ("TPM_RC_SUCCESS", 0x0000, TpmRcBase::Success),
        ("TPM_RC_BAD_TAG", 0x001E, TpmRcBase::BadTag),
        ("TPM_RC_INITIALIZE", 0x0100, TpmRcBase::Initialize),
        ("TPM_RC_FAILURE", 0x0101, TpmRcBase::Failure),
        ("TPM_RC_SENSITIVE", 0x0155, TpmRcBase::Sensitive),
        ("TPM_RC_CONTEXT_GAP", 0x0901, TpmRcBase::ContextGap),
        ("TPM_RC_NV_UNAVAILABLE", 0x0923, TpmRcBase::NvUnavailable),
        (
            "TPM_RC_HANDLE with handle index 1",
            0x018B,
            TpmRcBase::Handle,
        ),
        (
            "TPM_RC_ATTRIBUTES with handle index 4",
            0x0482,
            TpmRcBase::Attributes,
        ),
        (
            "TPM_RC_AUTH_FAIL with session index 0",
            0x088E,
            TpmRcBase::AuthFail,
        ),
        (
            "TPM_RC_CURVE with parameter index 1",
            0x01E6,
            TpmRcBase::Curve,
        ),
    ];

    for (description, raw_rc, expected_base) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.base(), Ok(expected_base), "{description}");
    }
}

fn test_tpm_rc_display() {
    let cases = [
        ("TPM_RC_SUCCESS", 0x0000, "TPM_RC_SUCCESS"),
        (
            "TPM_RC_HANDLE with handle index 1",
            0x018B,
            "[TPM_RC_HANDLE, handle[1]]",
        ),
        (
            "TPM_RC_ATTRIBUTES with handle index 4",
            0x0482,
            "[TPM_RC_ATTRIBUTES, handle[4]]",
        ),
        (
            "TPM_RC_AUTH_FAIL with session index 0",
            0x088E,
            "[TPM_RC_AUTH_FAIL, session[0]]",
        ),
        (
            "TPM_RC_NV_UNAVAILABLE (warning) without index",
            0x0923,
            "TPM_RC_NV_UNAVAILABLE",
        ),
    ];

    for (description, raw_rc, expected_display) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.to_string(), expected_display, "{description}");
    }
}

fn test_tpm_rc_index_from_raw() {
    let cases = [
        ("No index for success", 0x0000, None),
        ("No index for format 0", 0x0101, None),
        ("No index for warning", 0x0901, None),
        ("No index when N is 0", 0x008B, None),
        ("Parameter index 1", 0x01C1, Some(TpmRcIndex::Parameter(1))),
        ("Parameter index 8", 0x08C4, Some(TpmRcIndex::Parameter(8))),
        ("Handle index 1", 0x018B, Some(TpmRcIndex::Handle(1))),
        ("Handle index 7", 0x078B, Some(TpmRcIndex::Handle(7))),
        ("Session index 0", 0x088E, Some(TpmRcIndex::Session(0))),
        ("Session index 7", 0x0F8E, Some(TpmRcIndex::Session(7))),
    ];

    for (description, raw_rc, expected) in cases {
        let rc = TpmRc::try_from(raw_rc).unwrap();
        assert_eq!(rc.index(), expected, "{description}");
    }
}

fn test_tpmt_roundtrip_sym_def_xor() {
    let original_sym_def = TpmtSymDef {
        algorithm: TpmAlgId::Xor,
        key_bits: TpmuSymKeyBits::Xor(TpmAlgId::Sha256),
        mode: TpmuSymMode::Xor(TpmAlgId::Null),
    };

    let mut buf = [0u8; 1024];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        TpmBuild::build(&original_sym_def, &mut writer).unwrap();
        writer.len()
    };
    let built_bytes = &buf[..len];

    let (parsed_sym_def, remainder) = TpmtSymDef::parse(built_bytes).unwrap();

    assert_eq!(
        parsed_sym_def, original_sym_def,
        "Parsed TpmtSymDef does not match original"
    );
    assert!(
        remainder.is_empty(),
        "Buffer not fully consumed after parsing TpmtSymDef"
    );
}

fn print_ok() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[32mOK\x1B[0m");
    } else {
        println!("OK");
    }
}

fn print_failed() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[31mFAILED\x1B[0m");
    } else {
        println!("FAILED");
    }
}

macro_rules! test_suite {
    ($($test_fn:ident),* $(,)?) => {
        fn run_all_tests() -> usize {
            let tests: &[(&str, fn())] = &[
                $( (stringify!($test_fn), $test_fn) ),*
            ];

            let mut failed = 0;
            println!("Running {} tests...", tests.len());
            for (name, test) in tests {
                print!("Test {name} ... ");
                let result = std::panic::catch_unwind(test);
                if result.is_err() {
                    print_failed();
                    failed += 1;
                } else {
                    print_ok();
                }
            }
            failed
        }
    };
}

/// A linear congruential generator (LCG) implementation.
struct Rng {
    seed: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn next_u16(&mut self) -> u16 {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.seed >> 32) as u16
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u16() as u8
    }

    fn next_u32(&mut self) -> u32 {
        ((self.next_u16() as u32) << 16) | (self.next_u16() as u32)
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    fn gen_range(&mut self, range: std::ops::Range<u8>) -> u8 {
        range.start + (self.next_u8() % (range.end - range.start))
    }
}

pub trait TpmObject: Any + Debug {
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmErrorKind>;
    fn as_any(&self) -> &dyn Any;
    fn dyn_eq(&self, other: &dyn TpmObject) -> bool;
}

impl<T> TpmObject for T
where
    T: TpmBuild + TpmParse + PartialEq + Any + Debug,
{
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmErrorKind> {
        TpmBuild::build(self, writer)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn dyn_eq(&self, other: &dyn TpmObject) -> bool {
        other
            .as_any()
            .downcast_ref::<T>()
            .map_or(false, |a| self == a)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
enum TypeId {
    Clock = 0,
    Alg = 1,
    SessionAttrs = 2,
}

impl TryFrom<u8> for TypeId {
    type Error = TpmErrorKind;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Clock),
            1 => Ok(Self::Alg),
            2 => Ok(Self::SessionAttrs),
            _ => Err(TpmErrorKind::InvalidValue),
        }
    }
}

type ObjectParser = fn(&[u8]) -> Result<(Box<dyn TpmObject>, &[u8]), TpmErrorKind>;

fn make_parser<T: TpmParse + TpmObject>() -> ObjectParser {
    |bytes: &[u8]| {
        let (obj, remainder) = T::parse(bytes)?;
        Ok((Box::new(obj), remainder))
    }
}

fn random_object(rng: &mut Rng) -> (TypeId, Box<dyn TpmObject>) {
    match rng.gen_range(0..3) {
        0 => (
            TypeId::Clock,
            Box::new(TpmsClockInfo {
                clock: rng.next_u64(),
                reset_count: rng.next_u32(),
                restart_count: rng.next_u32(),
                safe: (rng.next_u8() % 2 == 0).into(),
            }),
        ),
        1 => {
            let alg = loop {
                if let Ok(alg) = TpmAlgId::try_from(rng.next_u16()) {
                    break alg;
                }
            };
            (TypeId::Alg, Box::new(alg))
        }
        _ => (
            TypeId::SessionAttrs,
            Box::new(TpmaSession::from_bits_truncate(rng.next_u8())),
        ),
    }
}

fn test_dynamic_roundtrip() {
    let mut parsers: HashMap<TypeId, ObjectParser> = HashMap::new();
    parsers.insert(TypeId::Clock, make_parser::<TpmsClockInfo>());
    parsers.insert(TypeId::Alg, make_parser::<TpmAlgId>());
    parsers.insert(TypeId::SessionAttrs, make_parser::<TpmaSession>());

    const LIST_SIZE: usize = 100;
    let mut rng = Rng::new(12345);
    let (type_list, original_list): (Vec<_>, Vec<_>) =
        (0..LIST_SIZE).map(|_| random_object(&mut rng)).unzip();
    let mut byte_stream = [0u8; TPM_MAX_COMMAND_SIZE];
    let final_len = {
        let mut writer = TpmWriter::new(&mut byte_stream);
        for i in 0..LIST_SIZE {
            let type_id = type_list[i];
            let item = &original_list[i];
            TpmBuild::build(&(type_id as u8), &mut writer).unwrap();
            item.build(&mut writer).unwrap();
        }
        writer.len()
    };
    let written_bytes = &byte_stream[..final_len];

    let mut parsed_list: Vec<Box<dyn TpmObject>> = Vec::with_capacity(LIST_SIZE);
    let mut remaining_bytes = written_bytes;

    while !remaining_bytes.is_empty() {
        let (tag_byte, stream_after_tag) = u8::parse(remaining_bytes).unwrap();
        let type_id = TypeId::try_from(tag_byte).unwrap();

        let parser_fn = parsers.get(&type_id).expect("Parser not registered!");

        let (parsed_obj, next_bytes) = parser_fn(stream_after_tag).unwrap();
        parsed_list.push(parsed_obj);
        remaining_bytes = next_bytes;
    }

    assert!(
        remaining_bytes.is_empty(),
        "Byte stream had trailing data after parsing."
    );
    assert_eq!(original_list.len(), parsed_list.len());
    for i in 0..LIST_SIZE {
        assert!(
            original_list[i].dyn_eq(parsed_list[i].as_ref()),
            "Mismatch at index {i}"
        );
    }
}

test_suite!(
    test_response_parse_remainder,
    test_tpm2b_build_length_too_large,
    test_tpm_buffer_slice_too_large,
    test_tpm_rc_base_from_raw,
    test_tpm_rc_display,
    test_tpm_rc_index_from_raw,
    test_tpmt_roundtrip_sym_def_xor,
    test_dynamic_roundtrip,
);

fn main() {
    let failed = run_all_tests();
    if failed > 0 {
        eprintln!("\n{failed} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("\nAll tests passed.");
}
