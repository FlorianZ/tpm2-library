// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use tpm2_protocol::{TpmError, TpmErrorValue};

pub struct TpmErrorExpectation {
    pub error: TpmError,
    pub exact: bool,
}

pub fn assert_tpm_error_matches(actual: TpmError, expected: &TpmErrorExpectation) {
    if expected.exact {
        assert_eq!(actual, expected.error, "mismatched TPM error");
    } else {
        assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected.error),
            "mismatched TPM error kind"
        );
    }
}

pub fn unmarshal_tpm_error_expectation(s: &str) -> Result<TpmErrorExpectation, &'static str> {
    let (kind, value, exact) = if let Some((kind, value_str)) = s.split_once('[') {
        let value_str = value_str
            .strip_suffix(']')
            .ok_or("MalformedValue missing closing bracket")?;

        (kind, unmarshal_tpm_error_value(value_str)?, true)
    } else {
        (s, TpmErrorValue::new(0), false)
    };

    Ok(TpmErrorExpectation {
        error: tpm_error_from_kind(kind, value)?,
        exact,
    })
}

fn tpm_error_from_kind(kind: &str, value: TpmErrorValue) -> Result<TpmError, &'static str> {
    match kind {
        "InvalidValue" | "InvalidCc" => Ok(TpmError::InvalidCc(value)),
        "InvalidRc" => Ok(TpmError::InvalidRc(value)),
        "InvalidTag" => Ok(TpmError::InvalidTag(value)),
        "UnexpectedEnd" => Ok(TpmError::UnexpectedEnd(value)),
        "TrailingData" => Ok(TpmError::TrailingData(value)),
        "VariantMissing" | "VariantNotAvailable" => Ok(TpmError::VariantNotAvailable(value)),
        _ => Err("unknown variant"),
    }
}

fn unmarshal_tpm_error_value(s: &str) -> Result<TpmErrorValue, &'static str> {
    let mut value = TpmErrorValue::new(0);

    if s.is_empty() {
        return Ok(value);
    }

    for field in s.split(',') {
        let (key, raw_value) = field
            .split_once('=')
            .ok_or("MalformedValue missing key-value separator")?;
        match key {
            "offset" => value.offset = parse_usize(raw_value)?,
            "value" => value.value = parse_u64(raw_value)?,
            "needed" => value.needed = parse_usize(raw_value)?,
            "available" => value.available = parse_usize(raw_value)?,
            "limit" => value.limit = parse_usize(raw_value)?,
            "actual" => value.actual = parse_usize(raw_value)?,
            _ => return Err("unknown error value field"),
        }
    }

    Ok(value)
}

fn parse_u64(s: &str) -> Result<u64, &'static str> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| "Invalid number format")
    } else {
        s.parse::<u64>().map_err(|_| "Invalid number format")
    }
}

fn parse_usize(s: &str) -> Result<usize, &'static str> {
    usize::try_from(parse_u64(s)?).map_err(|_| "Invalid number format")
}
