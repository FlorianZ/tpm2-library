// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use std::vec::Vec;

pub fn message_bytes_by_header(
    data: &str,
    cc: &str,
    type_str: &str,
    outcome: &str,
    tag: &str,
    size: &str,
) -> Vec<u8> {
    let header = format!("{tag}{size}").to_ascii_lowercase();
    let dump = data
        .lines()
        .filter_map(message_parts)
        .find_map(|(line_cc, line_type, line_outcome, dump)| {
            (line_cc == cc
                && line_type == type_str
                && line_outcome == outcome
                && dump.to_ascii_lowercase().starts_with(&header))
            .then_some(dump)
        })
        .unwrap_or_else(|| panic!("missing message entry: {cc} {type_str} {outcome} {tag}{size}"));

    hex_to_bytes(dump).unwrap()
}

fn message_parts(line: &str) -> Option<(&str, &str, &str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let cc = parts.next()?;
    let type_str = parts.next()?;
    let outcome = parts.next()?;
    let dump = parts.next_back()?;

    Some((cc, type_str, outcome, dump))
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.len().is_multiple_of(2) {
        return Err("invalid hex size");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "invalid hex character")
}
