// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WildcardError {
    #[error("invalid hex digit: '{0}'")]
    InvalidHexDigit(char),
    #[error("the pattern must represent exactly 8 hex characters (ignoring '*')")]
    IncorrectLength,
    #[error("only one '*' is allowed in a pattern")]
    TooManyAsterisks,
    #[error("the pattern has more than 8 non-'*' characters")]
    TooManyDigits,
}

/// Wildcard pattern matcher for 32-bit unsigned value represented
/// as a string of exactly eight digits.
///
/// Wildcards:
///
/// 1. `?` matches any digi, and can be use in place of any digit.
/// 2. `*` matches zero or more digits. Pattern matcher supports
///    only one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WildcardPattern(u32, u32);

impl WildcardPattern {
    /// Compiles a query string into a `WildcardPattern`.
    ///
    /// # Errors
    ///
    /// Returns `WildcardError` if the query string is invalid.
    pub fn new(query: &str) -> Result<Self, WildcardError> {
        if query == "*" {
            return Ok(Self(0, 0));
        }

        let mut mask: u32 = 0;
        let mut value: u32 = 0;

        let asterisk_pos = query.chars().position(|c| c == '*');

        if let Some(pos) = asterisk_pos {
            let (prefix, suffix_with_asterisk) = query.split_at(pos);
            let suffix = &suffix_with_asterisk[1..];

            if suffix.contains('*') {
                return Err(WildcardError::TooManyAsterisks);
            }

            if prefix.len() + suffix.len() > 8 {
                return Err(WildcardError::TooManyDigits);
            }

            for (i, c) in prefix.chars().enumerate() {
                let shift = (7 - i) * 4;
                match c.to_digit(16) {
                    Some(v) => {
                        mask |= 0xF << shift;
                        value |= v << shift;
                    }
                    None if c == '?' => {}
                    None => return Err(WildcardError::InvalidHexDigit(c)),
                }
            }

            for (i, c) in suffix.chars().rev().enumerate() {
                let shift = i * 4;
                match c.to_digit(16) {
                    Some(v) => {
                        mask |= 0xF << shift;
                        value |= v << shift;
                    }
                    None if c == '?' => {}
                    None => return Err(WildcardError::InvalidHexDigit(c)),
                }
            }
        } else {
            if query.len() != 8 {
                return Err(WildcardError::IncorrectLength);
            }
            for (i, c) in query.chars().enumerate() {
                let shift = (7 - i) * 4;
                match c.to_digit(16) {
                    Some(v) => {
                        mask |= 0xF << shift;
                        value |= v << shift;
                    }
                    None if c == '?' => {}
                    None => return Err(WildcardError::InvalidHexDigit(c)),
                }
            }
        }

        Ok(Self(mask, value))
    }

    /// Checks if a given handle matches the compiled pattern.
    #[must_use]
    pub fn matches(&self, handle: u32) -> bool {
        if self.0 == 0 && self.1 == 0 {
            return true;
        }
        (handle & self.0) == self.1
    }
}
