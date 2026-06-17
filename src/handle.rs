// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{convert::TryFrom, fmt, str::FromStr};
use tpm2_protocol::data::TpmHt;

#[derive(Debug)]
pub enum HandleError {
    /// Handle has more than one asterisk (`*`).
    HandleHasTooManyAsterisks,

    /// Handle contains a pattern (e.g., `*` or `?`).
    HandlePatternNotAllowed,

    /// Handle is less than eight characters.
    HandleTooShort,

    /// Handle is more than eight characters.
    HandleTooLong,

    /// Handle contains an invalid character.
    InvalidHandleCharacter(char),

    /// Handle type byte is not valid.
    InvalidHandleType(u8),
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandleHasTooManyAsterisks => write!(f, "handle has more than one asterisk"),
            Self::HandlePatternNotAllowed => write!(f, "handle pattern is not allowed"),
            Self::HandleTooShort => write!(f, "handle is less than eight characters"),
            Self::HandleTooLong => write!(f, "handle has more than eight characters"),
            Self::InvalidHandleCharacter(c) => write!(f, "invalid handle character: {c}"),
            Self::InvalidHandleType(b) => write!(f, "invalid handle type: 0x{b:02x}"),
        }
    }
}

impl std::error::Error for HandleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle {
    mask: u32,
    value: u32,
}

impl Handle {
    /// Creates a new handle that represents a single, specific handle value.
    #[must_use]
    pub fn new(value: u32) -> Self {
        Self {
            mask: 0xFFFF_FFFF,
            value,
        }
    }

    /// Returns the value of the handle if it represents a single handle.
    #[must_use]
    pub fn value(&self) -> Option<u32> {
        if self.mask == 0xFFFF_FFFF {
            Some(self.value)
        } else {
            None
        }
    }

    /// Checks if a given handle value matches the handle's pattern.
    #[must_use]
    pub fn matches(&self, handle: u32) -> bool {
        (handle & self.mask) == self.value
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.mask == 0 {
            write!(f, "*")
        } else {
            for i in (0..8).rev() {
                let shift = i * 4;
                let nibble_mask = (self.mask >> shift) & 0xF;
                if nibble_mask == 0xF {
                    let val = (self.value >> shift) & 0xF;
                    write!(f, "{val:x}")?;
                } else {
                    write!(f, "?")?;
                }
            }
            Ok(())
        }
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(value_str: &str) -> Result<Self, Self::Err> {
        if value_str == "*" {
            return Ok(Self { mask: 0, value: 0 });
        }

        let asterisk_count = value_str.chars().filter(|&c| c == '*').count();
        if asterisk_count > 1 {
            return Err(HandleError::HandleHasTooManyAsterisks);
        }

        let explicit_len = value_str.len() - asterisk_count;

        if asterisk_count == 0 {
            if explicit_len < 8 {
                return Err(HandleError::HandleTooShort);
            }
            if explicit_len > 8 {
                return Err(HandleError::HandleTooLong);
            }
        } else if explicit_len > 8 {
            return Err(HandleError::HandleTooLong);
        }

        let padding = 8 - explicit_len;
        let mut mask: u32 = 0;
        let mut value: u32 = 0;
        let mut nibble_idx = 7_i32;

        for c in value_str.chars() {
            if c == '*' {
                nibble_idx -= i32::try_from(padding).unwrap();
                continue;
            }

            #[allow(clippy::cast_sign_loss)]
            let shift = (nibble_idx * 4) as u32;

            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => {
                    let c = if c.is_alphanumeric() { c } else { '?' };
                    return Err(HandleError::InvalidHandleCharacter(c));
                }
            }
            nibble_idx -= 1;
        }

        Ok(Self { mask, value })
    }
}

impl TryFrom<Handle> for TpmHt {
    type Error = HandleError;

    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        let raw_handle = handle.value().ok_or(HandleError::HandlePatternNotAllowed)?;
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|_| HandleError::InvalidHandleType(ht_byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exact_handle() {
        let h = Handle::from_str("80000001").unwrap();
        assert_eq!(h.value(), Some(0x8000_0001));
    }

    #[test]
    fn parse_wildcard_handle() {
        let h = Handle::from_str("*").unwrap();
        assert!(h.value().is_none());
        assert_eq!(h.to_string(), "*");
    }

    #[test]
    fn reject_multiple_asterisks() {
        let err = Handle::from_str("80**0001").unwrap_err();
        assert!(matches!(err, HandleError::HandleHasTooManyAsterisks));
    }

    #[test]
    fn reject_invalid_characters() {
        let err = Handle::from_str("8000000g").unwrap_err();
        assert!(matches!(err, HandleError::InvalidHandleCharacter('g')));
    }

    #[test]
    fn reject_too_short() {
        let err = Handle::from_str("123").unwrap_err();
        assert!(matches!(err, HandleError::HandleTooShort));
    }

    #[test]
    fn pattern_display_uses_question_marks() {
        let h = Handle::from_str("80??0001").unwrap();
        assert_eq!(h.to_string(), "80??0001");
    }
}
