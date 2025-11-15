// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::LanguageError;
use std::{fmt, str::FromStr};
use tpm2_protocol::data::TpmHt;

/// Handle classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleClass {
    Tpm,
    Vtpm,
}

/// TPM and vTPM handles, with support for pattern matching.
///
/// A `Handle` can represent either a single, specific handle value (e.g.,
/// `tpm:81000001`) or a pattern for matching multiple handles (e.g., `tpm:81*`,
/// `vtpm:????????`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    class: HandleClass,
    mask: u32,
    value: u32,
}

impl Handle {
    /// Creates a new `Handle` that represents a single, specific handle value.
    #[must_use]
    pub fn new(class: HandleClass, value: u32) -> Self {
        Self {
            class,
            mask: 0xFFFF_FFFF,
            value,
        }
    }

    /// Returns the class of the handle (`Tpm` or `Vtpm`).
    #[must_use]
    pub fn class(&self) -> HandleClass {
        self.class
    }

    /// Returns the value of the handle if it represents a single handle.
    ///
    /// Returns `Some(value)` when the handle was created without wildcards.
    /// Returns `None` when the handle is a pattern.
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
        let scheme = match self.class {
            HandleClass::Tpm => "tpm",
            HandleClass::Vtpm => "vtpm",
        };
        write!(f, "{scheme}:")?;
        if self.mask == 0 {
            write!(f, "*")
        } else if self.mask == 0xFFFF_FFFF {
            write!(f, "{:08x}", self.value)
        } else {
            let mut out = [b'?'; 8];
            for (pos, item) in out.iter_mut().enumerate() {
                let i = 7usize.saturating_sub(pos);
                let nibble_mask = (self.mask >> (i * 4)) & 0xF;
                if nibble_mask == 0xF {
                    let nibble_val = (self.value >> (i * 4)) & 0xF;
                    *item = b"0123456789abcdef"[nibble_val as usize];
                }
            }
            let s = std::str::from_utf8(&out).map_err(|_| fmt::Error)?;
            write!(f, "{s}")
        }
    }
}

impl FromStr for Handle {
    type Err = LanguageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme_str, value_str) = s
            .split_once(':')
            .ok_or(LanguageError::HandlePrefixMissing)?;

        let class = match scheme_str {
            "tpm" => HandleClass::Tpm,
            "vtpm" => HandleClass::Vtpm,
            _ => return Err(LanguageError::InvalidHandlePrefix),
        };

        if value_str == "*" {
            return Ok(Self {
                class,
                mask: 0,
                value: 0,
            });
        }

        let mut normalized_str = String::with_capacity(8);
        if let Some((prefix, suffix)) = value_str.split_once('*') {
            if suffix.contains('*') {
                return Err(LanguageError::HandleHasTooManyAsterisks);
            }
            if prefix.len() + suffix.len() > 8 {
                return Err(LanguageError::HandleTooShort);
            }
            normalized_str.push_str(prefix);
            normalized_str.extend(
                std::iter::repeat('?').take(8_usize.saturating_sub(prefix.len() + suffix.len())),
            );
            normalized_str.push_str(suffix);
        } else {
            if value_str.len() < 8 {
                return Err(LanguageError::HandleTooLong);
            }
            if value_str.len() > 8 {
                return Err(LanguageError::HandleTooShort);
            }
            normalized_str.push_str(value_str);
        }

        let mut mask: u32 = 0;
        let mut value: u32 = 0;

        for (i, c) in normalized_str.chars().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let shift = ((7 - i) * 4) as u32;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => {
                    let c = if c.is_alphanumeric() { c } else { '?' };
                    return Err(LanguageError::InvalidHandleCharacter(c));
                }
            }
        }

        Ok(Self { class, mask, value })
    }
}

impl TryFrom<Handle> for TpmHt {
    type Error = LanguageError;

    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        let raw_handle = handle
            .value()
            .ok_or(LanguageError::HandlePatternNotAllowed)?;
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|_| LanguageError::InvalidHandleType(ht_byte))
    }
}
