// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! The chain of `if`-statements is a deliberate design choice as patterns in
//! a `match`-statement is too restricted for arbitrary expressions (e.g, see
//! `TpmRc` for an example).

#[macro_export]
macro_rules! tpm_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident($repr:ty) {
            $(
                $(#[$variant_meta:meta])*
                ($variant:ident, $value:expr, $display:literal)
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value
            ),*
        }

        impl TryFrom<$repr> for $name {
            type Error = ();

            #[allow(clippy::cognitive_complexity)]
            fn try_from(value: $repr) -> Result<Self, ()> {
                $(
                    if value == $value {
                        return Ok(Self::$variant);
                    }
                )*
                Err(())
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let s = match self {
                    $(Self::$variant => $display),*
                };
                write!(f, "{}", s)
            }
        }

        impl core::str::FromStr for $name {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($display => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();

            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmMarshal::marshal(&(*self as $repr), writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = <$repr>::unmarshal(buf)?;
                let enum_val = Self::try_from(val).map_err(|()| $crate::TpmProtocolError::InvalidValue)?;
                Ok((enum_val, buf))
            }
        }
    };
}
