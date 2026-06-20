// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! The chain of `if`-statements is a deliberate design choice as patterns in
//! a `match`-statement is too restricted for arbitrary expressions (e.g, see
//! `TpmRc` for an example).

#[doc(hidden)]
#[macro_export]
macro_rules! tpm_enum {
    (@impl $(#[$enum_meta:meta])* $vis:vis enum $name:ident($wrapper:ty, $repr:ty) {
        $(
            $(#[$variant_meta:meta])*
            ($variant:ident, $value:expr, $display:literal)
        ),* $(,)?
    }) => {
        $(#[$enum_meta])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value
            ),*
        }

        impl TryFrom<$repr> for $name {
            type Error = $crate::TpmError;

            #[allow(clippy::cast_lossless, clippy::cast_sign_loss)]
            fn try_from(value: $repr) -> Result<Self, $crate::TpmError> {
                match value {
                    $(
                        _ if value == $value => Ok(Self::$variant),
                    )*
                    _ => Err($crate::TpmError::VariantNotAvailable { offset: 0, value: value as u64 }),
                }
            }
        }

        impl $name {
            #[must_use]
            pub const fn value(self) -> $repr {
                self as $repr
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

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();

            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let value = <$wrapper>::from(*self as $repr);
                $crate::TpmMarshal::marshal(&value, writer)
            }
        }

        impl<'a> $crate::TpmField<'a> for $name {
            type View = Self;

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                let (value, buf) = <$wrapper as $crate::TpmCast>::cast_prefix(buf)?;
                let raw: $repr = value.value();
                let enum_val = Self::try_from(raw)?;

                Ok((enum_val, buf))
            }
        }
    };

    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmUint8) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmUint8, u8) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmInt8) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmInt8, i8) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmUint16) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmUint16, u16) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmUint32) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmUint32, u32) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmInt32) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmInt32, i32) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis enum $name:ident(TpmUint64) { $($rest:tt)* }) => {
        tpm_enum!(@impl $(#[$meta])* $vis enum $name($crate::basic::TpmUint64, u64) { $($rest)* });
    };
}
