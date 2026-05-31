// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub mod r#enum;
pub mod integer;
pub mod r#struct;

#[macro_export]
macro_rules! tpm_bitflags {
    (@impl $(#[$outer:meta])* $vis:vis struct $name:ident($wrapper:ty, $repr:ty) {
        $(
            $(#[$inner:meta])*
            const $field:ident = $value:expr, $string_name:literal;
        )*
    }) => {
        $(#[$outer])*
        $vis struct $name($repr);

        impl $name {
            $(
                $(#[$inner])*
                pub const $field: Self = Self($value);
            )*

            #[must_use]
            pub const fn bits(&self) -> $repr {
                self.0
            }

            #[must_use]
            pub const fn from_bits_truncate(bits: $repr) -> Self {
                Self(bits)
            }

            pub const fn set_bits(&mut self, bits: $repr) {
                self.0 = bits;
            }

            #[must_use]
            pub const fn empty() -> Self {
                Self(0)
            }

            #[must_use]
            pub const fn contains(&self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self::Output {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $name {
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::BitXor for $name {
            type Output = Self;
            fn bitxor(self, rhs: Self) -> Self::Output {
                Self(self.0 ^ rhs.0)
            }
        }

        impl core::ops::BitXorAssign for $name {
            fn bitxor_assign(&mut self, rhs: Self) {
                self.0 ^= rhs.0;
            }
        }

        impl core::ops::Not for $name {
            type Output = Self;
            fn not(self) -> Self::Output {
                Self(!self.0)
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let value = <$wrapper>::from(self.0);
                $crate::TpmMarshal::marshal(&value, writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = <$wrapper as $crate::TpmUnmarshal>::unmarshal(buf)?;
                Ok((Self(val.into()), buf))
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
    };

    ($(#[$meta:meta])* $vis:vis struct $name:ident(TpmUint8) { $($rest:tt)* }) => {
        tpm_bitflags!(@impl $(#[$meta])* $vis struct $name($crate::basic::TpmUint8, u8) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident(TpmUint16) { $($rest:tt)* }) => {
        tpm_bitflags!(@impl $(#[$meta])* $vis struct $name($crate::basic::TpmUint16, u16) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident(TpmUint32) { $($rest:tt)* }) => {
        tpm_bitflags!(@impl $(#[$meta])* $vis struct $name($crate::basic::TpmUint32, u32) { $($rest)* });
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident(TpmUint64) { $($rest:tt)* }) => {
        tpm_bitflags!(@impl $(#[$meta])* $vis struct $name($crate::basic::TpmUint64, u64) { $($rest)* });
    };
}

#[macro_export]
macro_rules! tpm_bool {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident(bool);
    ) => {
        $(#[$outer])*
        $vis struct $name(pub bool);

        impl From<bool> for $name {
            fn from(val: bool) -> Self {
                Self(val)
            }
        }

        impl From<$name> for bool {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let value = if self.0 { 1 } else { 0 };
                $crate::basic::TpmUint8::from(value).marshal(writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = $crate::basic::TpmUint8::unmarshal(buf)?;
                match u8::from(val) {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    _ => Err($crate::TpmProtocolError::InvalidBoolean),
                }
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$crate::basic::TpmUint8>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
    };
}

#[macro_export]
macro_rules! tpm_dispatch {
    (@const_check_sorted) => {};
    (@const_check_sorted $prev_cmd:ident, $( $rest_cmd:ident, )*) => {
        $crate::tpm_dispatch!(@const_check_sorted_impl $prev_cmd, $( $rest_cmd, )*);
    };
    (@const_check_sorted_impl $prev_cmd:ident,) => {};
    (@const_check_sorted_impl $prev_cmd:ident, $current_cmd:ident, $( $rest_cmd:ident, )* ) => {
        const _: () = assert!(
            <$crate::frame::data::$prev_cmd as $crate::frame::TpmHeader>::CC as u32 <= <$crate::frame::data::$current_cmd as $crate::frame::TpmHeader>::CC as u32,
            "TPM_DISPATCH_TABLE must be sorted by TpmCc."
        );
        $crate::tpm_dispatch!(@const_check_sorted_impl $current_cmd, $( $rest_cmd, )*);
    };

    ( $( ($cmd:ident, $resp:ident, $variant:ident) ),* $(,)? ) => {
        /// An owned TPM command body value.
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmCommandValue {
            $( $variant($crate::frame::data::$cmd), )*
        }

        impl $crate::TpmSized for TpmCommandValue {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(c) => $crate::TpmSized::len(c), )*
                }
            }
        }

        impl $crate::frame::TpmMarshalBody for TpmCommandValue {
             fn marshal_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(c) => $crate::frame::TpmMarshalBody::marshal_handles(c, writer), )*
                 }
             }
             fn marshal_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(c) => $crate::frame::TpmMarshalBody::marshal_parameters(c, writer), )*
                 }
             }
        }

        impl $crate::TpmMarshal for TpmCommandValue {
             fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(c) => $crate::TpmMarshal::marshal(c, writer), )*
                 }
             }
        }

        impl $crate::frame::TpmFrame for TpmCommandValue {
            fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(c) => $crate::frame::TpmFrame::cc(c), )*
                }
            }
            fn handles(&self) -> usize {
                match self {
                    $( Self::$variant(c) => $crate::frame::TpmFrame::handles(c), )*
                }
            }
        }

        impl TpmCommandValue {
            /// Marshals a command body into a writer.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmProtocolError)` on a marshal failure.
            pub fn marshal_frame(
                &self,
                tag: $crate::data::TpmSt,
                sessions: &$crate::frame::TpmAuthCommands,
                writer: &mut $crate::TpmWriter,
            ) -> $crate::TpmResult<()> {
                match self {
                    $( Self::$variant(c) => $crate::frame::tpm_marshal_command(c, tag, sessions, writer), )*
                }
            }
        }

        /// An owned TPM response body value.
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmResponseValue {
            $( $variant($crate::frame::data::$resp), )*
        }

        impl $crate::TpmSized for TpmResponseValue {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(r) => $crate::TpmSized::len(r), )*
                }
            }
        }

        impl $crate::frame::TpmMarshalBody for TpmResponseValue {
             fn marshal_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(r) => $crate::frame::TpmMarshalBody::marshal_handles(r, writer), )*
                 }
             }
             fn marshal_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(r) => $crate::frame::TpmMarshalBody::marshal_parameters(r, writer), )*
                 }
             }
        }

        impl $crate::TpmMarshal for TpmResponseValue {
             fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(r) => $crate::TpmMarshal::marshal(r, writer), )*
                 }
             }
        }

        impl $crate::frame::TpmFrame for TpmResponseValue {
            fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(r) => $crate::frame::TpmFrame::cc(r), )*
                }
            }
            fn handles(&self) -> usize {
                match self {
                    $( Self::$variant(r) => $crate::frame::TpmFrame::handles(r), )*
                }
            }
        }

        impl TpmResponseValue {
            $(
                /// Attempts to convert the `TpmResponseValue` into a specific response type.
                ///
                /// # Errors
                ///
                /// Returns the original `TpmResponseValue` as an error if the enum variant does not match.
                #[allow(non_snake_case, clippy::result_large_err)]
                pub fn $variant(self) -> Result<$crate::frame::data::$resp, Self> {
                    if let Self::$variant(r) = self {
                        Ok(r)
                    } else {
                        Err(self)
                    }
                }
            )*

            /// Marshals a response body into a writer.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmProtocolError)` on a marshal failure.
            pub fn marshal_frame(
                &self,
                rc: $crate::data::TpmRc,
                sessions: &$crate::frame::TpmAuthResponses,
                writer: &mut $crate::TpmWriter,
            ) -> $crate::TpmResult<()> {
                match self {
                    $( Self::$variant(r) => $crate::frame::tpm_marshal_response(r, sessions, rc, writer), )*
                }
            }
        }

        pub(crate) static TPM_DISPATCH_TABLE: &[$crate::frame::TpmDispatch] = &[
            $(
                $crate::frame::TpmDispatch {
                    cc: <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC,
                    handles: <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::HANDLES,
                    response_handles: <$crate::frame::data::$resp as $crate::frame::TpmHeader>::HANDLES,
                    command_unmarshaler: |handles, params| {
                        <$crate::frame::data::$cmd as $crate::frame::TpmUnmarshalCommand>::unmarshal_body(handles, params)
                            .map(|(c, r)| (TpmCommandValue::$variant(c), r))
                    },
                    response_unmarshaler: |tag, buf| {
                        <$crate::frame::data::$resp as $crate::frame::TpmUnmarshalResponse>::unmarshal_body(tag, buf)
                            .map(|(r, rest)| (TpmResponseValue::$variant(r), rest))
                    },
                },
            )*
        ];

        $crate::tpm_dispatch!(@const_check_sorted $( $cmd, )*);
    };
}
