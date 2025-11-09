// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub mod r#enum;
pub mod integer;
pub mod r#struct;

#[macro_export]
macro_rules! tpm_bitflags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident($repr:ty) {
            $(
                $(#[$inner:meta])*
                const $field:ident = $value:expr, $string_name:literal;
            )*
        }
    ) => {
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

            #[must_use]
            pub const fn empty() -> Self {
                Self(0)
            }

            #[must_use]
            pub const fn contains(&self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            pub fn flag_names(&self) -> impl Iterator<Item = &'static str> + '_ {
                [
                    $(
                        (Self::$field, $string_name),
                    )*
                ]
                .into_iter()
                .filter(move |(flag, _)| self.contains(*flag))
                .map(|(_, name)| name)
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

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmMarshal::marshal(&self.0, writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = <$repr>::unmarshal(buf)?;
                Ok((Self(val), buf))
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$repr>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }
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
                $crate::TpmMarshal::marshal(&u8::from(self.0), writer)
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = u8::unmarshal(buf)?;
                match val {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    _ => Err($crate::TpmProtocolError::InvalidValue),
                }
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<u8>();
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
        /// A TPM command
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmCommand {
            $( $variant($crate::frame::data::$cmd), )*
        }

        impl $crate::TpmSized for TpmCommand {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE as usize;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(c) => $crate::TpmSized::len(c), )*
                }
            }
        }

        impl $crate::frame::TpmMarshalBody for TpmCommand {
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

        impl $crate::TpmMarshal for TpmCommand {
             fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(c) => $crate::TpmMarshal::marshal(c, writer), )*
                 }
             }
        }

        impl $crate::frame::TpmFrame for TpmCommand {
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

        impl TpmCommand {
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

        /// A TPM response body
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmResponse {
            $( $variant($crate::frame::data::$resp), )*
        }

        impl $crate::TpmSized for TpmResponse {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE as usize;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(r) => $crate::TpmSized::len(r), )*
                }
            }
        }

        impl $crate::frame::TpmMarshalBody for TpmResponse {
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

        impl $crate::TpmMarshal for TpmResponse {
             fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                 match self {
                     $( Self::$variant(r) => $crate::TpmMarshal::marshal(r, writer), )*
                 }
             }
        }

        impl $crate::frame::TpmFrame for TpmResponse {
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

        impl TpmResponse {
            $(
                /// Attempts to convert the `TpmResponse` into a specific response type.
                ///
                /// # Errors
                ///
                /// Returns the original `TpmResponse` as an error if the enum variant does not match.
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
                    command_unmarshaler: |handles, params| {
                        <$crate::frame::data::$cmd as $crate::frame::TpmUnmarshalCommand>::unmarshal_body(handles, params)
                            .map(|(c, r)| (TpmCommand::$variant(c), r))
                    },
                    response_unmarshaler: |tag, buf| {
                        <$crate::frame::data::$resp as $crate::frame::TpmUnmarshalResponse>::unmarshal_body(tag, buf)
                            .map(|(r, rest)| (TpmResponse::$variant(r), rest))
                    },
                },
            )*
        ];

        $crate::tpm_dispatch!(@const_check_sorted $( $cmd, )*);
    };
}

#[macro_export]
macro_rules! tpm2b {
    ($name:ident, $capacity:expr) => {
        pub type $name = $crate::basic::TpmBuffer<$capacity>;
    };
}

#[macro_export]
macro_rules! tpm2b_struct {
    (
        $(#[$meta:meta])*
        $wrapper_ty:ident, $inner_ty:ty) => {
        $(#[$meta])*
        pub struct $wrapper_ty {
            pub inner: $inner_ty,
        }

        impl $crate::TpmSized for $wrapper_ty {
            const SIZE: usize = core::mem::size_of::<u16>() + <$inner_ty>::SIZE;
            fn len(&self) -> usize {
                core::mem::size_of::<u16>() + $crate::TpmSized::len(&self.inner)
            }
        }

        impl $crate::TpmMarshal for $wrapper_ty {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let inner_len = $crate::TpmSized::len(&self.inner);
                u16::try_from(inner_len)
                    .map_err(|_| $crate::TpmProtocolError::OperationFailed)?
                    .marshal(writer)?;
                $crate::TpmMarshal::marshal(&self.inner, writer)
            }
        }

        impl $crate::TpmUnmarshal for $wrapper_ty {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (size, buf_after_size) = u16::unmarshal(buf)?;
                let size = size as usize;

                if buf_after_size.len() < size {
                    return Err($crate::TpmProtocolError::UnexpectedEnd);
                }
                let (inner_bytes, rest) = buf_after_size.split_at(size);

                let (inner_val, tail) = <$inner_ty>::unmarshal(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmProtocolError::TrailingData);
                }

                Ok((Self { inner: inner_val }, rest))
            }
        }

        impl From<$inner_ty> for $wrapper_ty {
            fn from(inner: $inner_ty) -> Self {
                Self { inner }
            }
        }

        impl core::ops::Deref for $wrapper_ty {
            type Target = $inner_ty;
            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl core::ops::DerefMut for $wrapper_ty {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }
    };
}

#[macro_export]
macro_rules! tpml {
    ($name:ident, $inner_ty:ty, $capacity:expr) => {
        pub type $name = $crate::basic::TpmList<$inner_ty, $capacity>;
    };
}
