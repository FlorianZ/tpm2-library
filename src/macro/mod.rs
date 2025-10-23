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

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&self.0, writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = <$repr>::parse(buf)?;
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

        impl $crate::TpmBuild for $name {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $crate::TpmBuild::build(&u8::from(self.0), writer)
            }
        }

        impl $crate::TpmParse for $name {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (val, buf) = u8::parse(buf)?;
                match val {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    _ => Err($crate::TpmError::UnknownDiscriminant (stringify!($name), TpmDiscriminant::Unsigned(u64::from(val)))),
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
            <$crate::message::data::$prev_cmd as $crate::message::TpmHeader>::CC as u32 <= <$crate::message::data::$current_cmd as $crate::message::TpmHeader>::CC as u32,
            "TPM_DISPATCH_TABLE must be sorted by TpmCc."
        );
        $crate::tpm_dispatch!(@const_check_sorted_impl $current_cmd, $( $rest_cmd, )*);
    };

    ( $( ($cmd:ident, $resp:ident, $variant:ident) ),* $(,)? ) => {
        /// A TPM command
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmCommandBody {
            $( $variant($crate::message::data::$cmd), )*
        }

        impl $crate::TpmSized for TpmCommandBody {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(c) => $crate::TpmSized::len(c), )*
                }
            }
        }

        impl TpmCommandBody {
            #[must_use]
            pub fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(c) => c.cc(), )*
                }
            }

            /// Builds a command body into a writer.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` on a build failure.
            pub fn build(
                &self,
                tag: $crate::data::TpmSt,
                sessions: &$crate::message::TpmAuthCommands,
                writer: &mut $crate::TpmWriter,
            ) -> $crate::TpmResult<()> {
                match self {
                    $( Self::$variant(c) => $crate::message::tpm_build_command(c, tag, sessions, writer), )*
                }
            }
        }

        /// A TPM response body
        #[allow(clippy::large_enum_variant)]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum TpmResponseBody {
            $( $variant($crate::message::data::$resp), )*
        }

        impl $crate::TpmSized for TpmResponseBody {
            const SIZE: usize = $crate::constant::TPM_MAX_COMMAND_SIZE;
            fn len(&self) -> usize {
                match self {
                    $( Self::$variant(r) => $crate::TpmSized::len(r), )*
                }
            }
        }

        impl TpmResponseBody {
            #[must_use]
            pub fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(r) => r.cc(), )*
                }
            }

            $(
                /// Attempts to convert the `TpmResponseBody` into a specific response type.
                ///
                /// # Errors
                ///
                /// Returns the original `TpmResponseBody` as an error if the enum variant does not match.
                #[allow(non_snake_case, clippy::result_large_err)]
                pub fn $variant(self) -> Result<$crate::message::data::$resp, Self> {
                    if let Self::$variant(r) = self {
                        Ok(r)
                    } else {
                        Err(self)
                    }
                }
            )*

            /// Builds a response body into a writer.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` on a build failure.
            pub fn build(
                &self,
                rc: $crate::data::TpmRc,
                sessions: &$crate::message::TpmAuthResponses,
                writer: &mut $crate::TpmWriter,
            ) -> $crate::TpmResult<()> {
                match self {
                    $( Self::$variant(r) => $crate::message::tpm_build_response(r, sessions, rc, writer), )*
                }
            }
        }

        pub(crate) static TPM_DISPATCH_TABLE: &[$crate::message::TpmDispatch] = &[
            $(
                $crate::message::TpmDispatch {
                    cc: <$crate::message::data::$cmd as $crate::message::TpmHeader>::CC,
                    handles: <$crate::message::data::$cmd as $crate::message::TpmHeader>::HANDLES,
                    command_parser: |handles, params| {
                        <$crate::message::data::$cmd as $crate::message::TpmCommandBodyParse>::parse_body(handles, params)
                            .map(|(c, r)| (TpmCommandBody::$variant(c), r))
                    },
                    response_parser: |tag, buf| {
                        <$crate::message::data::$resp as $crate::message::TpmResponseBodyParse>::parse_body(tag, buf)
                            .map(|(r, rest)| (TpmResponseBody::$variant(r), rest))
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

        impl $crate::TpmBuild for $wrapper_ty {
            fn build(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let inner_len = $crate::TpmSized::len(&self.inner);
                u16::try_from(inner_len)
                    .map_err(|_| $crate::TpmError::CapacityExceeded)?
                    .build(writer)?;
                $crate::TpmBuild::build(&self.inner, writer)
            }
        }

        impl $crate::TpmParse for $wrapper_ty {
            fn parse(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (size, buf_after_size) = u16::parse(buf)?;
                let size = size as usize;

                if buf_after_size.len() < size {
                    return Err($crate::TpmError::DataTruncated);
                }
                let (inner_bytes, rest) = buf_after_size.split_at(size);

                let (inner_val, tail) = <$inner_ty>::parse(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmError::TrailingData);
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
