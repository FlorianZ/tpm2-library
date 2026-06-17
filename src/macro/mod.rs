// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

pub mod r#enum;
pub mod integer;
pub mod r#struct;

/// Generates the unchecked reinterpret casts shared by every
/// `repr(transparent)` wire view.
///
/// The bare form targets views backed by an unsized `[u8]` and also emits the
/// `AsRef`/`AsMut` byte-slice conversions. The `array` form targets views
/// backed by a fixed-size `[u8; N]` and emits only the unchecked casts.
#[macro_export]
macro_rules! tpm_byte_view {
    ($name:ident) => {
        $crate::tpm_byte_view!(@emit { } { $name });
    };
    ($name:ident<const $param:ident: usize>) => {
        $crate::tpm_byte_view!(@emit { <const $param: usize> } { $name<$param> });
    };
    (array $name:ident) => {
        $crate::tpm_byte_view!(@emit_array { } { $name });
    };
    (array $name:ident<const $param:ident: usize>) => {
        $crate::tpm_byte_view!(@emit_array { <const $param: usize> } { $name<$param> });
    };
    (@emit_array { $($generics:tt)* } { $($ty:tt)* }) => {
        impl $($generics)* $($ty)* {
            /// Casts a byte slice into this wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` satisfies every invariant required by
            /// the checked constructors for this view.
            #[must_use]
            pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                let ptr = buf.as_ptr().cast::<Self>();

                // SAFETY: an array-backed `tpm_byte_view!` type is
                // `repr(transparent)` over `[u8; N]`, sharing its layout and
                // alignment; the caller guarantees the exact byte length.
                unsafe { &*ptr }
            }

            /// Casts a mutable byte slice into this wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` satisfies every invariant required by
            /// the checked constructors for this view. The returned reference
            /// inherits the exclusive access represented by `buf`.
            #[must_use]
            pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
                let ptr = buf.as_mut_ptr().cast::<Self>();

                // SAFETY: an array-backed `tpm_byte_view!` type is
                // `repr(transparent)` over `[u8; N]`, sharing its layout and
                // alignment; the caller guarantees the exact byte length.
                unsafe { &mut *ptr }
            }
        }
    };
    (@emit { $($generics:tt)* } { $($ty:tt)* }) => {
        impl $($generics)* $($ty)* {
            /// Casts a byte slice into this wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` satisfies every invariant required by
            /// the checked constructors for this view.
            #[must_use]
            pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                let ptr = core::ptr::from_ref(buf) as *const Self;

                // SAFETY: a `tpm_byte_view!` type is `repr(transparent)` over
                // `[u8]`, sharing the slice's layout, metadata, and alignment.
                unsafe { &*ptr }
            }

            /// Casts a mutable byte slice into this wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` satisfies every invariant required by
            /// the checked constructors for this view. The returned reference
            /// inherits the exclusive access represented by `buf`.
            #[must_use]
            pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
                let ptr = core::ptr::from_mut(buf) as *mut Self;

                // SAFETY: a `tpm_byte_view!` type is `repr(transparent)` over
                // `[u8]`, sharing the slice's layout, metadata, and alignment.
                unsafe { &mut *ptr }
            }
        }

        impl $($generics)* AsRef<[u8]> for $($ty)* {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl $($generics)* AsMut<[u8]> for $($ty)* {
            fn as_mut(&mut self) -> &mut [u8] {
                self.as_bytes_mut()
            }
        }
    };
}

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

        impl<'a> $crate::TpmField<'a> for $name {
            type View = Self;

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                let (value, buf) = <$wrapper as $crate::TpmCast>::cast_prefix(buf)?;

                Ok((Self(value.value()), buf))
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

        impl<'a> $crate::TpmField<'a> for $name {
            type View = Self;

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                let (value, buf) = <$crate::basic::TpmUint8 as $crate::TpmCast>::cast_prefix(buf)?;
                match value.value() {
                    0 => Ok((Self(false), buf)),
                    1 => Ok((Self(true), buf)),
                    raw => Err($crate::TpmError::InvalidBoolean { offset: 0, value: u64::from(raw) }),
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
            /// Returns `Err(TpmError)` on a marshal failure.
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

        /// A borrowed TPM command frame selected by command code.
        pub enum TpmCommandView<'a> {
            $( $variant(&'a $crate::frame::TpmCommand), )*
        }

        impl<'a> TpmCommandView<'a> {
            /// Casts bytes into a borrowed command dispatch value.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the command frame is malformed or its
            /// command code has no dispatch entry.
            pub fn cast_frame(buf: &'a [u8]) -> $crate::TpmResult<Self> {
                let command = <$crate::frame::TpmCommand>::cast(buf)?;

                Self::cast(command)
            }

            /// Selects a borrowed command dispatch value from a command wire view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the command frame is malformed or its
            /// command code has no dispatch entry.
            pub fn cast(command: &'a $crate::frame::TpmCommand) -> $crate::TpmResult<Self> {
                command.validate()?;

                let cc = command.cc()?;
                match cc {
                    $( <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC => Ok(Self::$variant(command)), )*
                    #[allow(unreachable_patterns)]
                    _ => Err($crate::TpmError::InvalidCc { offset: 6, value: u64::from(cc.value()) }),
                }
            }

            /// Returns the selected command frame.
            #[must_use]
            pub fn command(&self) -> &'a $crate::frame::TpmCommand {
                match self {
                    $( Self::$variant(command) => command, )*
                }
            }

            /// Returns the selected command code.
            #[must_use]
            pub fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(_) => <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC, )*
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
            /// Returns `Err(TpmError)` on a marshal failure.
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

        /// A borrowed TPM response frame selected by command code.
        pub enum TpmResponseView<'a> {
            $( $variant(&'a $crate::frame::TpmResponse), )*
        }

        /// A borrowed response dispatch result or a TPM response code.
        pub type TpmResponseViewResult<'a> = Result<TpmResponseView<'a>, $crate::data::TpmRc>;

        impl<'a> TpmResponseView<'a> {
            /// Casts bytes into a borrowed response dispatch value.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the response frame is malformed or `cc`
            /// has no dispatch entry.
            pub fn cast_frame(
                cc: $crate::data::TpmCc,
                buf: &'a [u8],
            ) -> $crate::TpmResult<TpmResponseViewResult<'a>> {
                let response = <$crate::frame::TpmResponse>::cast(buf)?;

                Self::cast(cc, response)
            }

            /// Selects a borrowed response dispatch value from a response wire view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the response frame is malformed or `cc`
            /// has no dispatch entry.
            pub fn cast(
                cc: $crate::data::TpmCc,
                response: &'a $crate::frame::TpmResponse,
            ) -> $crate::TpmResult<TpmResponseViewResult<'a>> {
                let rc = response.rc()?;
                if !matches!(rc, $crate::data::TpmRc::Fmt0($crate::data::TpmRcBase::Success)) {
                    return Ok(Err(rc));
                }

                response.validate(cc)?;

                match cc {
                    $( <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC => Ok(Ok(Self::$variant(response))), )*
                    #[allow(unreachable_patterns)]
                    _ => Err($crate::TpmError::InvalidCc { offset: 0, value: u64::from(cc.value()) }),
                }
            }

            /// Returns the selected response frame.
            #[must_use]
            pub fn response(&self) -> &'a $crate::frame::TpmResponse {
                match self {
                    $( Self::$variant(response) => response, )*
                }
            }

            /// Returns the command code used for response dispatch.
            #[must_use]
            pub fn cc(&self) -> $crate::data::TpmCc {
                match self {
                    $( Self::$variant(_) => <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC, )*
                }
            }
        }

        pub(crate) static TPM_DISPATCH_TABLE: &[$crate::frame::TpmDispatch] = &[
            $(
                $crate::frame::TpmDispatch {
                    cc: <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::CC,
                    handles: <$crate::frame::data::$cmd as $crate::frame::TpmHeader>::HANDLES,
                    response_handles: <$crate::frame::data::$resp as $crate::frame::TpmHeader>::HANDLES,
                },
            )*
        ];

        $crate::tpm_dispatch!(@const_check_sorted $( $cmd, )*);
    };
}
