// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! integer {
    ($name:ident, $raw:ty, $bytes:expr) => {
        #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name([u8; $bytes]);

        impl $name {
            #[must_use]
            pub const fn new(value: $raw) -> Self {
                Self(value.to_be_bytes())
            }

            #[must_use]
            pub const fn value(self) -> $raw {
                <$raw>::from_be_bytes(self.0)
            }

            #[must_use]
            pub const fn get(&self) -> $raw {
                <$raw>::from_be_bytes(self.0)
            }

            pub const fn set(&mut self, value: $raw) {
                self.0 = value.to_be_bytes();
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            #[must_use]
            pub fn as_bytes_mut(&mut self) -> &mut [u8; $bytes] {
                &mut self.0
            }

            #[must_use]
            pub fn to_be_bytes(self) -> [u8; $bytes] {
                self.0
            }

            #[must_use]
            pub const fn from_be_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            /// Casts a byte slice into a TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
            /// `buf` is larger than this integer's wire size.
            pub fn cast(buf: &[u8]) -> $crate::TpmResult<&Self> {
                let _ = $crate::TpmWireBytes::<$bytes>::cast(buf)?;

                // SAFETY: `TpmWireBytes::<$bytes>::cast` validated the exact
                // byte length required by this transparent integer view.
                Ok(unsafe { Self::cast_unchecked(buf) })
            }

            /// Casts a byte slice into a TPM integer wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure that `buf.len()` equals this integer's
            /// wire size and that any containing protocol structure has been
            /// validated as needed.
            #[must_use]
            pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                let ptr = buf.as_ptr().cast::<Self>();

                // SAFETY: `$name` is `repr(transparent)` over `[u8; $bytes]`.
                // The caller guarantees exact size.
                unsafe { &*ptr }
            }

            /// Casts a mutable byte slice into a mutable TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
            /// `buf` is larger than this integer's wire size.
            pub fn cast_mut(buf: &mut [u8]) -> $crate::TpmResult<&mut Self> {
                let _ = $crate::TpmWireBytes::<$bytes>::cast_mut(buf)?;

                // SAFETY: `TpmWireBytes::<$bytes>::cast_mut` validated the exact
                // byte length required by this transparent integer view.
                Ok(unsafe { Self::cast_mut_unchecked(buf) })
            }

            /// Casts a mutable byte slice into a mutable TPM integer wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure that `buf.len()` equals this integer's
            /// wire size and that any containing protocol structure has been
            /// validated as needed. The returned reference inherits the
            /// exclusive access represented by `buf`.
            #[must_use]
            pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
                let ptr = buf.as_mut_ptr().cast::<Self>();

                // SAFETY: `$name` is `repr(transparent)` over `[u8; $bytes]`.
                // The caller guarantees exact size.
                unsafe { &mut *ptr }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.get()).finish()
            }
        }

        impl core::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl core::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.get().cmp(&other.get())
            }
        }

        impl From<$raw> for $name {
            fn from(value: $raw) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $raw {
            fn from(value: $name) -> $raw {
                value.value()
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.get(), f)
            }
        }

        impl core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self.get(), f)
            }
        }

        impl core::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::UpperHex::fmt(&self.get(), f)
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = $bytes;
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                writer.write_bytes(self.as_bytes())
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let size = core::mem::size_of::<$raw>();
                let bytes = buf.get(..size).ok_or($crate::TpmError::UnexpectedEnd(
                    $crate::TpmErrorValue::new(0).size(size, buf.len()),
                ))?;
                let array = bytes.try_into().map_err(|_| {
                    $crate::TpmError::UnexpectedEnd(
                        $crate::TpmErrorValue::new(0).size(size, buf.len()),
                    )
                })?;
                let val = Self::from_be_bytes(array);
                Ok((val, &buf[size..]))
            }
        }

        impl $crate::TpmCast for $name {
            fn cast(buf: &[u8]) -> $crate::TpmResult<&Self> {
                Self::cast(buf)
            }

            unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                // SAFETY: The caller upholds the unchecked cast contract for `$name`.
                unsafe { Self::cast_unchecked(buf) }
            }
        }

        impl $crate::TpmCastMut for $name {
            fn cast_mut(buf: &mut [u8]) -> $crate::TpmResult<&mut Self> {
                Self::cast_mut(buf)
            }

            unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
                // SAFETY: The caller upholds the unchecked mutable cast contract for `$name`.
                unsafe { Self::cast_mut_unchecked(buf) }
            }
        }

        impl TryFrom<usize> for $name
        where
            $raw: TryFrom<usize>,
        {
            type Error = <$raw as TryFrom<usize>>::Error;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                <$raw>::try_from(value).map(Self::new)
            }
        }
    };
}
