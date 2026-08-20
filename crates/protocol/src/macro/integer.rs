// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[doc(hidden)]
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
                Self::validate(buf)?;

                // SAFETY: The validation above guarantees the exact byte length
                // required by this transparent integer view.
                Ok(unsafe { Self::cast_unchecked(buf) })
            }

            /// Validates an exact TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
            /// `buf` is larger than this integer's wire size.
            pub fn validate(buf: &[u8]) -> $crate::TpmResult<()> {
                $crate::TpmWireBytes::<$bytes>::validate(buf)
            }

            /// Validates that `buf` starts with a TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            pub fn validate_prefix(buf: &[u8]) -> $crate::TpmResult<()> {
                $crate::TpmWireBytes::<$bytes>::validate_prefix(buf)
            }

            /// Casts the first bytes in a slice into a TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            pub fn cast_prefix(buf: &[u8]) -> $crate::TpmResult<(&Self, &[u8])> {
                Self::validate_prefix(buf)?;
                let (head, tail) = buf.split_at($bytes);

                // SAFETY: The validation above guarantees that `head` has exactly
                // the byte length required by this transparent integer view.
                Ok((unsafe { Self::cast_unchecked(head) }, tail))
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
                Self::validate(buf)?;

                // SAFETY: The validation above guarantees the exact
                // byte length required by this transparent integer view.
                Ok(unsafe { Self::cast_mut_unchecked(buf) })
            }

            /// Casts the first mutable bytes in a slice into a TPM integer wire view.
            ///
            /// # Errors
            ///
            /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
            /// `buf` is smaller than this integer's wire size.
            pub fn cast_prefix_mut(buf: &mut [u8]) -> $crate::TpmResult<(&mut Self, &mut [u8])> {
                Self::validate_prefix(buf)?;
                let (head, tail) = buf.split_at_mut($bytes);

                // SAFETY: The validation above guarantees that `head` has exactly
                // the byte length required by this transparent integer view.
                Ok((unsafe { Self::cast_mut_unchecked(head) }, tail))
            }

        }

        $crate::tpm_byte_view!(array $name);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.value()).finish()
            }
        }

        impl core::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl core::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.value().cmp(&other.value())
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
                core::fmt::Display::fmt(&self.value(), f)
            }
        }

        impl core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self.value(), f)
            }
        }

        impl core::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::UpperHex::fmt(&self.value(), f)
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

        impl $crate::TpmCast for $name {
            fn cast(buf: &[u8]) -> $crate::TpmResult<&Self> {
                Self::cast(buf)
            }

            fn cast_prefix(buf: &[u8]) -> $crate::TpmResult<(&Self, &[u8])> {
                Self::cast_prefix(buf)
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

            fn cast_prefix_mut(buf: &mut [u8]) -> $crate::TpmResult<(&mut Self, &mut [u8])> {
                Self::cast_prefix_mut(buf)
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
