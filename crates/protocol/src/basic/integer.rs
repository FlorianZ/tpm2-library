// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmCast, TpmCastMut, TpmMarshal, TpmResult, TpmSized, TpmWireBytes, TpmWriter};
use core::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, LowerHex, UpperHex},
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// Native integer that can occupy an `N`-byte TPM wire field.
trait TpmIntBytes<const N: usize>: Copy + Ord {
    fn to_be_bytes(self) -> [u8; N];
    fn from_be_bytes(bytes: [u8; N]) -> Self;
}

/// Big-endian TPM integer of native type `T` and wire width `N`.
#[repr(transparent)]
pub struct TpmInt<T, const N: usize>([u8; N], PhantomData<T>);

impl<T, const N: usize> Copy for TpmInt<T, N> {}

impl<T, const N: usize> Clone for TpmInt<T, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, const N: usize> TpmInt<T, N> {
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; N]) -> Self {
        Self(bytes, PhantomData)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; N] {
        self.0
    }

    /// Casts a byte slice into a TPM integer wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than this integer's wire size.
    /// Returns [`TrailingData`](crate::TpmError::TrailingData) when
    /// `buf` is larger than this integer's wire size.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
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
    pub fn validate(buf: &[u8]) -> TpmResult<()> {
        TpmWireBytes::<N>::validate(buf)
    }

    /// Validates that `buf` starts with a TPM integer wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than this integer's wire size.
    pub fn validate_prefix(buf: &[u8]) -> TpmResult<()> {
        TpmWireBytes::<N>::validate_prefix(buf)
    }

    /// Casts the first bytes in a slice into a TPM integer wire view.
    ///
    /// # Errors
    ///
    /// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when
    /// `buf` is smaller than this integer's wire size.
    pub fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::validate_prefix(buf)?;
        let (head, tail) = buf.split_at(N);

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
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
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
    pub fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::validate_prefix(buf)?;
        let (head, tail) = buf.split_at_mut(N);

        // SAFETY: The validation above guarantees that `head` has exactly
        // the byte length required by this transparent integer view.
        Ok((unsafe { Self::cast_mut_unchecked(head) }, tail))
    }
}

crate::tpm_byte_view!(array TpmInt<T, const N: usize>);

impl<T, const N: usize> Default for TpmInt<T, N> {
    fn default() -> Self {
        Self::from_be_bytes([0; N])
    }
}

impl<T, const N: usize> PartialEq for TpmInt<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T, const N: usize> Eq for TpmInt<T, N> {}

impl<T, const N: usize> Hash for TpmInt<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: TpmIntBytes<N>, const N: usize> PartialOrd for TpmInt<T, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: TpmIntBytes<N>, const N: usize> Ord for TpmInt<T, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        T::from_be_bytes(self.0).cmp(&T::from_be_bytes(other.0))
    }
}

impl<T: TpmIntBytes<N> + Debug, const N: usize> Debug for TpmInt<T, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("TpmInt")
            .field(&T::from_be_bytes(self.0))
            .finish()
    }
}

impl<T: TpmIntBytes<N>, const N: usize> From<T> for TpmInt<T, N> {
    fn from(value: T) -> Self {
        Self::from_be_bytes(value.to_be_bytes())
    }
}

impl<T: TpmIntBytes<N> + Display, const N: usize> Display for TpmInt<T, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&T::from_be_bytes(self.0), f)
    }
}

impl<T: TpmIntBytes<N> + LowerHex, const N: usize> LowerHex for TpmInt<T, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&T::from_be_bytes(self.0), f)
    }
}

impl<T: TpmIntBytes<N> + UpperHex, const N: usize> UpperHex for TpmInt<T, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&T::from_be_bytes(self.0), f)
    }
}

impl<T, const N: usize> TpmSized for TpmInt<T, N> {
    const SIZE: usize = N;

    fn len(&self) -> usize {
        Self::SIZE
    }
}

impl<T, const N: usize> TpmMarshal for TpmInt<T, N> {
    fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
        writer.write_bytes(self.as_bytes())
    }
}

impl<T, const N: usize> TpmCast for TpmInt<T, N> {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::cast_prefix(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `TpmInt`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl<T, const N: usize> TpmCastMut for TpmInt<T, N> {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::cast_prefix_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for `TpmInt`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl<T, const N: usize> TryFrom<usize> for TpmInt<T, N>
where
    T: TpmIntBytes<N> + TryFrom<usize>,
{
    type Error = T::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        T::try_from(value).map(Self::from)
    }
}

macro_rules! tpm_int {
    ($name:ident, $raw:ty, $n:literal) => {
        pub type $name = TpmInt<$raw, $n>;

        impl TpmIntBytes<$n> for $raw {
            fn to_be_bytes(self) -> [u8; $n] {
                <$raw>::to_be_bytes(self)
            }

            fn from_be_bytes(bytes: [u8; $n]) -> Self {
                <$raw>::from_be_bytes(bytes)
            }
        }

        impl TpmInt<$raw, $n> {
            #[must_use]
            pub const fn new(value: $raw) -> Self {
                Self::from_be_bytes(<$raw>::to_be_bytes(value))
            }

            #[must_use]
            pub const fn value(self) -> $raw {
                <$raw>::from_be_bytes(self.to_be_bytes())
            }

            pub const fn set(&mut self, value: $raw) {
                *self = Self::new(value);
            }
        }

        impl From<TpmInt<$raw, $n>> for $raw {
            fn from(value: TpmInt<$raw, $n>) -> $raw {
                value.value()
            }
        }
    };
}

tpm_int!(TpmUint8, u8, 1);
tpm_int!(TpmInt8, i8, 1);
tpm_int!(TpmUint16, u16, 2);
tpm_int!(TpmUint32, u32, 4);
tpm_int!(TpmUint64, u64, 8);
tpm_int!(TpmInt32, i32, 4);

pub type TpmHandle = TpmUint32;
