// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! integer {
    ($name:ident, $raw:ty, $bytes:expr) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $raw);

        impl $name {
            #[must_use]
            pub const fn new(value: $raw) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn value(self) -> $raw {
                self.0
            }

            #[must_use]
            pub fn to_be_bytes(self) -> [u8; $bytes] {
                self.0.to_be_bytes()
            }

            #[must_use]
            pub fn from_be_bytes(bytes: [u8; $bytes]) -> Self {
                Self(<$raw>::from_be_bytes(bytes))
            }
        }

        impl From<$raw> for $name {
            fn from(value: $raw) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $raw {
            fn from(value: $name) -> $raw {
                value.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl core::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = core::mem::size_of::<$raw>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                writer.write_bytes(&self.to_be_bytes())
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let size = core::mem::size_of::<$raw>();
                let bytes = buf
                    .get(..size)
                    .ok_or($crate::TpmProtocolError::UnexpectedEnd)?;
                let array = bytes
                    .try_into()
                    .map_err(|_| $crate::TpmProtocolError::UnexpectedEnd)?;
                let val = Self::from_be_bytes(array);
                Ok((val, &buf[size..]))
            }
        }

        impl TryFrom<usize> for $name
        where
            $raw: TryFrom<usize>,
        {
            type Error = <$raw as TryFrom<usize>>::Error;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                <$raw>::try_from(value).map(Self)
            }
        }

        impl $crate::TpmSized for $raw {
            const SIZE: usize = core::mem::size_of::<$raw>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl $crate::TpmMarshal for $raw {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                writer.write_bytes(&self.to_be_bytes())
            }
        }

        impl $crate::TpmUnmarshal for $raw {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let size = core::mem::size_of::<$raw>();
                let bytes = buf
                    .get(..size)
                    .ok_or($crate::TpmProtocolError::UnexpectedEnd)?;
                let array = bytes
                    .try_into()
                    .map_err(|_| $crate::TpmProtocolError::UnexpectedEnd)?;
                let val = <$raw>::from_be_bytes(array);
                Ok((val, &buf[size..]))
            }
        }
    };
}
