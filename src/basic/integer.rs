// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, TpmWriter};
use core::{convert::TryFrom, fmt, mem::size_of};

macro_rules! define_integer {
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

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl TpmSized for $name {
            const SIZE: usize = size_of::<$raw>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl TpmMarshal for $name {
            fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
                writer.write_bytes(&self.to_be_bytes())
            }
        }

        impl TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
                let size = size_of::<$raw>();
                let bytes = buf
                    .get(..size)
                    .ok_or(crate::TpmProtocolError::UnexpectedEnd)?;
                let array = bytes
                    .try_into()
                    .map_err(|_| crate::TpmProtocolError::UnexpectedEnd)?;
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
    };
}

define_integer!(Uint8, u8, 1);
define_integer!(Int8, i8, 1);
define_integer!(Uint16, u16, 2);
define_integer!(Uint32, u32, 4);
define_integer!(Uint64, u64, 8);
define_integer!(Int32, i32, 4);

/// Associates primitive integer types with their TPM wrapper counterparts.
pub trait IntegerRepr: Copy {
    /// The wrapper type used for marshaling and unmarshaling.
    type Wrapper: TpmSized + TpmMarshal + TpmUnmarshal + From<Self> + Into<Self>;
}

impl IntegerRepr for u8 {
    type Wrapper = Uint8;
}

impl IntegerRepr for i8 {
    type Wrapper = Int8;
}

impl IntegerRepr for u16 {
    type Wrapper = Uint16;
}

impl IntegerRepr for u32 {
    type Wrapper = Uint32;
}

impl IntegerRepr for u64 {
    type Wrapper = Uint64;
}

impl IntegerRepr for i32 {
    type Wrapper = Int32;
}
