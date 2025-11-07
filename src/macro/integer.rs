// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! tpm_integer {
    ($ty:ty, $variant:ident) => {
        impl TpmUnmarshal for $ty {
            fn unmarshal(buf: &[u8]) -> TpmResult<(Self, &[u8])> {
                let size = size_of::<$ty>();
                let bytes = buf.get(..size).ok_or(TpmProtocolError::UnexpectedEof)?;
                let array = bytes
                    .try_into()
                    .map_err(|_| TpmProtocolError::MalformedValue)?;
                let val = <$ty>::from_be_bytes(array);
                Ok((val, &buf[size..]))
            }
        }

        impl TpmMarshal for $ty {
            fn marshal(&self, writer: &mut TpmWriter) -> TpmResult<()> {
                writer.write_bytes(&self.to_be_bytes())
            }
        }

        impl TpmSized for $ty {
            const SIZE: usize = size_of::<$ty>();
            fn len(&self) -> usize {
                Self::SIZE
            }
        }

        impl core::convert::From<$ty> for TpmDiscriminant {
            fn from(value: $ty) -> Self {
                Self::$variant(value.into())
            }
        }
    };
}
