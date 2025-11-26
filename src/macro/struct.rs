// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! tpm_struct {
    (
        $(#[$meta:meta])*
        kind: Command,
        name: $name:ident,
        cc: $cc:expr,
        handles: $count:literal,
        parameters: {
            $(pub $param_field:ident: $param_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            pub handles: [$crate::basic::TpmHandle; $count],
            $(pub $param_field: $param_type,)*
        }

        impl $crate::frame::TpmHeader for $name {
            const CC: $crate::data::TpmCc = $cc;
            const HANDLES: usize = $count;
        }

        impl $crate::frame::TpmFrame for $name {
            fn cc(&self) -> $crate::data::TpmCc {
                Self::CC
            }
            fn handles(&self) -> usize {
                Self::HANDLES
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = (Self::HANDLES * <$crate::basic::TpmHandle>::SIZE) $(+ <$param_type>::SIZE)*;
            fn len(&self) -> usize {
                (self.handles.len() * <$crate::basic::TpmHandle>::SIZE) $(+ $crate::TpmSized::len(&self.$param_field))*
            }
        }

        impl $crate::TpmMarshal for $name {
            #[allow(unused_variables)]
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                <Self as $crate::frame::TpmMarshalBody>::marshal_handles(self, writer)?;
                <Self as $crate::frame::TpmMarshalBody>::marshal_parameters(self, writer)
            }
        }

        impl $crate::frame::TpmMarshalBody for $name {
            #[allow(unused_variables)]
            fn marshal_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                for handle in &self.handles {
                    $crate::TpmMarshal::marshal(handle, writer)?;
                }
                Ok(())
            }

            #[allow(unused_variables)]
            fn marshal_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmMarshal::marshal(&self.$param_field, writer)?;)*
                Ok(())
            }
        }

        impl $crate::frame::TpmUnmarshalCommand for $name {
            #[allow(unused_mut, unused_variables)]
            fn unmarshal_body<'a>(
                handles_buf: &'a [u8],
                params_buf: &'a [u8],
            ) -> $crate::TpmResult<(Self, &'a [u8])> {
                let mut cursor = handles_buf;
                let mut handles: [$crate::basic::TpmHandle; $count] = ::core::default::Default::default();
                for handle in &mut handles {
                    let (val, tail) = <$crate::basic::TpmHandle as $crate::TpmUnmarshal>::unmarshal(cursor)?;
                    *handle = val;
                    cursor = tail;
                }

                if !cursor.is_empty() {
                    return Err($crate::TpmProtocolError::TrailingData);
                }

                let mut cursor = params_buf;
                $(
                    let ($param_field, tail) = <$param_type as $crate::TpmUnmarshal>::unmarshal(cursor)?;
                    cursor = tail;
                )*

                Ok((
                    Self {
                        handles,
                        $($param_field,)*
                    },
                    cursor,
                ))
            }
        }
    };

    (
        $(#[$meta:meta])*
        kind: Response,
        name: $name:ident,
        cc: $cc:expr,
        handles: $count:literal,
        parameters: {
            $(pub $param_field:ident: $param_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            pub handles: [$crate::basic::TpmHandle; $count],
            $(pub $param_field: $param_type,)*
        }

        impl $crate::frame::TpmHeader for $name {
            const CC: $crate::data::TpmCc = $cc;
            const HANDLES: usize = $count;
        }

        impl $crate::frame::TpmFrame for $name {
            fn cc(&self) -> $crate::data::TpmCc {
                Self::CC
            }
            fn handles(&self) -> usize {
                Self::HANDLES
            }
        }

        impl $crate::frame::TpmMarshalBody for $name {
            #[allow(unused_variables)]
            fn marshal_handles(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                for handle in &self.handles {
                    $crate::TpmMarshal::marshal(handle, writer)?;
                }
                Ok(())
            }
            #[allow(unused_variables)]
            fn marshal_parameters(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $($crate::TpmMarshal::marshal(&self.$param_field, writer)?;)*
                Ok(())
            }
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = (Self::HANDLES * <$crate::basic::TpmHandle>::SIZE) $(+ <$param_type>::SIZE)*;
            fn len(&self) -> usize {
                (self.handles.len() * <$crate::basic::TpmHandle>::SIZE) $(+ $crate::TpmSized::len(&self.$param_field))*
            }
        }

        impl $crate::TpmMarshal for $name {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                <Self as $crate::frame::TpmMarshalBody>::marshal_handles(self, writer)?;
                <Self as $crate::frame::TpmMarshalBody>::marshal_parameters(self, writer)
            }
        }

        impl $crate::frame::TpmUnmarshalResponse for $name {
            #[allow(unused_mut, unused_variables)]
            fn unmarshal_body(
                tag: $crate::data::TpmSt,
                buf: &[u8],
            ) -> $crate::TpmResult<(Self, &[u8])> {
                let mut cursor = buf;
                let mut handles: [$crate::basic::TpmHandle; $count] = ::core::default::Default::default();
                for handle in &mut handles {
                    let (val, tail) = <$crate::basic::TpmHandle as $crate::TpmUnmarshal>::unmarshal(cursor)?;
                    *handle = val;
                    cursor = tail;
                }

                if tag == $crate::data::TpmSt::Sessions {
                    let (size, buf_after_size) =
                        <$crate::basic::TpmUint32 as $crate::TpmUnmarshal>::unmarshal(cursor)?;
                    let size = u32::from(size) as usize;
                    if buf_after_size.len() < size {
                        return Err($crate::TpmProtocolError::UnexpectedEnd);
                    }
                    let (mut params_cursor, final_tail) = buf_after_size.split_at(size);

                    $(
                        let ($param_field, tail) = <$param_type as $crate::TpmUnmarshal>::unmarshal(params_cursor)?;
                        params_cursor = tail;
                    )*

                    if !params_cursor.is_empty() {
                        return Err($crate::TpmProtocolError::TrailingData);
                    }

                    Ok((
                        Self {
                            handles,
                            $($param_field,)*
                        },
                        final_tail,
                    ))
                } else {
                    let mut params_cursor = cursor;
                    $(
                        let ($param_field, tail) = <$param_type as $crate::TpmUnmarshal>::unmarshal(params_cursor)?;
                        params_cursor = tail;
                    )*

                    Ok((
                        Self {
                            handles,
                            $($param_field,)*
                        },
                        params_cursor,
                    ))
                }
            }
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(pub $field_name:ident: $field_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(pub $field_name: $field_type,)*
        }

        impl $crate::TpmSized for $name {
            const SIZE: usize = 0 $(+ <$field_type>::SIZE)*;
            fn len(&self) -> usize {
                0 $(+ $crate::TpmSized::len(&self.$field_name))*
            }
        }

        impl $crate::TpmMarshal for $name {
            #[allow(unused_variables)]
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                $( $crate::TpmMarshal::marshal(&self.$field_name, writer)?; )*
                Ok(())
            }
        }

        impl $crate::TpmUnmarshal for $name {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                $(let ($field_name, buf) = <$field_type>::unmarshal(buf)?;)*
                Ok((
                    Self {
                        $($field_name,)*
                    },
                    buf,
                ))
            }
        }
    };
}
