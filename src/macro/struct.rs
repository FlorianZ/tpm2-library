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

        impl $name {
            /// Casts a command frame into a typed wire view for this command.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the frame is malformed or
            /// has a different command code.
            pub fn cast_frame(buf: &[u8]) -> $crate::TpmResult<&$crate::frame::TpmCommand> {
                let command = <$crate::frame::TpmCommand>::cast(buf)?;

                let cc = command.cc()?;
                if cc != Self::CC {
                    return Err($crate::TpmError::InvalidCc(
                        $crate::TpmErrorValue::new(6).value(u64::from(cc.value())),
                    ));
                }

                Ok(command)
            }

            /// Casts a mutable command frame into a typed mutable wire view for this command.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the frame is malformed or
            /// has a different command code.
            pub fn cast_frame_mut(
                buf: &mut [u8],
            ) -> $crate::TpmResult<&mut $crate::frame::TpmCommand> {
                let command = <$crate::frame::TpmCommand>::cast_mut(buf)?;

                let cc = command.cc()?;
                if cc != Self::CC {
                    return Err($crate::TpmError::InvalidCc(
                        $crate::TpmErrorValue::new(6).value(u64::from(cc.value())),
                    ));
                }

                Ok(command)
            }
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
                    return Err($crate::TpmError::TrailingData(
                        $crate::TpmErrorValue::at(handles_buf, cursor).actual(cursor.len()),
                    ));
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

        impl $name {
            /// Casts a response frame into a typed wire view for this response.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the frame envelope is malformed.
            pub fn cast_frame(buf: &[u8]) -> $crate::TpmResult<&$crate::frame::TpmResponse> {
                <$crate::frame::TpmResponse>::cast(buf)
            }

            /// Casts a mutable response frame into a typed mutable wire view for this response.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the frame envelope is malformed.
            pub fn cast_frame_mut(
                buf: &mut [u8],
            ) -> $crate::TpmResult<&mut $crate::frame::TpmResponse> {
                <$crate::frame::TpmResponse>::cast_mut(buf)
            }
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
                        return Err($crate::TpmError::UnexpectedEnd(
                            $crate::TpmErrorValue::at(buf, buf_after_size).size(size, buf_after_size.len()),
                        ));
                    }
                    let (mut params_cursor, final_tail) = buf_after_size.split_at(size);

                    $(
                        let ($param_field, tail) = <$param_type as $crate::TpmUnmarshal>::unmarshal(params_cursor)?;
                        params_cursor = tail;
                    )*

                    if !params_cursor.is_empty() {
                        return Err($crate::TpmError::TrailingData(
                            $crate::TpmErrorValue::at(buf, params_cursor).actual(params_cursor.len()),
                        ));
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
            const SIZE: usize = $crate::basic::TpmUint16::SIZE + <$inner_ty>::SIZE;
            fn len(&self) -> usize {
                $crate::basic::TpmUint16::SIZE + $crate::TpmSized::len(&self.inner)
            }
        }

        impl $crate::TpmMarshal for $wrapper_ty
        where
            $inner_ty: $crate::TpmSized,
        {
            fn marshal(&self, writer: &mut $crate::TpmWriter) -> $crate::TpmResult<()> {
                let inner_len = $crate::TpmSized::len(&self.inner);
                let len_field = <$crate::basic::TpmUint16>::try_from(inner_len)
                    .map_err(|_| $crate::TpmError::IntegerTooLarge(
                        $crate::TpmErrorValue::new(writer.len()).value_usize(inner_len),
                    ))?;
                len_field.marshal(writer)?;
                $crate::TpmMarshal::marshal(&self.inner, writer)
            }
        }

        impl $crate::TpmUnmarshal for $wrapper_ty {
            fn unmarshal(buf: &[u8]) -> $crate::TpmResult<(Self, &[u8])> {
                let (size, buf_after_size) = <$crate::basic::TpmUint16 as $crate::TpmUnmarshal>::unmarshal(buf)?;
                let size = u16::from(size) as usize;

                if buf_after_size.len() < size {
                    return Err($crate::TpmError::UnexpectedEnd(
                        $crate::TpmErrorValue::at(buf, buf_after_size).size(size, buf_after_size.len()),
                    ));
                }
                let (inner_bytes, rest) = buf_after_size.split_at(size);

                let (inner_val, tail) = <$inner_ty>::unmarshal(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmError::TrailingData(
                        $crate::TpmErrorValue::at(buf, tail).actual(tail.len()),
                    ));
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
