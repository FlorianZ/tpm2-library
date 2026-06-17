// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#[macro_export]
macro_rules! tpm_struct {
    (@wire_field_methods [$($prev_type:ty,)*],) => {};

    (@wire_field_methods [$($prev_type:ty,)*], pub $field_name:ident: $field_type:ty $(, pub $rest_field:ident: $rest_type:ty)* $(,)?) => {
        /// Returns a borrowed field view.
        ///
        /// # Errors
        ///
        /// Returns `Err(TpmError)` when preceding fields or this field are malformed.
        #[allow(unused_mut)]
        pub fn $field_name(&self) -> $crate::TpmResult<&$field_type>
        where
            $($prev_type: for<'a> $crate::TpmField<'a>,)*
            $field_type: for<'a> $crate::TpmField<'a, View = &'a $field_type>,
        {
            let mut cursor = &self.0;
            $(
                let (_, tail) = <$prev_type as $crate::TpmField>::cast_prefix_field(cursor)?;
                cursor = tail;
            )*

            let (value, _) = <$field_type as $crate::TpmField>::cast_prefix_field(cursor)?;

            Ok(value)
        }

        $crate::tpm_struct!(@wire_field_methods [$($prev_type,)* $field_type,], $(pub $rest_field: $rest_type),*);
    };

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
                    return Err($crate::TpmError::InvalidCc { offset: 6, value: u64::from(cc.value()) });
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
                    return Err($crate::TpmError::InvalidCc { offset: 6, value: u64::from(cc.value()) });
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
    };

    (
        $(#[$meta:meta])*
        wire: $wire:ident,
        $vis:vis struct $name:ident {
            $(pub $field_name:ident: $field_type:ty),*
            $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(pub $field_name: $field_type,)*
        }

        #[repr(transparent)]
        $vis struct $wire([u8]);

        impl $wire {
            /// Casts bytes into a typed wire structure view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` is not exactly one valid wire
            /// structure.
            pub fn cast(buf: &[u8]) -> $crate::TpmResult<&Self>
            where
                $($field_type: for<'a> $crate::TpmField<'a>,)*
            {
                Self::validate(buf)?;

                // SAFETY: `validate` checked the complete wire structure.
                Ok(unsafe { Self::cast_unchecked(buf) })
            }

            /// Casts the first typed wire structure from `buf` and returns the remainder.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` does not start with a valid wire
            /// structure.
            pub fn cast_prefix(buf: &[u8]) -> $crate::TpmResult<(&Self, &[u8])>
            where
                $($field_type: for<'a> $crate::TpmField<'a>,)*
            {
                let wire_len = Self::validate_prefix(buf)?;
                if buf.len() < wire_len {
                    return Err($crate::TpmError::UnexpectedEnd { offset: 0, needed: wire_len, available: buf.len() });
                }

                let (head, tail) = buf.split_at(wire_len);

                // SAFETY: `validate_prefix` checked the complete wire structure.
                Ok((unsafe { Self::cast_unchecked(head) }, tail))
            }

            /// Casts bytes into a typed wire structure view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` is exactly one valid wire structure.
            #[must_use]
            pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                let ptr = core::ptr::from_ref(buf) as *const Self;

                // SAFETY: `$wire` is `repr(transparent)` over `[u8]`, so it has
                // the same layout, metadata, and alignment as the referenced slice.
                unsafe { &*ptr }
            }

            /// Returns the complete wire structure bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Validates an exact typed wire structure view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` is not exactly one valid wire
            /// structure.
            pub fn validate(buf: &[u8]) -> $crate::TpmResult<()>
            where
                $($field_type: for<'a> $crate::TpmField<'a>,)*
            {
                let wire_len = Self::validate_prefix(buf)?;

                if buf.len() > wire_len {
                    return Err($crate::TpmError::TrailingData { offset: wire_len, actual: buf.len() - wire_len });
                }

                Ok(())
            }

            #[allow(unused_assignments, unused_mut, unused_variables)]
            /// Validates a typed wire structure prefix.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` does not start with a valid wire
            /// structure.
            pub fn validate_prefix(buf: &[u8]) -> $crate::TpmResult<usize>
            where
                $($field_type: for<'a> $crate::TpmField<'a>,)*
            {
                let mut cursor = buf;
                let mut consumed = 0usize;

                $(
                    let before = cursor.len();
                    let (_, tail) = <$field_type as $crate::TpmField>::cast_prefix_field(cursor)?;
                    let field_len = before.checked_sub(tail.len()).ok_or(
                        $crate::TpmError::IntegerTooLarge { offset: consumed, value: $crate::tpm_value(tail.len()) },
                    )?;
                    consumed = consumed.checked_add(field_len).ok_or(
                        $crate::TpmError::IntegerTooLarge { offset: consumed, value: $crate::tpm_value(before) },
                    )?;
                    cursor = tail;
                )*

                Ok(consumed)
            }

            $crate::tpm_struct!(@wire_field_methods [], $(pub $field_name: $field_type),*);
        }

        impl AsRef<[u8]> for $wire {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl<'a> $crate::TpmField<'a> for $name
        where
            $($field_type: for<'b> $crate::TpmField<'b>,)*
        {
            type View = &'a $wire;

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                $wire::cast_prefix(buf)
            }
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
        wire: $wire_ty:ident,
        $wrapper_ty:ident, $inner_ty:ty) => {
        $(#[$meta])*
        pub struct $wrapper_ty {
            pub inner: $inner_ty,
        }

        #[repr(transparent)]
        pub struct $wire_ty([u8]);

        impl $wire_ty {
            /// Casts bytes into a typed TPM2B wire view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` is not exactly one valid TPM2B
            /// wrapper for the inner type.
            pub fn cast(buf: &[u8]) -> $crate::TpmResult<&Self>
            where
                $inner_ty: for<'a> $crate::TpmField<'a>,
            {
                Self::validate(buf)?;

                // SAFETY: `validate` checked the complete TPM2B wrapper.
                Ok(unsafe { Self::cast_unchecked(buf) })
            }

            /// Casts the first TPM2B wire view from `buf` and returns the remainder.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` does not start with a valid TPM2B
            /// wrapper for the inner type.
            pub fn cast_prefix(buf: &[u8]) -> $crate::TpmResult<(&Self, &[u8])>
            where
                $inner_ty: for<'a> $crate::TpmField<'a>,
            {
                let wire_len = Self::validate_prefix(buf)?;
                let (head, tail) = buf.split_at(wire_len);

                // SAFETY: `validate_prefix` checked the complete TPM2B wrapper.
                Ok((unsafe { Self::cast_unchecked(head) }, tail))
            }

            /// Casts bytes into a typed TPM2B wire view without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure `buf` is exactly one valid TPM2B wrapper for
            /// the inner type.
            #[must_use]
            pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
                let ptr = core::ptr::from_ref(buf) as *const Self;

                // SAFETY: `$wire_ty` is `repr(transparent)` over `[u8]`, so it has
                // the same layout, metadata, and alignment as the referenced slice.
                unsafe { &*ptr }
            }

            /// Returns the complete TPM2B wrapper bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Returns the borrowed inner structure view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when the TPM2B payload is not exactly one
            /// valid inner structure.
            pub fn inner(&self) -> $crate::TpmResult<<$inner_ty as $crate::TpmField<'_>>::View>
            where
                $inner_ty: for<'a> $crate::TpmField<'a>,
            {
                let inner_bytes = &self.0[<$crate::basic::TpmUint16 as $crate::TpmSized>::SIZE..];
                let (inner, tail) = <$inner_ty as $crate::TpmField>::cast_prefix_field(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmError::TrailingData { offset: $crate::tpm_offset(&self.0, tail), actual: tail.len() });
                }

                Ok(inner)
            }

            /// Validates an exact typed TPM2B wire view.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` is not exactly one valid TPM2B
            /// wrapper for the inner type.
            pub fn validate(buf: &[u8]) -> $crate::TpmResult<()>
            where
                $inner_ty: for<'a> $crate::TpmField<'a>,
            {
                let wire_len = Self::validate_prefix(buf)?;

                if buf.len() > wire_len {
                    return Err($crate::TpmError::TrailingData { offset: wire_len, actual: buf.len() - wire_len });
                }

                Ok(())
            }

            /// Validates a typed TPM2B wire view prefix.
            ///
            /// # Errors
            ///
            /// Returns `Err(TpmError)` when `buf` does not start with a valid TPM2B
            /// wrapper for the inner type.
            pub fn validate_prefix(buf: &[u8]) -> $crate::TpmResult<usize>
            where
                $inner_ty: for<'a> $crate::TpmField<'a>,
            {
                let (size_field, payload) = <$crate::basic::TpmUint16 as $crate::TpmCast>::cast_prefix(buf)?;
                let payload_len = size_field.get() as usize;

                if payload.len() < payload_len {
                    return Err($crate::TpmError::UnexpectedEnd { offset: $crate::tpm_offset(buf, payload), needed: payload_len, available: payload.len() });
                }

                let (inner_bytes, _) = payload.split_at(payload_len);
                let (_, tail) = <$inner_ty as $crate::TpmField>::cast_prefix_field(inner_bytes)?;

                if !tail.is_empty() {
                    return Err($crate::TpmError::TrailingData { offset: $crate::tpm_offset(buf, tail), actual: tail.len() });
                }

                Ok(<$crate::basic::TpmUint16 as $crate::TpmSized>::SIZE + payload_len)
            }
        }

        impl AsRef<[u8]> for $wire_ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl<'a> $crate::TpmField<'a> for $wrapper_ty
        where
            $inner_ty: for<'b> $crate::TpmField<'b>,
        {
            type View = &'a $wire_ty;

            fn cast_prefix_field(buf: &'a [u8]) -> $crate::TpmResult<(Self::View, &'a [u8])> {
                $wire_ty::cast_prefix(buf)
            }
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
                    .map_err(|_| $crate::TpmError::IntegerTooLarge { offset: writer.len(), value: $crate::tpm_value(inner_len) })?;
                len_field.marshal(writer)?;
                $crate::TpmMarshal::marshal(&self.inner, writer)
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
