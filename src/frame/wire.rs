// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

use super::{TPM_DISPATCH_TABLE, TPM_HEADER_SIZE};
use crate::{
    data::{TpmCc, TpmRc, TpmSt},
    TpmCast, TpmCastMut, TpmProtocolError, TpmResult,
};
use core::mem::size_of;

const HEADER_SIZE: usize = TPM_HEADER_SIZE as usize;
const TAG_OFFSET: usize = 0;
const SIZE_OFFSET: usize = 2;
const CODE_OFFSET: usize = 6;

/// A zero-copy TPM command wire view over caller-owned bytes.
#[repr(transparent)]
pub struct TpmCommand([u8]);

impl TpmCommand {
    /// Casts a byte slice into a TPM command wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the command frame bounds and
        // dispatch invariants required for this transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts a byte slice into a TPM command wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` contains exactly one complete TPM
    /// command frame with a valid command code and handle area layout.
    #[must_use]
    pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        let ptr = core::ptr::from_ref(buf) as *const Self;

        // SAFETY: `TpmCommand` is `repr(transparent)` over `[u8]`, so it has
        // the same layout, metadata, and alignment as the referenced slice.
        unsafe { &*ptr }
    }

    /// Casts a mutable byte slice into a mutable TPM command wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the command frame bounds and
        // dispatch invariants required for this transparent wire view. The
        // `&mut` input provides exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts a mutable byte slice into a mutable TPM command wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` contains exactly one complete TPM
    /// command frame with a valid command code and handle area layout. The
    /// returned reference inherits the exclusive access represented by `buf`.
    #[must_use]
    pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        let ptr = core::ptr::from_mut(buf) as *mut Self;

        // SAFETY: `TpmCommand` is `repr(transparent)` over `[u8]`, so it has
        // the same layout, metadata, and alignment as the referenced slice.
        unsafe { &mut *ptr }
    }

    /// Returns the complete command frame bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the mutable command frame bytes.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the command tag.
    ///
    /// # Errors
    ///
    /// Returns [`VariantNotAvailable`](crate::TpmProtocolError::VariantNotAvailable)
    /// when the tag value is not defined.
    pub fn tag(&self) -> TpmResult<TpmSt> {
        TpmSt::try_from(read_u16(&self.0, TAG_OFFSET))
    }

    /// Returns the command frame size field.
    #[must_use]
    pub fn size(&self) -> u32 {
        read_u32(&self.0, SIZE_OFFSET)
    }

    /// Returns the command code.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCc`](crate::TpmProtocolError::InvalidCc) when the
    /// command code has no dispatch entry.
    pub fn cc(&self) -> TpmResult<TpmCc> {
        command_code(&self.0)
    }

    /// Returns the command handle area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn handles(&self) -> TpmResult<&[u8]> {
        let dispatch = dispatch_for(self.cc()?)?;
        let handle_area_size = dispatch.handles * size_of::<u32>();

        Ok(&self.0[HEADER_SIZE..HEADER_SIZE + handle_area_size])
    }

    /// Returns the command authorization area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command has no sessions or its
    /// authorization area is malformed.
    pub fn auth_area(&self) -> TpmResult<&[u8]> {
        let (auth_area, _) = self.session_and_parameter_areas()?;
        Ok(auth_area)
    }

    /// Returns the command parameter area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn parameters(&self) -> TpmResult<&[u8]> {
        let (_, parameters) = self.session_and_parameter_areas()?;
        Ok(parameters)
    }

    /// Returns `true` when the command frame contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the command frame length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    fn session_and_parameter_areas(&self) -> TpmResult<(&[u8], &[u8])> {
        let dispatch = dispatch_for(self.cc()?)?;
        let tag = self.tag()?;
        let handle_area_size = dispatch.handles * size_of::<u32>();
        let after_handles = &self.0[HEADER_SIZE + handle_area_size..];

        if tag != TpmSt::Sessions {
            return Ok((&[], after_handles));
        }

        if after_handles.len() < size_of::<u32>() {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        let auth_size = read_u32(after_handles, 0) as usize;
        let auth_start = size_of::<u32>();
        let auth_end = auth_start
            .checked_add(auth_size)
            .ok_or(TpmProtocolError::IntegerTooLarge)?;

        if after_handles.len() < auth_end {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        Ok((&after_handles[auth_start..auth_end], &after_handles[auth_end..]))
    }

    fn validate_envelope(buf: &[u8]) -> TpmResult<()> {
        validate_frame_size(buf)?;

        let tag = TpmSt::try_from(read_u16(buf, TAG_OFFSET))?;
        if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
            return Err(TpmProtocolError::InvalidTag);
        }

        let dispatch = dispatch_for(command_code(buf)?)?;
        let body = &buf[HEADER_SIZE..];
        let handle_area_size = dispatch.handles * size_of::<u32>();

        if body.len() < handle_area_size {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        if tag == TpmSt::Sessions {
            let after_handles = &body[handle_area_size..];
            if after_handles.len() < size_of::<u32>() {
                return Err(TpmProtocolError::UnexpectedEnd);
            }

            let auth_size = read_u32(after_handles, 0) as usize;
            let auth_end = size_of::<u32>()
                .checked_add(auth_size)
                .ok_or(TpmProtocolError::IntegerTooLarge)?;

            if after_handles.len() < auth_end {
                return Err(TpmProtocolError::UnexpectedEnd);
            }
        }

        Ok(())
    }
}

impl TpmCast for TpmCommand {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `TpmCommand`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl TpmCastMut for TpmCommand {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmCommand`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl AsRef<[u8]> for TpmCommand {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for TpmCommand {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

/// A zero-copy TPM response wire view over caller-owned bytes.
#[repr(transparent)]
pub struct TpmResponse([u8]);

impl TpmResponse {
    /// Casts a byte slice into a TPM response wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the response envelope is malformed.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the response frame bounds
        // required for this transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts a byte slice into a TPM response wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` contains exactly one complete TPM
    /// response frame.
    #[must_use]
    pub unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        let ptr = core::ptr::from_ref(buf) as *const Self;

        // SAFETY: `TpmResponse` is `repr(transparent)` over `[u8]`, so it has
        // the same layout, metadata, and alignment as the referenced slice.
        unsafe { &*ptr }
    }

    /// Casts a mutable byte slice into a mutable TPM response wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the response envelope is malformed.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the response frame bounds
        // required for this transparent wire view. The `&mut` input provides
        // exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts a mutable byte slice into a mutable TPM response wire view without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `buf` contains exactly one complete TPM
    /// response frame. The returned reference inherits the exclusive access
    /// represented by `buf`.
    #[must_use]
    pub unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        let ptr = core::ptr::from_mut(buf) as *mut Self;

        // SAFETY: `TpmResponse` is `repr(transparent)` over `[u8]`, so it has
        // the same layout, metadata, and alignment as the referenced slice.
        unsafe { &mut *ptr }
    }

    /// Returns the complete response frame bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the mutable response frame bytes.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the response tag.
    ///
    /// # Errors
    ///
    /// Returns [`VariantNotAvailable`](crate::TpmProtocolError::VariantNotAvailable)
    /// when the tag value is not defined.
    pub fn tag(&self) -> TpmResult<TpmSt> {
        TpmSt::try_from(read_u16(&self.0, TAG_OFFSET))
    }

    /// Returns the response frame size field.
    #[must_use]
    pub fn size(&self) -> u32 {
        read_u32(&self.0, SIZE_OFFSET)
    }

    /// Returns the response code.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the response code is malformed.
    pub fn rc(&self) -> TpmResult<TpmRc> {
        TpmRc::try_from(read_u32(&self.0, CODE_OFFSET))
    }

    /// Returns the response body bytes after the TPM header.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.0[HEADER_SIZE..]
    }

    /// Returns `true` when the response frame contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the response frame length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    fn validate_envelope(buf: &[u8]) -> TpmResult<()> {
        validate_frame_size(buf)?;
        let _ = TpmSt::try_from(read_u16(buf, TAG_OFFSET))?;
        let _ = TpmRc::try_from(read_u32(buf, CODE_OFFSET))?;

        Ok(())
    }
}

impl TpmCast for TpmResponse {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    unsafe fn cast_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: The caller upholds the unchecked cast contract for `TpmResponse`.
        unsafe { Self::cast_unchecked(buf) }
    }
}

impl TpmCastMut for TpmResponse {
    fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::cast_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmResponse`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

impl AsRef<[u8]> for TpmResponse {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for TpmResponse {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

fn command_code(buf: &[u8]) -> TpmResult<TpmCc> {
    TpmCc::try_from(read_u32(buf, CODE_OFFSET)).map_err(|_| TpmProtocolError::InvalidCc)
}

fn dispatch_for(cc: TpmCc) -> TpmResult<&'static super::TpmDispatch> {
    TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| TpmProtocolError::InvalidCc)
}

fn validate_frame_size(buf: &[u8]) -> TpmResult<()> {
    if buf.len() < HEADER_SIZE {
        return Err(TpmProtocolError::UnexpectedEnd);
    }

    let size = read_u32(buf, SIZE_OFFSET) as usize;
    if buf.len() < size {
        return Err(TpmProtocolError::UnexpectedEnd);
    }

    if buf.len() > size {
        return Err(TpmProtocolError::TrailingData);
    }

    Ok(())
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}
