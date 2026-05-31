// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

use super::{TPM_DISPATCH_TABLE, TPM_HEADER_SIZE};
use crate::{
    TpmCast, TpmCastMut, TpmProtocolError, TpmResult,
    constant::MAX_SESSIONS,
    data::{TpmCc, TpmRc, TpmRcBase, TpmSt},
};
use core::{mem::size_of, ops::Range};

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

    /// Sets the command tag without changing the frame shape.
    pub fn set_tag(&mut self, tag: TpmSt) {
        write_u16(&mut self.0, TAG_OFFSET, tag.value());
    }

    /// Sets the command code without changing the frame shape.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCc`](crate::TpmProtocolError::InvalidCc) when the
    /// command code has no dispatch entry.
    pub fn set_cc(&mut self, cc: TpmCc) -> TpmResult<()> {
        let _ = dispatch_for(cc)?;

        write_u32(&mut self.0, CODE_OFFSET, cc.value());
        Ok(())
    }

    /// Returns the command handle area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn handles(&self) -> TpmResult<&[u8]> {
        let range = self.handle_area_range()?;

        Ok(&self.0[range])
    }

    /// Returns the mutable command handle area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn handles_mut(&mut self) -> TpmResult<&mut [u8]> {
        let range = self.handle_area_range()?;

        Ok(&mut self.0[range])
    }

    /// Returns the command authorization area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command has no sessions or its
    /// authorization area is malformed.
    pub fn auth_area(&self) -> TpmResult<&[u8]> {
        let (auth_area, _) = self.session_and_parameter_ranges()?;

        Ok(&self.0[auth_area])
    }

    /// Returns the mutable command authorization area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command has no sessions or its
    /// authorization area is malformed.
    pub fn auth_area_mut(&mut self) -> TpmResult<&mut [u8]> {
        let (auth_area, _) = self.session_and_parameter_ranges()?;

        Ok(&mut self.0[auth_area])
    }

    /// Returns the command parameter area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn parameters(&self) -> TpmResult<&[u8]> {
        let (_, parameters) = self.session_and_parameter_ranges()?;

        Ok(&self.0[parameters])
    }

    /// Returns the mutable command parameter area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command envelope is malformed.
    pub fn parameters_mut(&mut self) -> TpmResult<&mut [u8]> {
        let (_, parameters) = self.session_and_parameter_ranges()?;

        Ok(&mut self.0[parameters])
    }

    /// Validates command frame structure without constructing an owned command body.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the command frame is malformed.
    pub fn validate(&self) -> TpmResult<()> {
        Self::validate_envelope(&self.0)?;
        validate_auth_commands(self.auth_area()?)
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

    fn handle_area_range(&self) -> TpmResult<Range<usize>> {
        let dispatch = dispatch_for(self.cc()?)?;
        let handle_area_size = dispatch.handles * size_of::<u32>();

        Ok(HEADER_SIZE..HEADER_SIZE + handle_area_size)
    }

    fn session_and_parameter_ranges(&self) -> TpmResult<(Range<usize>, Range<usize>)> {
        let handle_area = self.handle_area_range()?;
        let tag = self.tag()?;
        let after_handles_start = handle_area.end;

        if tag != TpmSt::Sessions {
            return Ok((
                after_handles_start..after_handles_start,
                after_handles_start..self.0.len(),
            ));
        }

        let after_handles = &self.0[after_handles_start..];

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

        let auth_start = after_handles_start + auth_start;
        let auth_end = after_handles_start + auth_end;

        Ok((auth_start..auth_end, auth_end..self.0.len()))
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

    /// Sets the response tag without changing the frame shape.
    pub fn set_tag(&mut self, tag: TpmSt) {
        write_u16(&mut self.0, TAG_OFFSET, tag.value());
    }

    /// Sets the response code without changing the frame shape.
    pub fn set_rc(&mut self, rc: TpmRc) {
        write_u32(&mut self.0, CODE_OFFSET, rc.value());
    }

    /// Returns the response body bytes after the TPM header.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.0[HEADER_SIZE..]
    }

    /// Returns the mutable response body bytes after the TPM header.
    #[must_use]
    pub fn body_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_SIZE..]
    }

    /// Validates response frame structure without constructing an owned response body.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmProtocolError)` when the response frame is malformed or
    /// `cc` has no dispatch entry.
    pub fn validate(&self, cc: TpmCc) -> TpmResult<()> {
        Self::validate_envelope(&self.0)?;
        let dispatch = dispatch_for(cc)?;

        if !matches!(self.rc()?, TpmRc::Fmt0(TpmRcBase::Success)) {
            return Ok(());
        }

        if self.tag()? != TpmSt::Sessions {
            return Ok(());
        }

        let handle_area_size = dispatch.response_handles * size_of::<u32>();
        let body = self.body();
        if body.len() < handle_area_size {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        let after_handles = &body[handle_area_size..];
        if after_handles.len() < size_of::<u32>() {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        let params_len = read_u32(after_handles, 0) as usize;
        let sessions_start = size_of::<u32>()
            .checked_add(params_len)
            .ok_or(TpmProtocolError::IntegerTooLarge)?;

        if after_handles.len() < sessions_start {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        validate_auth_responses(&after_handles[sessions_start..])
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

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_be_bytes());
}

fn validate_auth_commands(mut buf: &[u8]) -> TpmResult<()> {
    let mut count = 0;

    while !buf.is_empty() {
        if count >= MAX_SESSIONS {
            return Err(TpmProtocolError::TooManyItems);
        }

        if buf.len() < size_of::<u32>() {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        buf = &buf[size_of::<u32>()..];
        buf = skip_tpm2b(buf)?;

        if buf.is_empty() {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        buf = &buf[1..];
        buf = skip_tpm2b(buf)?;
        count += 1;
    }

    Ok(())
}

fn validate_auth_responses(mut buf: &[u8]) -> TpmResult<()> {
    let mut count = 0;

    while !buf.is_empty() {
        if count >= MAX_SESSIONS {
            return Err(TpmProtocolError::TooManyItems);
        }

        buf = skip_tpm2b(buf)?;

        if buf.is_empty() {
            return Err(TpmProtocolError::UnexpectedEnd);
        }

        buf = &buf[1..];
        buf = skip_tpm2b(buf)?;
        count += 1;
    }

    Ok(())
}

fn skip_tpm2b(buf: &[u8]) -> TpmResult<&[u8]> {
    if buf.len() < size_of::<u16>() {
        return Err(TpmProtocolError::UnexpectedEnd);
    }

    let size = read_u16(buf, 0) as usize;
    let end = size_of::<u16>()
        .checked_add(size)
        .ok_or(TpmProtocolError::IntegerTooLarge)?;

    if buf.len() < end {
        return Err(TpmProtocolError::UnexpectedEnd);
    }

    Ok(&buf[end..])
}
