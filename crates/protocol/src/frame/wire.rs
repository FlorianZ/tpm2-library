// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

use super::{TPM_DISPATCH_TABLE, TPM_HEADER_SIZE};
use crate::{
    TpmCast, TpmCastMut, TpmError, TpmResult, TpmUnmarshal,
    basic::TpmUint32,
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
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the command frame bounds and
        // dispatch invariants required for this transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts the first TPM command frame in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed or
    /// incomplete.
    pub fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        let frame_len = frame_prefix_size(buf)?;
        let (frame, tail) = buf.split_at(frame_len);

        Self::validate_envelope(frame)?;

        // SAFETY: `validate_envelope` checked the complete command frame.
        Ok((unsafe { Self::cast_unchecked(frame) }, tail))
    }

    /// Casts a mutable byte slice into a mutable TPM command wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the command frame bounds and
        // dispatch invariants required for this transparent wire view. The
        // `&mut` input provides exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts the first mutable TPM command frame in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed or
    /// incomplete.
    pub fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        let frame_len = frame_prefix_size(buf)?;
        let (frame, tail) = buf.split_at_mut(frame_len);

        Self::validate_envelope(frame)?;

        // SAFETY: `validate_envelope` checked the complete command frame.
        Ok((unsafe { Self::cast_mut_unchecked(frame) }, tail))
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
    /// Returns [`InvalidTag`](crate::TpmError::InvalidTag)
    /// when the tag value is not defined.
    pub fn tag(&self) -> TpmResult<TpmSt> {
        let raw = read_u16(&self.0, TAG_OFFSET);

        TpmSt::try_from(raw).map_err(|_| TpmError::InvalidTag {
            offset: TAG_OFFSET,
            value: u64::from(raw),
        })
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
    /// Returns [`InvalidCc`](crate::TpmError::InvalidCc) when the
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
    /// Returns [`InvalidCc`](crate::TpmError::InvalidCc) when the
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
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn handles(&self) -> TpmResult<&[u8]> {
        let range = self.handle_area_range()?;

        Ok(&self.0[range])
    }

    /// Returns the mutable command handle area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn handles_mut(&mut self) -> TpmResult<&mut [u8]> {
        let range = self.handle_area_range()?;

        Ok(&mut self.0[range])
    }

    /// Returns the command authorization area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command has no sessions or its
    /// authorization area is malformed.
    pub fn auth_area(&self) -> TpmResult<&[u8]> {
        let (auth_area, _) = self.session_and_parameter_ranges()?;

        Ok(&self.0[auth_area])
    }

    /// Returns the mutable command authorization area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command has no sessions or its
    /// authorization area is malformed.
    pub fn auth_area_mut(&mut self) -> TpmResult<&mut [u8]> {
        let (auth_area, _) = self.session_and_parameter_ranges()?;

        Ok(&mut self.0[auth_area])
    }

    /// Returns the command parameter area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn parameters(&self) -> TpmResult<&[u8]> {
        let (_, parameters) = self.session_and_parameter_ranges()?;

        Ok(&self.0[parameters])
    }

    /// Returns the mutable command parameter area bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command envelope is malformed.
    pub fn parameters_mut(&mut self) -> TpmResult<&mut [u8]> {
        let (_, parameters) = self.session_and_parameter_ranges()?;

        Ok(&mut self.0[parameters])
    }

    /// Reconstructs an owned command body from this frame.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the frame is malformed or does not match `R`.
    pub fn unmarshal<R: super::TpmUnmarshalBody>(&self) -> TpmResult<R> {
        self.validate()?;
        let cc = self.cc()?;
        if cc != R::CC {
            return Err(TpmError::InvalidCc {
                offset: CODE_OFFSET,
                value: u64::from(cc.value()),
            });
        }

        R::unmarshal_body(self.handles()?, self.parameters()?)
    }

    /// Validates command frame structure without constructing an owned command body.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the command frame is malformed.
    pub fn validate(&self) -> TpmResult<()> {
        Self::validate_envelope(&self.0)?;
        let auth_area = self.auth_area()?;

        validate_auth_commands(&self.0, auth_area)
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
        let handle_area_size = handle_area_size(dispatch.handles, HEADER_SIZE)?;
        let handle_area_end =
            HEADER_SIZE
                .checked_add(handle_area_size)
                .ok_or(TpmError::IntegerTooLarge {
                    offset: HEADER_SIZE,
                    value: crate::tpm_value(handle_area_size),
                })?;

        if self.0.len() < handle_area_end {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE,
                needed: handle_area_size,
                available: self.0.len().saturating_sub(HEADER_SIZE),
            });
        }

        Ok(HEADER_SIZE..handle_area_end)
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
            return Err(TpmError::UnexpectedEnd {
                offset: after_handles_start,
                needed: size_of::<u32>(),
                available: after_handles.len(),
            });
        }

        let auth_size = read_u32(after_handles, 0) as usize;
        let auth_start = size_of::<u32>();
        let auth_end = auth_start
            .checked_add(auth_size)
            .ok_or(TpmError::IntegerTooLarge {
                offset: after_handles_start,
                value: crate::tpm_value(auth_size),
            })?;

        if after_handles.len() < auth_end {
            return Err(TpmError::UnexpectedEnd {
                offset: after_handles_start + auth_start,
                needed: auth_size,
                available: after_handles.len().saturating_sub(auth_start),
            });
        }

        let auth_start = after_handles_start + auth_start;
        let auth_end = after_handles_start + auth_end;

        Ok((auth_start..auth_end, auth_end..self.0.len()))
    }

    fn validate_envelope(buf: &[u8]) -> TpmResult<()> {
        validate_frame_size(buf)?;

        let raw_tag = read_u16(buf, TAG_OFFSET);
        let tag = TpmSt::try_from(raw_tag).map_err(|_| TpmError::InvalidTag {
            offset: TAG_OFFSET,
            value: u64::from(raw_tag),
        })?;
        if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
            return Err(TpmError::InvalidTag {
                offset: TAG_OFFSET,
                value: u64::from(raw_tag),
            });
        }

        let dispatch = dispatch_for(command_code(buf)?)?;
        let body = &buf[HEADER_SIZE..];
        let handle_area_size = handle_area_size(dispatch.handles, HEADER_SIZE)?;

        if body.len() < handle_area_size {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE,
                needed: handle_area_size,
                available: body.len(),
            });
        }

        if tag == TpmSt::Sessions {
            let after_handles = &body[handle_area_size..];
            if after_handles.len() < size_of::<u32>() {
                return Err(TpmError::UnexpectedEnd {
                    offset: HEADER_SIZE + handle_area_size,
                    needed: size_of::<u32>(),
                    available: after_handles.len(),
                });
            }

            let auth_size = read_u32(after_handles, 0) as usize;
            let auth_end =
                size_of::<u32>()
                    .checked_add(auth_size)
                    .ok_or(TpmError::IntegerTooLarge {
                        offset: HEADER_SIZE + handle_area_size,
                        value: crate::tpm_value(auth_size),
                    })?;

            if after_handles.len() < auth_end {
                return Err(TpmError::UnexpectedEnd {
                    offset: HEADER_SIZE + handle_area_size + size_of::<u32>(),
                    needed: auth_size,
                    available: after_handles.len().saturating_sub(size_of::<u32>()),
                });
            }
        }

        Ok(())
    }
}

impl TpmCast for TpmCommand {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::cast_prefix(buf)
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

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::cast_prefix_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmCommand`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

crate::tpm_byte_view!(TpmCommand);

/// A zero-copy TPM response wire view over caller-owned bytes.
#[repr(transparent)]
pub struct TpmResponse([u8]);

impl TpmResponse {
    /// Casts a byte slice into a TPM response wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the response envelope is malformed.
    pub fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the response frame bounds
        // required for this transparent wire view.
        Ok(unsafe { Self::cast_unchecked(buf) })
    }

    /// Casts the first TPM response frame in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the response envelope is malformed or
    /// incomplete.
    pub fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        let frame_len = frame_prefix_size(buf)?;
        let (frame, tail) = buf.split_at(frame_len);

        Self::validate_envelope(frame)?;

        // SAFETY: `validate_envelope` checked the complete response frame.
        Ok((unsafe { Self::cast_unchecked(frame) }, tail))
    }

    /// Casts a mutable byte slice into a mutable TPM response wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the response envelope is malformed.
    pub fn cast_mut(buf: &mut [u8]) -> TpmResult<&mut Self> {
        Self::validate_envelope(buf)?;

        // SAFETY: `validate_envelope` checked the response frame bounds
        // required for this transparent wire view. The `&mut` input provides
        // exclusive access.
        Ok(unsafe { Self::cast_mut_unchecked(buf) })
    }

    /// Casts the first mutable TPM response frame in a byte slice into a wire view.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the response envelope is malformed or
    /// incomplete.
    pub fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        let frame_len = frame_prefix_size(buf)?;
        let (frame, tail) = buf.split_at_mut(frame_len);

        Self::validate_envelope(frame)?;

        // SAFETY: `validate_envelope` checked the complete response frame.
        Ok((unsafe { Self::cast_mut_unchecked(frame) }, tail))
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
    /// Returns [`InvalidTag`](crate::TpmError::InvalidTag)
    /// when the tag value is not defined.
    pub fn tag(&self) -> TpmResult<TpmSt> {
        let raw = read_u16(&self.0, TAG_OFFSET);

        TpmSt::try_from(raw).map_err(|_| TpmError::InvalidTag {
            offset: TAG_OFFSET,
            value: u64::from(raw),
        })
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
    /// Returns `Err(TpmError)` when the response code is malformed.
    pub fn rc(&self) -> TpmResult<TpmRc> {
        let raw = read_u32(&self.0, CODE_OFFSET);

        TpmRc::try_from(raw).map_err(|_| TpmError::InvalidRc {
            offset: CODE_OFFSET,
            value: u64::from(raw),
        })
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
    /// Returns `Err(TpmError)` when the response frame is malformed or
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

        let handle_area_size = handle_area_size(dispatch.response_handles, HEADER_SIZE)?;
        let body = self.body();
        if body.len() < handle_area_size {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE,
                needed: handle_area_size,
                available: body.len(),
            });
        }

        let after_handles = &body[handle_area_size..];
        if after_handles.len() < size_of::<u32>() {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE + handle_area_size,
                needed: size_of::<u32>(),
                available: after_handles.len(),
            });
        }

        let params_len = read_u32(after_handles, 0) as usize;
        let sessions_start =
            size_of::<u32>()
                .checked_add(params_len)
                .ok_or(TpmError::IntegerTooLarge {
                    offset: HEADER_SIZE + handle_area_size,
                    value: crate::tpm_value(params_len),
                })?;

        if after_handles.len() < sessions_start {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE + handle_area_size + size_of::<u32>(),
                needed: params_len,
                available: after_handles.len().saturating_sub(size_of::<u32>()),
            });
        }

        validate_auth_responses(&self.0, &after_handles[sessions_start..])
    }

    /// Reconstructs an owned response body from this frame.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmError)` when the frame is malformed or does not match `R`.
    pub fn unmarshal<R: super::TpmUnmarshalBody>(&self) -> TpmResult<R> {
        self.validate(R::CC)?;
        let (handles, parameters) = self.body_parts::<R>()?;
        R::unmarshal_body(handles, parameters)
    }

    fn body_parts<R: super::TpmHeader>(&self) -> TpmResult<(&[u8], &[u8])> {
        let handle_area_size = handle_area_size(R::HANDLES, HEADER_SIZE)?;
        let body = self.body();
        if body.len() < handle_area_size {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE,
                needed: handle_area_size,
                available: body.len(),
            });
        }

        let (handles, after_handles) = body.split_at(handle_area_size);
        if self.tag()? != TpmSt::Sessions {
            return Ok((handles, after_handles));
        }

        let (parameter_size, after_size) = TpmUint32::unmarshal(after_handles)?;
        let parameter_size =
            usize::try_from(parameter_size.value()).map_err(|_| TpmError::IntegerTooLarge {
                offset: HEADER_SIZE + handle_area_size,
                value: u64::from(parameter_size.value()),
            })?;
        if after_size.len() < parameter_size {
            return Err(TpmError::UnexpectedEnd {
                offset: HEADER_SIZE + handle_area_size + size_of::<u32>(),
                needed: parameter_size,
                available: after_size.len(),
            });
        }

        Ok((handles, &after_size[..parameter_size]))
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
        let raw_tag = read_u16(buf, TAG_OFFSET);
        let _ = TpmSt::try_from(raw_tag).map_err(|_| TpmError::InvalidTag {
            offset: TAG_OFFSET,
            value: u64::from(raw_tag),
        })?;
        let raw_rc = read_u32(buf, CODE_OFFSET);
        let _ = TpmRc::try_from(raw_rc).map_err(|_| TpmError::InvalidRc {
            offset: CODE_OFFSET,
            value: u64::from(raw_rc),
        })?;

        Ok(())
    }
}

impl TpmCast for TpmResponse {
    fn cast(buf: &[u8]) -> TpmResult<&Self> {
        Self::cast(buf)
    }

    fn cast_prefix(buf: &[u8]) -> TpmResult<(&Self, &[u8])> {
        Self::cast_prefix(buf)
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

    fn cast_prefix_mut(buf: &mut [u8]) -> TpmResult<(&mut Self, &mut [u8])> {
        Self::cast_prefix_mut(buf)
    }

    unsafe fn cast_mut_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: The caller upholds the unchecked mutable cast contract for
        // `TpmResponse`.
        unsafe { Self::cast_mut_unchecked(buf) }
    }
}

crate::tpm_byte_view!(TpmResponse);

fn command_code(buf: &[u8]) -> TpmResult<TpmCc> {
    let raw = read_u32(buf, CODE_OFFSET);

    TpmCc::try_from(raw).map_err(|_| TpmError::InvalidCc {
        offset: CODE_OFFSET,
        value: u64::from(raw),
    })
}

fn dispatch_for(cc: TpmCc) -> TpmResult<&'static super::TpmDispatch> {
    TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| TpmError::InvalidCc {
            offset: 0,
            value: u64::from(cc.value()),
        })
}

fn validate_frame_size(buf: &[u8]) -> TpmResult<()> {
    let size = frame_prefix_size(buf)?;

    if buf.len() > size {
        return Err(TpmError::TrailingData {
            offset: size,
            actual: buf.len() - size,
        });
    }

    Ok(())
}

fn handle_area_size(handles: usize, offset: usize) -> TpmResult<usize> {
    handles
        .checked_mul(size_of::<u32>())
        .ok_or(TpmError::IntegerTooLarge {
            offset,
            value: crate::tpm_value(handles),
        })
}

fn frame_prefix_size(buf: &[u8]) -> TpmResult<usize> {
    if buf.len() < HEADER_SIZE {
        return Err(TpmError::UnexpectedEnd {
            offset: 0,
            needed: HEADER_SIZE,
            available: buf.len(),
        });
    }

    let size = read_u32(buf, SIZE_OFFSET) as usize;
    if buf.len() < size {
        return Err(TpmError::UnexpectedEnd {
            offset: buf.len(),
            needed: size - buf.len(),
            available: 0,
        });
    }

    Ok(size)
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

fn validate_auth_commands(base: &[u8], mut buf: &[u8]) -> TpmResult<()> {
    let mut count = 0;

    while !buf.is_empty() {
        if count >= MAX_SESSIONS {
            return Err(TpmError::TooManyItems {
                offset: crate::tpm_offset(base, buf),
                limit: MAX_SESSIONS,
                actual: count + 1,
            });
        }

        if buf.len() < size_of::<u32>() {
            return Err(TpmError::UnexpectedEnd {
                offset: crate::tpm_offset(base, buf),
                needed: size_of::<u32>(),
                available: buf.len(),
            });
        }

        buf = &buf[size_of::<u32>()..];
        buf = skip_tpm2b(base, buf)?;

        if buf.is_empty() {
            return Err(TpmError::UnexpectedEnd {
                offset: crate::tpm_offset(base, buf),
                needed: 1,
                available: 0,
            });
        }

        buf = &buf[1..];
        buf = skip_tpm2b(base, buf)?;
        count += 1;
    }

    Ok(())
}

fn validate_auth_responses(base: &[u8], mut buf: &[u8]) -> TpmResult<()> {
    let mut count = 0;

    while !buf.is_empty() {
        if count >= MAX_SESSIONS {
            return Err(TpmError::TooManyItems {
                offset: crate::tpm_offset(base, buf),
                limit: MAX_SESSIONS,
                actual: count + 1,
            });
        }

        buf = skip_tpm2b(base, buf)?;

        if buf.is_empty() {
            return Err(TpmError::UnexpectedEnd {
                offset: crate::tpm_offset(base, buf),
                needed: 1,
                available: 0,
            });
        }

        buf = &buf[1..];
        buf = skip_tpm2b(base, buf)?;
        count += 1;
    }

    Ok(())
}

fn skip_tpm2b<'a>(base: &[u8], buf: &'a [u8]) -> TpmResult<&'a [u8]> {
    if buf.len() < size_of::<u16>() {
        return Err(TpmError::UnexpectedEnd {
            offset: crate::tpm_offset(base, buf),
            needed: size_of::<u16>(),
            available: buf.len(),
        });
    }

    let size = read_u16(buf, 0) as usize;
    let end = size_of::<u16>()
        .checked_add(size)
        .ok_or(TpmError::IntegerTooLarge {
            offset: crate::tpm_offset(base, buf),
            value: crate::tpm_value(size),
        })?;

    if buf.len() < end {
        return Err(TpmError::UnexpectedEnd {
            offset: crate::tpm_offset(base, buf),
            needed: end,
            available: buf.len(),
        });
    }

    Ok(&buf[end..])
}
