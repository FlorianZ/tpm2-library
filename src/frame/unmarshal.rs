// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    TPM_DISPATCH_TABLE, TPM_HEADER_SIZE, TpmAuthCommands, TpmAuthResponses, TpmCommandValue,
    TpmHandles, TpmResponseValue,
};
use crate::{
    TpmError, TpmResult, TpmUnmarshal,
    basic::TpmUint32,
    data::{TpmCc, TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
};
use core::mem::size_of;

const HEADER_SIZE: usize = TPM_HEADER_SIZE as usize;
const TAG_OFFSET: usize = 0;
const SIZE_OFFSET: usize = 2;
const CODE_OFFSET: usize = 6;

/// A unified struct holding all dispatch info for a given Command Code.
#[doc(hidden)]
pub struct TpmDispatch {
    pub cc: TpmCc,
    pub handles: usize,
    pub response_handles: usize,
    #[allow(clippy::type_complexity)]
    pub command_unmarshaler:
        for<'a> fn(&'a [u8], &'a [u8]) -> TpmResult<(TpmCommandValue, &'a [u8])>,
    #[allow(clippy::type_complexity)]
    pub response_unmarshaler:
        for<'a> fn(TpmSt, &'a [u8]) -> TpmResult<(TpmResponseValue, &'a [u8])>,
}

/// Represents the dualistic nature of responses.
pub type TpmResponseValueResult = Result<(TpmResponseValue, TpmAuthResponses), TpmRc>;

/// Unmarshals a TPM command.
///
/// # Errors
///
/// Returns [`InvalidCc`](crate::TpmError::InvalidCc) when the command code is
/// non-existent.
/// Returns [`TrailingData`](crate::TpmError::TrailingData) when after
/// unmarshaling there is some data left.
/// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when the
/// buffer does not hold all the bytes.
pub fn tpm_unmarshal_command(
    buf: &[u8],
) -> TpmResult<(TpmHandles, TpmCommandValue, TpmAuthCommands)> {
    if buf.len() < HEADER_SIZE {
        return Err(TpmError::UnexpectedEnd(
            crate::TpmErrorValue::new(0).size(HEADER_SIZE, buf.len()),
        ));
    }
    let buf_len = buf.len();

    let raw_tag = read_u16(buf, TAG_OFFSET);
    let tag = TpmSt::try_from(raw_tag).map_err(|_| {
        TpmError::InvalidTag(crate::TpmErrorValue::new(TAG_OFFSET).value(u64::from(raw_tag)))
    })?;
    let size_usize = read_u32(buf, SIZE_OFFSET) as usize;
    let raw_cc = read_u32(buf, CODE_OFFSET);
    let cc = TpmCc::try_from(raw_cc).map_err(|_| {
        TpmError::InvalidCc(crate::TpmErrorValue::new(CODE_OFFSET).value(u64::from(raw_cc)))
    })?;
    let body_buf = &buf[HEADER_SIZE..];

    if buf_len < size_usize {
        return Err(TpmError::UnexpectedEnd(
            crate::TpmErrorValue::new(buf_len).size(size_usize - buf_len, 0),
        ));
    } else if buf_len > size_usize {
        return Err(TpmError::TrailingData(
            crate::TpmErrorValue::new(size_usize).actual(buf_len - size_usize),
        ));
    }

    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| {
            TpmError::InvalidCc(crate::TpmErrorValue::new(CODE_OFFSET).value(u64::from(cc.value())))
        })?;

    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmError::InvalidTag(
            crate::TpmErrorValue::new(TAG_OFFSET).value(u64::from(raw_tag)),
        ));
    }

    let handle_area_size = dispatch.handles * size_of::<u32>();
    if body_buf.len() < handle_area_size {
        return Err(TpmError::UnexpectedEnd(
            crate::TpmErrorValue::new(HEADER_SIZE).size(handle_area_size, body_buf.len()),
        ));
    }
    let (handle_area, after_handles) = body_buf.split_at(handle_area_size);

    let mut sessions = TpmAuthCommands::new();
    let param_area = if tag == TpmSt::Sessions {
        let (auth_area_size, buf_after_auth_size) = TpmUint32::unmarshal(after_handles)?;
        let auth_area_size = u32::from(auth_area_size) as usize;
        if buf_after_auth_size.len() < auth_area_size {
            return Err(TpmError::UnexpectedEnd(
                crate::TpmErrorValue::new(HEADER_SIZE + handle_area_size + size_of::<TpmUint32>())
                    .size(auth_area_size, buf_after_auth_size.len()),
            ));
        }
        let (mut auth_area, param_area) = buf_after_auth_size.split_at(auth_area_size);
        while !auth_area.is_empty() {
            let (session, rest) = TpmsAuthCommand::unmarshal(auth_area)?;
            sessions.try_push(session)?;
            auth_area = rest;
        }
        if !auth_area.is_empty() {
            return Err(TpmError::TrailingData(
                crate::TpmErrorValue::at(buf, auth_area).actual(auth_area.len()),
            ));
        }
        param_area
    } else {
        after_handles
    };

    let (command_data, param_remainder) = (dispatch.command_unmarshaler)(handle_area, param_area)?;

    if !param_remainder.is_empty() {
        return Err(TpmError::TrailingData(
            crate::TpmErrorValue::at(buf, param_remainder).actual(param_remainder.len()),
        ));
    }

    let mut handles = TpmHandles::new();
    let mut temp_handle_cursor = handle_area;
    while !temp_handle_cursor.is_empty() {
        let (handle, rest) = TpmUint32::unmarshal(temp_handle_cursor)?;
        handles.try_push(handle)?;
        temp_handle_cursor = rest;
    }

    Ok((handles, command_data, sessions))
}

/// Unmarshals a response from a TPM response buffer.
///
/// # Errors
///
/// Returns [`InvalidCc`](crate::TpmError::InvalidCc) when the command code is
/// non-existent.
/// Returns [`TrailingData`](crate::TpmError::TrailingData) when after
/// unmarshaling there is some data left.
/// Returns [`UnexpectedEnd`](crate::TpmError::UnexpectedEnd) when the
/// buffer does not hold all the bytes.
pub fn tpm_unmarshal_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmResponseValueResult> {
    if buf.len() < HEADER_SIZE {
        return Err(TpmError::UnexpectedEnd(
            crate::TpmErrorValue::new(0).size(HEADER_SIZE, buf.len()),
        ));
    }

    let raw_tag = read_u16(buf, TAG_OFFSET);
    let tag = TpmSt::try_from(raw_tag).map_err(|_| {
        TpmError::InvalidTag(crate::TpmErrorValue::new(TAG_OFFSET).value(u64::from(raw_tag)))
    })?;
    let size_usize = read_u32(buf, SIZE_OFFSET) as usize;
    let raw_rc = read_u32(buf, CODE_OFFSET);
    let rc = TpmRc::try_from(raw_rc).map_err(|_| {
        TpmError::InvalidRc(crate::TpmErrorValue::new(CODE_OFFSET).value(u64::from(raw_rc)))
    })?;
    let body_buf = &buf[HEADER_SIZE..];

    if buf.len() < size_usize {
        return Err(TpmError::UnexpectedEnd(
            crate::TpmErrorValue::new(buf.len()).size(size_usize - buf.len(), 0),
        ));
    } else if buf.len() > size_usize {
        return Err(TpmError::TrailingData(
            crate::TpmErrorValue::new(size_usize).actual(buf.len() - size_usize),
        ));
    }

    if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        return Ok(Err(rc));
    }

    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| {
            TpmError::InvalidCc(crate::TpmErrorValue::new(0).value(u64::from(cc.value())))
        })?;

    let (body, mut session_area) = (dispatch.response_unmarshaler)(tag, body_buf)?;

    let mut auth_responses = TpmAuthResponses::new();
    if tag == TpmSt::Sessions {
        while !session_area.is_empty() {
            let (session, rest) = TpmsAuthResponse::unmarshal(session_area)?;
            auth_responses.try_push(session)?;
            session_area = rest;
        }
    }

    if !session_area.is_empty() {
        return Err(TpmError::TrailingData(
            crate::TpmErrorValue::at(buf, session_area).actual(session_area.len()),
        ));
    }

    Ok(Ok((body, auth_responses)))
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
