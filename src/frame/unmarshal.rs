// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    TpmAuthCommands, TpmAuthResponses, TpmCommandBody, TpmHandles, TpmResponseBody,
    TPM_DISPATCH_TABLE,
};
use crate::{
    constant::TPM_HEADER_SIZE,
    data::{TpmCc, TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
    TpmDiscriminant, TpmError, TpmResult, TpmUnmarshal,
};
use core::{convert::TryFrom, mem::size_of};

/// A unified struct holding all dispatch info for a given Command Code.
#[doc(hidden)]
pub struct TpmDispatch {
    pub cc: TpmCc,
    pub handles: usize,
    #[allow(clippy::type_complexity)]
    pub command_unmarshaler:
        for<'a> fn(&'a [u8], &'a [u8]) -> TpmResult<(TpmCommandBody, &'a [u8])>,
    #[allow(clippy::type_complexity)]
    pub response_unmarshaler: for<'a> fn(TpmSt, &'a [u8]) -> TpmResult<(TpmResponseBody, &'a [u8])>,
}

/// Represents the dualistic nature of responses.
pub type TpmResponseResult = Result<(TpmResponseBody, TpmAuthResponses), TpmRc>;

/// Unmarshals a command from a TPM command buffer.
///
/// # Errors
///
/// * `TpmError::Truncated` if the buffer is too small
/// * `TpmError::UnknownDiscriminant` if the buffer contains an unsupported command code or unexpected byte
/// * `TpmError::TrailingData` if the command has after spurious data left
pub fn tpm_unmarshal_command(
    buf: &[u8],
) -> TpmResult<(TpmHandles, TpmCommandBody, TpmAuthCommands)> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmError::Truncated);
    }
    let buf_len = buf.len();

    let (tag_raw, buf) = u16::unmarshal(buf)?;
    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmError::UnknownDiscriminant("TpmSt", TpmDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;
    let (size, buf) = u32::unmarshal(buf)?;
    let (cc_raw, body_buf) = u32::unmarshal(buf)?;

    if buf_len < size as usize {
        return Err(TpmError::Truncated);
    } else if buf_len > size as usize {
        return Err(TpmError::TrailingData);
    }

    let cc = TpmCc::try_from(cc_raw).map_err(|()| {
        TpmError::UnknownDiscriminant("TpmCc", TpmDiscriminant::Unsigned(u64::from(cc_raw)))
    })?;
    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| {
            TpmError::UnknownDiscriminant("TpmCc", TpmDiscriminant::Unsigned(u64::from(cc_raw)))
        })?;

    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmError::Malformed);
    }

    let handle_area_size = dispatch.handles * size_of::<u32>();
    if body_buf.len() < handle_area_size {
        return Err(TpmError::Truncated);
    }
    let (handle_area, after_handles) = body_buf.split_at(handle_area_size);

    let mut sessions = TpmAuthCommands::new();
    let param_area = if tag == TpmSt::Sessions {
        let (auth_area_size, buf_after_auth_size) = u32::unmarshal(after_handles)?;
        let auth_area_size = auth_area_size as usize;
        if buf_after_auth_size.len() < auth_area_size {
            return Err(TpmError::Truncated);
        }
        let (mut auth_area, param_area) = buf_after_auth_size.split_at(auth_area_size);
        while !auth_area.is_empty() {
            let (session, rest) = TpmsAuthCommand::unmarshal(auth_area)?;
            sessions.try_push(session)?;
            auth_area = rest;
        }
        if !auth_area.is_empty() {
            return Err(TpmError::TrailingData);
        }
        param_area
    } else {
        after_handles
    };

    let (command_data, param_remainder) = (dispatch.command_unmarshaler)(handle_area, param_area)?;

    if !param_remainder.is_empty() {
        return Err(TpmError::TrailingData);
    }

    let mut handles = TpmHandles::new();
    let mut temp_handle_cursor = handle_area;
    while !temp_handle_cursor.is_empty() {
        let (handle, rest) = u32::unmarshal(temp_handle_cursor)?;
        handles.try_push(handle.into())?;
        temp_handle_cursor = rest;
    }

    Ok((handles, command_data, sessions))
}

/// Unmarshals a response from a TPM response buffer.
///
/// # Errors
///
/// * `TpmError::Truncated` if the buffer is too small
/// * `TpmError::UnknownDiscriminant` if the buffer contains an unsupported command code
/// * `TpmError::TrailingData` if the response has after spurious data left
pub fn tpm_unmarshal_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmResponseResult> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmError::Truncated);
    }

    let (tag_raw, remainder) = u16::unmarshal(buf)?;
    let (size, remainder) = u32::unmarshal(remainder)?;
    let (code, body_buf) = u32::unmarshal(remainder)?;

    if buf.len() < size as usize {
        return Err(TpmError::Truncated);
    } else if buf.len() > size as usize {
        return Err(TpmError::TrailingData);
    }

    let rc = TpmRc::try_from(code)?;
    if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        return Ok(Err(rc));
    }

    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmError::UnknownDiscriminant("TpmSt", TpmDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;

    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| {
            TpmError::UnknownDiscriminant("TpmCc", TpmDiscriminant::Unsigned(u64::from(cc as u32)))
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
        return Err(TpmError::TrailingData);
    }

    Ok(Ok((body, auth_responses)))
}
