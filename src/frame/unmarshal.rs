// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    TPM_DISPATCH_TABLE, TPM_HEADER_SIZE, TpmAuthCommands, TpmAuthResponses, TpmCommandValue,
    TpmHandles, TpmResponseValue,
};
use crate::{
    TpmProtocolError, TpmResult, TpmUnmarshal,
    basic::TpmUint32,
    data::{TpmCc, TpmRc, TpmRcBase, TpmSt, TpmsAuthCommand, TpmsAuthResponse},
};
use core::mem::size_of;

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
/// Returns [`InvalidValue`](crate::TpmProtocolError::InvalidValue) when the
/// command code is non-existent.
/// Returns [`TrailingData`](crate::TpmProtocolError::TrailingData) when after
/// unmarshaling there is some data left.
/// Returns [`UnexpectedEnd`](crate::TpmProtocolError::UnexpectedEnd) when the
/// buffer does not hold all the bytes.
pub fn tpm_unmarshal_command(
    buf: &[u8],
) -> TpmResult<(TpmHandles, TpmCommandValue, TpmAuthCommands)> {
    if buf.len() < TPM_HEADER_SIZE as usize {
        return Err(TpmProtocolError::UnexpectedEnd);
    }
    let buf_len = buf.len();

    let (tag, buf) = TpmSt::unmarshal(buf)?;
    let (size, buf) = TpmUint32::unmarshal(buf)?;
    let (cc, body_buf) = TpmCc::unmarshal(buf)?;

    let size_usize = u32::from(size) as usize;
    if buf_len < size_usize {
        return Err(TpmProtocolError::UnexpectedEnd);
    } else if buf_len > size_usize {
        return Err(TpmProtocolError::TrailingData);
    }

    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| TpmProtocolError::InvalidCc)?;

    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmProtocolError::InvalidTag);
    }

    let handle_area_size = dispatch.handles * size_of::<u32>();
    if body_buf.len() < handle_area_size {
        return Err(TpmProtocolError::UnexpectedEnd);
    }
    let (handle_area, after_handles) = body_buf.split_at(handle_area_size);

    let mut sessions = TpmAuthCommands::new();
    let param_area = if tag == TpmSt::Sessions {
        let (auth_area_size, buf_after_auth_size) = TpmUint32::unmarshal(after_handles)?;
        let auth_area_size = u32::from(auth_area_size) as usize;
        if buf_after_auth_size.len() < auth_area_size {
            return Err(TpmProtocolError::UnexpectedEnd);
        }
        let (mut auth_area, param_area) = buf_after_auth_size.split_at(auth_area_size);
        while !auth_area.is_empty() {
            let (session, rest) = TpmsAuthCommand::unmarshal(auth_area)?;
            sessions.try_push(session)?;
            auth_area = rest;
        }
        if !auth_area.is_empty() {
            return Err(TpmProtocolError::TrailingData);
        }
        param_area
    } else {
        after_handles
    };

    let (command_data, param_remainder) = (dispatch.command_unmarshaler)(handle_area, param_area)?;

    if !param_remainder.is_empty() {
        return Err(TpmProtocolError::TrailingData);
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
/// Returns [`InvalidValue`](crate::TpmProtocolError::InvalidValue) when the
/// command code is non-existent.
/// Returns [`TrailingData`](crate::TpmProtocolError::TrailingData) when after
/// unmarshaling there is some data left.
/// Returns [`UnexpectedEnd`](crate::TpmProtocolError::UnexpectedEnd) when the
/// buffer does not hold all the bytes.
pub fn tpm_unmarshal_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmResponseValueResult> {
    if buf.len() < TPM_HEADER_SIZE as usize {
        return Err(TpmProtocolError::UnexpectedEnd);
    }

    let (tag, remainder) = TpmSt::unmarshal(buf)?;
    let (size, remainder) = TpmUint32::unmarshal(remainder)?;
    let (rc, body_buf) = TpmRc::unmarshal(remainder)?;

    let size_usize = u32::from(size) as usize;
    if buf.len() < size_usize {
        return Err(TpmProtocolError::UnexpectedEnd);
    } else if buf.len() > size_usize {
        return Err(TpmProtocolError::TrailingData);
    }

    if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        return Ok(Err(rc));
    }

    let dispatch = TPM_DISPATCH_TABLE
        .binary_search_by_key(&cc, |d| d.cc)
        .map(|index| &TPM_DISPATCH_TABLE[index])
        .map_err(|_| TpmProtocolError::InvalidCc)?;

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
        return Err(TpmProtocolError::TrailingData);
    }

    Ok(Ok((body, auth_responses)))
}
