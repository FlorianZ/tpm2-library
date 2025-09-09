// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{
    TpmAuthCommands, TpmAuthResponses, TpmCommandBody, TpmHandles, TpmResponseBody,
    PARSE_COMMAND_MAP, PARSE_RESPONSE_MAP,
};
use crate::{
    data::{TpmCc, TpmRc, TpmSt, TpmsAuthCommand, TpmsAuthResponse, TPM_HEADER_SIZE},
    TpmErrorKind, TpmNotDiscriminant, TpmParse, TpmResult,
};
use core::{convert::TryFrom, mem::size_of};

/// Represents the dualistic nature of responses.
pub type TpmResponseResult = Result<(TpmResponseBody, TpmAuthResponses), TpmRc>;

/// Parses a command from a TPM command buffer.
///
/// # Errors
///
/// * `TpmErrorKind::ParseUnderflow` if the buffer is too small
/// * `TpmErrorKind::NotDiscriminant` if the buffer contains an unsupported command code or unexpected byte
/// * `TpmErrorKind::TrailingData` if the command has after spurious data left
pub fn tpm_parse_command(buf: &[u8]) -> TpmResult<(TpmHandles, TpmCommandBody, TpmAuthCommands)> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmErrorKind::ParseUnderflow);
    }
    let buf_len = buf.len();

    let (tag_raw, buf) = u16::parse(buf)?;
    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmSt", TpmNotDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;
    let (size, buf) = u32::parse(buf)?;
    let (cc_raw, body_buf) = u32::parse(buf)?;

    if buf_len < size as usize {
        return Err(TpmErrorKind::ParseUnderflow);
    } else if buf_len > size as usize {
        return Err(TpmErrorKind::TrailingData);
    }

    let cc = TpmCc::try_from(cc_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmCc", TpmNotDiscriminant::Unsigned(u64::from(cc_raw)))
    })?;
    let dispatch = PARSE_COMMAND_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_COMMAND_MAP[index])
        .map_err(|_| {
            TpmErrorKind::NotDiscriminant("TpmCc", TpmNotDiscriminant::Unsigned(u64::from(cc_raw)))
        })?;

    if tag != TpmSt::NoSessions && tag != TpmSt::Sessions {
        return Err(TpmErrorKind::InvalidValue);
    }

    let handle_area_size = dispatch.1 * size_of::<u32>();
    if body_buf.len() < handle_area_size {
        return Err(TpmErrorKind::ParseUnderflow);
    }
    let (handle_area, after_handles) = body_buf.split_at(handle_area_size);

    let mut sessions = TpmAuthCommands::new();
    let param_area = if tag == TpmSt::Sessions {
        let (auth_area_size, buf_after_auth_size) = u32::parse(after_handles)?;
        let auth_area_size = auth_area_size as usize;
        if buf_after_auth_size.len() < auth_area_size {
            return Err(TpmErrorKind::ParseUnderflow);
        }
        let (mut auth_area, param_area) = buf_after_auth_size.split_at(auth_area_size);
        while !auth_area.is_empty() {
            let (session, rest) = TpmsAuthCommand::parse(auth_area)?;
            sessions
                .try_push(session)
                .map_err(|_| TpmErrorKind::ParseCapacity)?;
            auth_area = rest;
        }
        if !auth_area.is_empty() {
            return Err(TpmErrorKind::TrailingData);
        }
        param_area
    } else {
        after_handles
    };

    let (command_data, param_remainder) = (dispatch.2)(handle_area, param_area)?;

    if !param_remainder.is_empty() {
        return Err(TpmErrorKind::TrailingData);
    }

    let mut handles = TpmHandles::new();
    let mut temp_handle_cursor = handle_area;
    while !temp_handle_cursor.is_empty() {
        let (handle, rest) = u32::parse(temp_handle_cursor)?;
        handles.try_push(handle)?;
        temp_handle_cursor = rest;
    }

    Ok((handles, command_data, sessions))
}

/// Parses a response from a TPM response buffer.
///
/// # Errors
///
/// * `TpmErrorKind::ParseUnderflow` if the buffer is too small
/// * `TpmErrorKind::NotDiscriminant` if the buffer contains an unsupported command code
/// * `TpmErrorKind::TrailingData` if the response has after spurious data left
pub fn tpm_parse_response(cc: TpmCc, buf: &[u8]) -> TpmResult<TpmResponseResult> {
    if buf.len() < TPM_HEADER_SIZE {
        return Err(TpmErrorKind::ParseUnderflow);
    }

    let (tag_raw, remainder) = u16::parse(buf)?;
    let (size, remainder) = u32::parse(remainder)?;
    let (code, body_buf) = u32::parse(remainder)?;

    if buf.len() < size as usize {
        return Err(TpmErrorKind::ParseUnderflow);
    } else if buf.len() > size as usize {
        return Err(TpmErrorKind::TrailingData);
    }

    let rc = TpmRc::try_from(code)?;
    if rc.is_error() || rc.is_warning() {
        return Ok(Err(rc));
    }

    let tag = TpmSt::try_from(tag_raw).map_err(|()| {
        TpmErrorKind::NotDiscriminant("TpmSt", TpmNotDiscriminant::Unsigned(u64::from(tag_raw)))
    })?;

    let dispatch = PARSE_RESPONSE_MAP
        .binary_search_by_key(&cc, |d| d.0)
        .map(|index| &PARSE_RESPONSE_MAP[index])
        .map_err(|_| {
            TpmErrorKind::NotDiscriminant(
                "TpmCc",
                TpmNotDiscriminant::Unsigned(u64::from(cc as u32)),
            )
        })?;

    let (body, mut session_area) = (dispatch.1)(tag, body_buf)?;

    let mut auth_responses = TpmAuthResponses::new();
    if tag == TpmSt::Sessions {
        while !session_area.is_empty() {
            let (session, rest) = TpmsAuthResponse::parse(session_area)?;
            auth_responses
                .try_push(session)
                .map_err(|_| TpmErrorKind::ParseCapacity)?;
            session_area = rest;
        }
    }

    if !session_area.is_empty() {
        return Err(TpmErrorKind::TrailingData);
    }

    Ok(Ok((body, auth_responses)))
}
