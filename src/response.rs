// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::unmarshal::TpmUnmarshal;
use anyhow::{Result, anyhow};
use tpm2_protocol::{
    TpmError, TpmErrorValue, TpmResult, TpmSized,
    basic::{TpmHandle, TpmUint32},
    data::TpmSt,
    frame::{
        TpmCreatePrimaryResponse, TpmCreateResponse, TpmDictionaryAttackLockResetResponse,
        TpmEvictControlResponse, TpmHeader, TpmImportResponse, TpmLoadResponse,
        TpmNvReadPublicResponse, TpmNvReadResponse, TpmPcrEventResponse, TpmPcrReadResponse,
        TpmResponse, TpmUnsealResponse,
    },
};

pub(crate) trait TpmResponseBody: TpmHeader + Sized {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self>;
}

pub(crate) fn parse_response<R: TpmResponseBody>(response: &TpmResponse) -> Result<R> {
    response.validate(R::CC)?;
    let (handles, params) = response_parts::<R>(response)?;
    Ok(R::unmarshal_response(handles, params)?)
}

fn response_parts<R: TpmHeader>(response: &TpmResponse) -> Result<(&[u8], &[u8])> {
    let handle_area_size = R::HANDLES
        .checked_mul(TpmHandle::SIZE)
        .ok_or_else(|| anyhow!("integer overflow"))?;
    let body = response.body();
    if body.len() < handle_area_size {
        return Err(anyhow!("malformed data"));
    }

    let (handles, after_handles) = body.split_at(handle_area_size);
    if response.tag()? != TpmSt::Sessions {
        return Ok((handles, after_handles));
    }

    let (parameter_size, after_size) = TpmUint32::cast_prefix(after_handles)?;
    let parameter_size = usize::try_from(parameter_size.value())?;
    if after_size.len() < parameter_size {
        return Err(anyhow!("malformed data"));
    }

    Ok((handles, &after_size[..parameter_size]))
}

fn read<T: TpmUnmarshal>(cursor: &mut &[u8]) -> TpmResult<T> {
    let (value, tail) = T::unmarshal(cursor)?;
    *cursor = tail;
    Ok(value)
}

fn ensure_empty(buf: &[u8]) -> TpmResult<()> {
    if buf.is_empty() {
        Ok(())
    } else {
        Err(TpmError::TrailingData(
            TpmErrorValue::new(0).actual(buf.len()),
        ))
    }
}

impl TpmResponseBody for TpmImportResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let out_private = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self {
            handles: [],
            out_private,
        })
    }
}

impl TpmResponseBody for TpmEvictControlResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        ensure_empty(params)?;
        Ok(Self { handles: [] })
    }
}

impl TpmResponseBody for TpmDictionaryAttackLockResetResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        ensure_empty(params)?;
        Ok(Self { handles: [] })
    }
}

impl TpmResponseBody for TpmCreatePrimaryResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        let mut handles_buf = handles;
        let object_handle = read(&mut handles_buf)?;
        ensure_empty(handles_buf)?;

        let mut params = params;
        let out_public = read(&mut params)?;
        let creation_data = read(&mut params)?;
        let creation_hash = read(&mut params)?;
        let creation_ticket = read(&mut params)?;
        let name = read(&mut params)?;
        ensure_empty(params)?;

        Ok(Self {
            handles: [object_handle],
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name,
        })
    }
}

impl TpmResponseBody for TpmCreateResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let out_private = read(&mut params)?;
        let out_public = read(&mut params)?;
        let creation_data = read(&mut params)?;
        let creation_hash = read(&mut params)?;
        let creation_ticket = read(&mut params)?;
        ensure_empty(params)?;

        Ok(Self {
            handles: [],
            out_private,
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
        })
    }
}

impl TpmResponseBody for TpmLoadResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        let mut handles_buf = handles;
        let object_handle = read(&mut handles_buf)?;
        ensure_empty(handles_buf)?;

        let mut params = params;
        let name = read(&mut params)?;
        ensure_empty(params)?;

        Ok(Self {
            handles: [object_handle],
            name,
        })
    }
}

impl TpmResponseBody for TpmPcrEventResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let digests = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self {
            handles: [],
            digests,
        })
    }
}

impl TpmResponseBody for TpmPcrReadResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let pcr_update_counter = read(&mut params)?;
        let pcr_selection_out = read(&mut params)?;
        let pcr_values = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self {
            handles: [],
            pcr_update_counter,
            pcr_selection_out,
            pcr_values,
        })
    }
}

impl TpmResponseBody for TpmUnsealResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let out_data = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self {
            handles: [],
            out_data,
        })
    }
}

impl TpmResponseBody for TpmNvReadPublicResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let nv_public = read(&mut params)?;
        let nv_name = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self {
            handles: [],
            nv_public,
            nv_name,
        })
    }
}

impl TpmResponseBody for TpmNvReadResponse {
    fn unmarshal_response(handles: &[u8], params: &[u8]) -> TpmResult<Self> {
        ensure_empty(handles)?;
        let mut params = params;
        let data = read(&mut params)?;
        ensure_empty(params)?;
        Ok(Self { handles: [], data })
    }
}
