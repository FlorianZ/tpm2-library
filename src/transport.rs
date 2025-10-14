// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::device::DeviceError;
use std::{any::Any, fs::File, io::Read, io::Write};
use tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE;

/// A trait for a transport layer capable of sending and receiving full TPM
/// commands.
pub trait Transport: Send + std::fmt::Debug {
    /// Sends a complete command buffer to the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` on I/O failure.
    fn send(&mut self, command_bytes: &[u8]) -> Result<(), DeviceError>;

    /// Receives a complete response buffer from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `DeviceError` on I/O failure or if the response is malformed.
    fn receive(&mut self) -> Result<Vec<u8>, DeviceError>;

    /// Returns this transport as a `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A transport implementation that wraps a `std::fs::File`.
#[derive(Debug)]
pub struct FileTransport(pub File);

/// Reads a complete TPM response from any stream that implements `Read`.
pub(crate) fn receive_from_stream<R: Read>(stream: &mut R) -> Result<Vec<u8>, DeviceError> {
    let mut header = [0u8; 10];
    stream.read_exact(&mut header)?;
    let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
        return Err(DeviceError::ResponseCorrupted);
    };
    let size = u32::from_be_bytes(size_bytes) as usize;
    if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
        return Err(DeviceError::ResponseCorrupted);
    }
    let mut resp_buf = header.to_vec();
    resp_buf.resize(size, 0);
    stream.read_exact(&mut resp_buf[header.len()..])?;
    Ok(resp_buf)
}

impl Transport for FileTransport {
    fn send(&mut self, command_bytes: &[u8]) -> Result<(), DeviceError> {
        self.0.write_all(command_bytes)?;
        self.0.flush()?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, DeviceError> {
        receive_from_stream(&mut self.0)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
