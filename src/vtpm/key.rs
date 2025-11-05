//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{RefreshAction, VtpmContext, VtpmError};
use crate::{
    device::{Device, DeviceError},
    key::format_alg_from_public,
    write_object,
};
use std::{any::Any, fs, path::Path};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bPublic, TpmRcBase, TpmSt, TpmsContext},
    frame::{tpm_unmarshal_command, TpmAuthCommands, TpmCommandBody},
    TpmHandle, TpmMarshal, TpmMarshalError, TpmSized, TpmUnmarshal, TpmUnmarshalError, TpmWriter,
};

/// Serialize a command and its auth sessions into `Vec<u8>`.
fn marshal_command(
    command: &TpmCommandBody,
    sessions: &TpmAuthCommands,
) -> Result<Vec<u8>, TpmMarshalError> {
    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let tag = if sessions.is_empty() {
        TpmSt::NoSessions
    } else {
        TpmSt::Sessions
    };
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        command.marshal_frame(tag, sessions, &mut writer)?;
        writer.len()
    };
    buf.truncate(len);
    Ok(buf)
}

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub context: TpmsContext,
    pub handle: TpmHandle,
    pub public: Tpm2bPublic,
    pub parent: Tpm2bPublic,
    pub policy: Vec<(TpmCommandBody, TpmAuthCommands)>,
}

impl VtpmKey {
    pub(super) fn load_from_path(path: &Path) -> Result<Self, VtpmError> {
        let content = fs::read(path)?;
        let (key, remainder) = Self::unmarshal(&content).map_err(VtpmError::ProtocolUnmarshal)?;
        if !remainder.is_empty() {
            log::warn!("trailing data");
        }
        Ok(key)
    }
}

impl TpmSized for VtpmKey {
    const SIZE: usize = 0;
    fn len(&self) -> usize {
        self.context.len()
            + self.handle.len()
            + self.public.len()
            + self.parent.len()
            + self
                .policy
                .iter()
                .map(|(cmd, auth)| cmd.len() + auth.len())
                .sum::<usize>()
    }
}

impl TpmMarshal for VtpmKey {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmMarshalError> {
        self.context.marshal(writer)?;
        self.handle.marshal(writer)?;
        self.public.marshal(writer)?;
        self.parent.marshal(writer)?;
        u32::try_from(self.policy.len())
            .map_err(|_| TpmMarshalError::InvalidValue)?
            .marshal(writer)?;
        for (cmd, auth) in &self.policy {
            let blob = marshal_command(cmd, auth)?;
            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(blob.as_slice())
                .map_err(|_| TpmMarshalError::CapacityExceeded)?
                .marshal(writer)?;
        }
        Ok(())
    }
}

impl TpmUnmarshal for VtpmKey {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmUnmarshalError> {
        let (context, remainder) = TpmsContext::unmarshal(buffer)?;
        let (handle, remainder) = TpmHandle::unmarshal(remainder)?;
        let (public, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (parent, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (count, mut remainder) = u32::unmarshal(remainder)?;
        let mut policy = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (blob, rest) =
                TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)?;
            let (_, body, auth) = tpm_unmarshal_command(blob.as_ref())?;
            policy.push((body, auth));
            remainder = rest;
        }
        Ok((
            Self {
                context,
                handle,
                public,
                parent,
                policy,
            },
            remainder,
        ))
    }
}

impl VtpmContext for VtpmKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn handle(&self) -> u32 {
        self.handle.0
    }

    fn class(&self) -> &'static str {
        "transient"
    }

    fn details(&self) -> String {
        format_alg_from_public(&self.public.inner)
    }

    fn save(&self, path: &Path) -> Result<(), VtpmError> {
        let bytes = write_object(self).map_err(VtpmError::ProtocolMarshal)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn delete(
        &self,
        _device: &mut Device,
        cache_dir: &Path,
        vhandle: u32,
    ) -> Result<(), VtpmError> {
        let path = cache_dir.join(format!("{vhandle:08x}.bin"));
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }

    fn refresh(&mut self, device: &mut Device) -> Result<RefreshAction, VtpmError> {
        match device.load_context(self.context.clone()) {
            Ok(handle) => match device.flush_context(handle) {
                Ok(()) => Ok(RefreshAction::Keep),
                Err(e) => Err(e.into()),
            },
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                Ok(RefreshAction::Stale)
            }
            Err(e) => Err(e.into()),
        }
    }
}
