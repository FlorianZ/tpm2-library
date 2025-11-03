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
    basic::{TpmBuffer, TpmList},
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bPublic, TpmRcBase, TpmsContext},
    TpmHandle, TpmMarshal, TpmMarshalError, TpmSized, TpmUnmarshal, TpmUnmarshalError, TpmWriter,
};

/// A local constant for the max commands, as tpm2-protocol 0.12 does not export this.
const MAX_POLICY_COMMANDS: usize = 32;
type TpmPolicyCommandBlob = TpmBuffer<{ TPM_MAX_COMMAND_SIZE as usize }>;

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub context: TpmsContext,
    pub handle: TpmHandle,
    pub public: Tpm2bPublic,
    pub parent: Tpm2bPublic,
    pub policy: TpmList<TpmPolicyCommandBlob, MAX_POLICY_COMMANDS>,
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
            + self.policy.len()
    }
}

impl TpmMarshal for VtpmKey {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmMarshalError> {
        self.context.marshal(writer)?;
        self.handle.marshal(writer)?;
        self.public.marshal(writer)?;
        self.parent.marshal(writer)?;
        self.policy.marshal(writer)
    }
}

impl TpmUnmarshal for VtpmKey {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmUnmarshalError> {
        let (context, remainder) = TpmsContext::unmarshal(buffer)?;
        let (handle, remainder) = TpmHandle::unmarshal(remainder)?;
        let (public, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (parent, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (policy, remainder) =
            TpmList::<TpmPolicyCommandBlob, MAX_POLICY_COMMANDS>::unmarshal(remainder)?;
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
