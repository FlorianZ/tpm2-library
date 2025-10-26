// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{RefreshAction, VtpmContext, VtpmError};
use crate::{
    device::{Device, DeviceError},
    key::format_alg_from_public,
    write_object,
};
use std::{any::Any, fs, path::Path};
use tpm2_protocol::{
    data::{Tpm2bPublic, TpmRcBase, TpmsContext},
    TpmBuild, TpmError, TpmHandle, TpmParse, TpmSized, TpmWriter,
};

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub context: TpmsContext,
    pub handle: TpmHandle,
    pub public: Tpm2bPublic,
    pub parent: Tpm2bPublic,
}

impl VtpmKey {
    pub(super) fn load_from_path(path: &Path) -> Result<Self, VtpmError> {
        let content = fs::read(path)?;
        let (key, remainder) = Self::parse(&content)?;
        if !remainder.is_empty() {
            log::warn!("trailing data");
        }
        Ok(key)
    }
}

impl TpmSized for VtpmKey {
    const SIZE: usize = 0;
    fn len(&self) -> usize {
        self.context.len() + self.public.len() + self.parent.len()
    }
}

impl TpmBuild for VtpmKey {
    fn build(&self, writer: &mut TpmWriter) -> Result<(), TpmError> {
        self.context.build(writer)?;
        self.handle.build(writer)?;
        self.public.build(writer)?;
        self.parent.build(writer)
    }
}

impl TpmParse for VtpmKey {
    fn parse(buffer: &[u8]) -> Result<(Self, &[u8]), TpmError> {
        let (context, remainder) = TpmsContext::parse(buffer)?;
        let (handle, remainder) = TpmHandle::parse(remainder)?;
        let (public, remainder) = Tpm2bPublic::parse(remainder)?;
        let (parent, remainder) = Tpm2bPublic::parse(remainder)?;
        Ok((
            Self {
                context,
                handle,
                public,
                parent,
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
        let bytes = write_object(self)?;
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
