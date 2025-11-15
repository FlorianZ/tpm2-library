//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{RefreshAction, VtpmContext, VtpmError};
use crate::{
    alg::format_alg_from_public,
    device::{Device, DeviceError},
    write_object,
};
use std::{any::Any, fs, path::Path};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bDigest, Tpm2bName, Tpm2bPublic, TpmCc, TpmRcBase, TpmsContext},
    frame::{TpmAuthCommands, TpmCommand},
    TpmHandle, TpmMarshal, TpmProtocolError, TpmSized, TpmUnmarshal, TpmWriter,
};
use tpm2_tpmkey::{Error as TpmKeyError, TpmPolicy, TpmPolicyCommand};

#[derive(Debug, Clone)]
pub struct VtpmKey {
    pub context: TpmsContext,
    pub handle: TpmHandle,
    pub public: Tpm2bPublic,
    pub parent: Tpm2bPublic,
    pub empty_auth: u32,
    pub policy: Vec<u8>,
}

impl VtpmKey {
    pub(super) fn load_from_path(path: &Path) -> Result<Self, VtpmError> {
        let content = fs::read(path)?;
        let (key, remainder) = Self::unmarshal(&content).map_err(VtpmError::Protocol)?;
        if !remainder.is_empty() {
            log::warn!("trailing data");
        }
        Ok(key)
    }

    /// Converts a "live" `TpmCommandList` into a "storable" `TpmPolicy`.
    ///
    /// This performs the "second pass" for `PolicySecret`, converting the
    /// `auth_handle` into a `Tpm2bName` for durable storage.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyData`](VtpmError::PolicyData) if the command conversion fails.
    /// Returns [`Device`](VtpmError::Device) if reading the public handle name fails.
    pub fn command_list_to_tpmkey_policy(
        device: &mut Device,
        commands: &[(TpmCommand, TpmAuthCommands)],
    ) -> Result<TpmPolicy, VtpmError> {
        let mut policy = Vec::new();
        for (cmd, auths) in commands {
            let step = match cmd {
                TpmCommand::PolicySecret(inner) => {
                    let (_, name) = device.read_public(inner.auth_handle)?;
                    TpmPolicyCommand::from_policy_secret(inner, &name).map_err(VtpmError::from)?
                }
                _ => TpmPolicyCommand::from_command(cmd, auths).map_err(VtpmError::from)?,
            };
            policy.push(step);
        }
        Ok(TpmPolicy { name: None, policy })
    }

    /// Converts a "storable" `TpmPolicy` (from a `TpmKey` file) into the
    /// custom binary cache format.
    ///
    /// # Errors
    ///
    /// Returns [`IntDecode`](VtpmError::IntDecode) if the policy command count exceeds `u32::MAX`.
    /// Returns [`Protocol`](VtpmError::Protocol) if marshalling fails or the policy body is too large.
    /// Returns [`PolicyData`](VtpmError::PolicyData) if the policy blob is malformed.
    pub fn policy_from_tpmkey_policy(policy: &TpmPolicy) -> Result<Vec<u8>, VtpmError> {
        let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
        let len = {
            let mut writer = TpmWriter::new(&mut buf);
            let count = u32::try_from(policy.policy.len())?;
            count.marshal(&mut writer)?;

            for cmd in &policy.policy {
                cmd.code().marshal(&mut writer)?;

                if cmd.code() == TpmCc::PolicySecret {
                    let (handle, rest) = TpmHandle::unmarshal(cmd.body())
                        .map_err(|_| VtpmError::PolicyData(TpmKeyError::InvalidPolicy))?;
                    let (name, rest) = Tpm2bName::unmarshal(rest)
                        .map_err(|_| VtpmError::PolicyData(TpmKeyError::InvalidPolicy))?;
                    let (digest, _) = Tpm2bDigest::unmarshal(rest)
                        .map_err(|_| VtpmError::PolicyData(TpmKeyError::InvalidPolicy))?;

                    handle.marshal(&mut writer)?;
                    name.marshal(&mut writer)?;
                    digest.marshal(&mut writer)?;
                } else {
                    TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(cmd.body())?
                        .marshal(&mut writer)?;
                }
            }
            writer.len()
        };
        buf.truncate(len);
        Ok(buf)
    }
}

impl TpmSized for VtpmKey {
    const SIZE: usize = 0;
    fn len(&self) -> usize {
        self.context.len()
            + self.handle.len()
            + self.public.len()
            + self.parent.len()
            + u32::SIZE
            + TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::SIZE
    }
}

impl TpmMarshal for VtpmKey {
    fn marshal(&self, writer: &mut TpmWriter) -> Result<(), TpmProtocolError> {
        self.context.marshal(writer)?;
        self.handle.marshal(writer)?;
        self.public.marshal(writer)?;
        self.parent.marshal(writer)?;
        self.empty_auth.marshal(writer)?;
        TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(self.policy.as_slice())?
            .marshal(writer)?;
        Ok(())
    }
}

impl TpmUnmarshal for VtpmKey {
    fn unmarshal(buffer: &[u8]) -> Result<(Self, &[u8]), TpmProtocolError> {
        let (context, remainder) = TpmsContext::unmarshal(buffer)?;
        let (handle, remainder) = TpmHandle::unmarshal(remainder)?;
        let (public, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (parent, remainder) = Tpm2bPublic::unmarshal(remainder)?;
        let (empty_auth, remainder) = u32::unmarshal(remainder)?;
        let (policy_blob, remainder) =
            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::unmarshal(remainder)?;

        Ok((
            Self {
                context,
                handle,
                public,
                parent,
                empty_auth,
                policy: policy_blob.to_vec(),
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
        let bytes = write_object(self).map_err(VtpmError::Protocol)?;
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
