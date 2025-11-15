//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{RefreshAction, VtpmContext, VtpmError};
use crate::device::{Device, DeviceError};
use std::{any::Any, fs, path::Path};
use tpm2_crypto::Hash;
use tpm2_protocol::{
    basic::TpmBuffer,
    data::{
        Tpm2bAuth, Tpm2bName, Tpm2bNonce, TpmAlgId, TpmCc, TpmHt, TpmRcBase, TpmRh, TpmaSession,
        TpmsAuthCommand, TpmsContext,
    },
    frame::TpmStartAuthSessionResponse,
    TpmHandle, TpmSized,
};

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct VtpmSession {
    pub context: TpmsContext,
    pub nonce_tpm: Tpm2bNonce,
    pub attributes: TpmaSession,
    pub hmac_key: Tpm2bAuth,
    pub auth_hash: TpmAlgId,
}

impl VtpmSession {
    /// Creates a new session from a `StartAuthSession` response.
    ///
    /// # Errors
    ///
    /// Returns a [`VtpmError`] if the hash algorithm is unsupported or if `KDFa` fails.
    pub fn new(
        auth_hash: TpmAlgId,
        nonce_caller: Tpm2bNonce,
        resp: &TpmStartAuthSessionResponse,
        auth_value: &[u8],
    ) -> Result<Self, VtpmError> {
        let digest_len = Hash::from(auth_hash).size();
        let hmac_key_bytes = if (resp.session_handle.0 >> 24) as u8 == TpmHt::HmacSession as u8 {
            if auth_value.is_empty() {
                Vec::new()
            } else {
                let key_bits = u16::try_from(digest_len * 8)
                    .map_err(|_| VtpmError::InvalidKeyBits(digest_len.to_string()))?;
                Hash::from(auth_hash).kdfa(
                    auth_value,
                    "ATH",
                    &resp.nonce_tpm,
                    &nonce_caller,
                    key_bits,
                )?
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            context: TpmsContext {
                sequence: 0,
                saved_handle: resp.session_handle.0.into(),
                hierarchy: TpmRh::Null,
                context_blob: TpmBuffer::default(),
            },
            nonce_tpm: resp.nonce_tpm,
            attributes: TpmaSession::CONTINUE_SESSION,
            hmac_key: Tpm2bAuth::try_from(hmac_key_bytes.as_slice())
                .map_err(|_| VtpmError::CapacityExceeded)?,
            auth_hash,
        })
    }
}

impl VtpmContext for VtpmSession {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn handle(&self) -> u32 {
        self.context.saved_handle.0
    }

    fn class(&self) -> &'static str {
        if (self.handle() >> 24) as u8 == TpmHt::PolicySession as u8 {
            "policy"
        } else {
            "hmac"
        }
    }

    fn details(&self) -> String {
        String::new()
    }

    fn save(&self, _path: &Path) -> Result<(), VtpmError> {
        Ok(())
    }

    fn delete(&self, device: &mut Device, cache_dir: &Path, vhandle: u32) -> Result<(), VtpmError> {
        let path = cache_dir.join(format!("{vhandle:08x}.bin"));
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        match device.flush_session(self.context.clone()) {
            Ok(()) => {}
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                log::debug!("vtpm session:{vhandle:08x} stale");
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn refresh(&mut self, device: &mut Device) -> Result<RefreshAction, VtpmError> {
        let vhandle = self.handle();
        match device.load_context(self.context.clone()) {
            Ok(phandle) => match device.save_context(phandle) {
                Ok(context) => {
                    self.context = context;
                    match device.flush_context(phandle) {
                        Ok(()) => Ok(RefreshAction::Keep),
                        Err(e) => {
                            log::warn!("vtpm:{vhandle:08x}: {e}");
                            Ok(RefreshAction::Stale)
                        }
                    }
                }
                Err(e) => {
                    log::warn!("vtpm:{vhandle:08x}: {e}");
                    if let Err(e) = device.flush_context(phandle) {
                        log::warn!("vtpm:{vhandle:08x}: {e}");
                    }
                    if matches!(&e, DeviceError::TpmRc(rc) if rc.base() == TpmRcBase::ReferenceH0) {
                        Ok(RefreshAction::Stale)
                    } else {
                        Err(e.into())
                    }
                }
            },
            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                Ok(RefreshAction::Stale)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Creates a password authorization session command structure.
///
/// # Errors
///
/// Returns a [`VtpmError`] if the password cannot be converted to a `Tpm2bAuth`.
pub fn build_password_session(password: &[u8]) -> Result<TpmsAuthCommand, VtpmError> {
    Ok(TpmsAuthCommand {
        session_handle: (tpm2_protocol::data::TpmRh::Pw as u32).into(),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password).map_err(|_| VtpmError::CapacityExceeded)?,
    })
}

/// Creates an authorization command structure for an HMAC session.
///
/// # Errors
///
/// Returns a [`VtpmError`] on cryptographic failures or if TPM data structures
/// cannot be serialized.
#[allow(clippy::too_many_arguments)]
pub fn create_auth(
    device: &mut Device,
    session: &VtpmSession,
    nonce_caller: &Tpm2bNonce,
    auth_value: &[u8],
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
    nonce_decrypt: Option<&Tpm2bNonce>,
    nonce_encrypt: Option<&Tpm2bNonce>,
) -> Result<TpmsAuthCommand, VtpmError> {
    let handle_names: Vec<Tpm2bName> = handles
        .iter()
        .map(|&handle| {
            let handle_type = (handle >> 24) as u8;
            if handle_type == TpmHt::Transient as u8 || handle_type == TpmHt::Persistent as u8 {
                device
                    .read_public(handle.into())
                    .map(|(_, name)| name)
                    .map_err(VtpmError::Device)
            } else {
                let mut buf = [0u8; TpmHandle::SIZE];
                let mut pos = 0;
                handle.to_be_bytes().iter().for_each(|b| {
                    if pos < buf.len() {
                        buf[pos] = *b;
                        pos += 1;
                    }
                });
                let len = pos;

                if let Ok(name) = Tpm2bName::try_from(&buf[..len]) {
                    Ok(name)
                } else {
                    Err(VtpmError::CapacityExceeded)
                }
            }
        })
        .collect::<Result<_, VtpmError>>()?;

    let command_code_bytes = (command_code as u32).to_be_bytes();

    let mut cp_hash_chunks: Vec<&[u8]> = Vec::with_capacity(2 + handle_names.len());
    cp_hash_chunks.push(&command_code_bytes);
    for name in &handle_names {
        cp_hash_chunks.push(name.as_ref());
    }
    cp_hash_chunks.push(parameters);

    let cp_hash = Hash::from(session.auth_hash).digest(&cp_hash_chunks)?;

    let hmac_bytes = if (session.context.saved_handle.0 >> 24) as u8 == TpmHt::HmacSession as u8 {
        let hmac_key = [session.hmac_key.as_ref(), auth_value].concat();
        if hmac_key.is_empty() {
            return Ok(TpmsAuthCommand {
                session_handle: session.context.saved_handle,
                nonce: *nonce_caller,
                session_attributes: session.attributes,
                hmac: Tpm2bAuth::default(),
            });
        }

        let mut hmac_payload: Vec<&[u8]> = Vec::with_capacity(8);
        hmac_payload.push(&cp_hash);
        hmac_payload.push(nonce_caller.as_ref());
        hmac_payload.push(session.nonce_tpm.as_ref());

        if let Some(nonce) = nonce_decrypt {
            hmac_payload.push(nonce.as_ref());
        }
        if let Some(nonce) = nonce_encrypt {
            if nonce_decrypt.map_or(true, |d| d.as_ref() != nonce.as_ref()) {
                hmac_payload.push(nonce.as_ref());
            }
        }

        let attribute_bits = [session.attributes.bits()];
        hmac_payload.push(&attribute_bits);

        Hash::from(session.auth_hash).hmac(&hmac_key, &hmac_payload)?
    } else {
        Vec::new()
    };

    Ok(TpmsAuthCommand {
        session_handle: session.context.saved_handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::try_from(hmac_bytes.as_slice())
            .map_err(|_| VtpmError::CapacityExceeded)?,
    })
}
