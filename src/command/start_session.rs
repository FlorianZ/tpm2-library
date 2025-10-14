// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{session::SessionType, CommandError},
    context::ContextCache,
    device::{with_device, Device},
    key::from_str_to_alg_id,
    session::Session as SessionData,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc, str::FromStr};
use tpm2_protocol::data::TpmSe;

/// Starts a new authorization session.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "start-session")]
pub struct StartSession {
    /// session specifier, e.g., 'hmac:sha256'
    #[argh(positional)]
    pub session_spec: String,
}

impl SubCommand for StartSession {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        with_device(device, |device| {
            let (type_str, alg_str) = self.session_spec.split_once(':').ok_or_else(|| {
                CommandError::InvalidInput(
                    "session specifier must be in the format 'type:algorithm'".to_string(),
                )
            })?;

            let session_type_enum = SessionType::from_str(type_str)
                .map_err(|e| CommandError::InvalidInput(e.to_string()))?;

            let auth_hash = from_str_to_alg_id(alg_str)?;

            let session_type = match session_type_enum {
                SessionType::Hmac => TpmSe::Hmac,
                SessionType::Policy => TpmSe::Policy,
                SessionType::Trial => TpmSe::Trial,
            };

            let (resp, nonce_caller) = device.start_session(session_type, auth_hash)?;
            let live_handle = resp.session_handle;
            let mut session = SessionData::new(session_type, auth_hash, nonce_caller, &resp)?;

            session.context = device.save_context(live_handle.0)?;
            session.handle = tpm2_protocol::TpmHandle(0);

            let saved_uri = context.session_map.add(session);
            context.session_map.save()?;

            writeln!(context.writer, "{saved_uri}")?;
            Ok(())
        })
    }
}
