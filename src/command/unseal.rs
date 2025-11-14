//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    device::{with_device, Device},
    session::{Session, SessionError},
    vtpm::VtpmSession,
};
use clap::Args;
use tpm2_policy_language::{Auth, Handle, HandleClass};
use tpm2_protocol::{
    data::{TpmAlgId, TpmCc, TpmRh, TpmSe},
    frame::{TpmCommand, TpmFrame, TpmUnsealCommand},
};

type KeyPolicyInfo = (Vec<u8>, TpmAlgId);

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// Input: 'tpm:<persistent handle>' or 'vtpm:<transient handle>'
    pub input: Handle,

    /// Force hex output when redirecting to a file or pipe
    #[arg(long)]
    pub hex: bool,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Unseal {
    /// Creates and executes a policy session from a key's embedded policy blobs.
    fn create_policy_session_from_blobs(
        job: &mut Session,
        device: &mut Device,
        policy_blob: &[u8],
        key_name_alg: TpmAlgId,
    ) -> Result<Option<Auth>, CommandError> {
        let Some(commands) = job.to_policy_command_list(device, policy_blob)? else {
            return Ok(None);
        };

        if commands.is_empty() {
            return Ok(None);
        }

        let (resp, nonce_caller) = Session::start_session(
            device,
            TpmSe::Policy,
            key_name_alg,
            (TpmRh::Null as u32).into(),
        )?;

        let temp_session = VtpmSession::new(key_name_alg, nonce_caller, &resp, &[])?;
        let vhandle = job.cache.add_session(temp_session);
        let policy_phandle = resp.session_handle;

        let execution_result: Result<(), CommandError> = (|| {
            for (command_body, auth_sessions) in commands {
                let mut command_body = command_body.clone();

                match &mut command_body {
                    TpmCommand::PolicyPcr(cmd) => cmd.policy_session = policy_phandle.0.into(),
                    TpmCommand::PolicyOr(cmd) => cmd.policy_session = policy_phandle.0.into(),
                    TpmCommand::PolicyRestart(cmd) => {
                        cmd.session_handle = policy_phandle.0.into();
                    }
                    TpmCommand::PolicySecret(cmd) => {
                        cmd.policy_session = policy_phandle.0.into();
                    }
                    _ => {
                        return Err(CommandError::InvalidInput(format!(
                            "Unsupported policy command: {}",
                            command_body.cc()
                        )))
                    }
                }
                device.transmit(&command_body, auth_sessions.as_ref())?;
            }
            Ok(())
        })();

        match execution_result {
            Ok(()) => {
                let new_context = device.save_context(policy_phandle)?;
                let session = job
                    .cache
                    .get_mut_session(vhandle)
                    .ok_or(CommandError::InvalidHandle)?;
                session.context = new_context;
                job.cache.save()?;
                Ok(Some(Auth::Session(vhandle)))
            }
            Err(e) => {
                let _ = job.cache.remove(device, vhandle);
                Err(e)
            }
        }
    }
}

impl Task for Unseal {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        let vhandle = self
            .input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;

        with_device(job.device.clone(), |device| {
            let item_handle = job.load_context(device, &self.input)?;

            let mut auths = self.auth_args.auths().to_vec();
            let mut policy_session_auth: Option<Auth> = None;

            let key_info: Option<KeyPolicyInfo> = if self.input.class() == HandleClass::Vtpm {
                job.cache.find_by_vhandle(vhandle).ok().map(|key| {
                    let policy = if key.policy.is_empty() {
                        Vec::new()
                    } else {
                        key.policy.clone()
                    };
                    (policy, key.public.inner.name_alg)
                })
            } else {
                None
            };

            if self.auth_args.auths().as_ref() == [Auth::default()] {
                if let Some((policy_blob, name_alg)) = key_info {
                    if !policy_blob.is_empty() {
                        if let Some(session_auth) = Unseal::create_policy_session_from_blobs(
                            job,
                            device,
                            &policy_blob,
                            name_alg,
                        )? {
                            auths = vec![session_auth.clone()];
                            policy_session_auth = Some(session_auth);
                        }
                    }
                }
            }

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (resp, _) = job
                .execute(device, &unseal_cmd, &unseal_handles, &auths)
                .map_err(|e: SessionError| {
                    if let Some(Auth::Session(vhandle)) = policy_session_auth {
                        if let Err(e) = job.cache.remove(device, vhandle) {
                            log::error!("Failed to clean up policy session: {e}");
                        }
                    }
                    Into::<CommandError>::into(e)
                })?;

            if let Some(Auth::Session(vhandle)) = policy_session_auth {
                if let Err(e) = job.cache.remove(device, vhandle) {
                    log::error!("Failed to clean up policy session: {e}");
                }
            }

            let out_data = resp
                .Unseal()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if self.hex || job.is_tty {
                writeln!(job.writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                job.writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
