// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

//! 28.2 `TPM2_ContextSave`
//! 28.3 `TPM2_ContextLoad`
//! 28.4 `TPM2_FlushContext`
//! 28.5 `TPM2_EvictControl`

use crate::{
    data::{TpmCc, TpmsContext},
    tpm_struct, TpmPersistent, TpmTransient,
};

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmContextLoadCommand,
    cc: TpmCc::ContextLoad,
    handles: {},
    parameters: {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmContextLoadResponse,
    cc: TpmCc::ContextLoad,
    handles: {
        pub loaded_handle: TpmTransient,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmContextSaveCommand,
    cc: TpmCc::ContextSave,
    handles: {
        pub save_handle: TpmTransient,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmContextSaveResponse,
    cc: TpmCc::ContextSave,
    handles: {},
    parameters: {
        pub context: TpmsContext,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmFlushContextCommand,
    cc: TpmCc::FlushContext,
    handles: {},
    parameters: {
        pub flush_handle: u32,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmFlushContextResponse,
    cc: TpmCc::FlushContext,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmEvictControlCommand,
    cc: TpmCc::EvictControl,
    handles: {
        pub auth: crate::data::TpmiRhHierarchy,
        pub object_handle: crate::data::TpmiDhObject,
    },
    parameters: {
        pub persistent_handle: TpmPersistent,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmEvictControlResponse,
    cc: TpmCc::EvictControl,
    handles: {},
    parameters: {}
}
