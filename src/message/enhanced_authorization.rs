// SPDX-License-Identifier: MIT OR Apache-2.0 Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! 23 Enhanced Authorization (EA) Commands
//!
//! 23.3 `TPM2_PolicySigned`
//! 23.4 `TPM2_PolicySecret`
//! 23.5 `TPM2_PolicyTicket`
//! 23.6 `TPM2_PolicyOR`
//! 23.7 `TPM2_PolicyPCR`
//! 23.8 `TPM2_PolicyLocality`
//! 23.9 `TPM2_PolicyNV`
//! 23.10 `TPM2_PolicyCounterTimer`
//! 23.11 `TPM2_PolicyCommandCode`
//! 23.12 `TPM2_PolicyPhysicalPresence`
//! 23.13 `TPM2_PolicyCpHash`
//! 23.14 `TPM2_PolicyNameHash`
//! 23.15 `TPM2_PolicyDuplicationSelect`
//! 23.16 `TPM2_PolicyAuthorize`
//! 23.17 `TPM2_PolicyAuthValue`
//! 23.18 `TPM2_PolicyPassword`
//! 23.19 `TPM2_PolicyGetDigest`
//! 23.20 `TPM2_PolicyNvWritten`
//! 23.21 `TPM2_PolicyTemplate`
//! 23.22 `TPM2_PolicyAuthorizeNV`
//! 23.23 `TPM2_PolicyCapability`
//! 23.24 `TPM2_PolicyParameters`
//! 23.25 `TPM2_PolicyTransportSPDM`

use crate::{
    data::{
        Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce, Tpm2bTimeout, TpmCap, TpmCc, TpmEo,
        TpmaLocality, TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmtSignature, TpmtTkAuth,
        TpmtTkVerified,
    },
    tpm_struct,
};
use core::fmt::Debug;

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicySignedCommand,
    cc: TpmCc::PolicySigned,
    handles: {
        pub auth_object: crate::data::TpmiDhObject,
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub expiration: i32,
        pub auth: TpmtSignature,
    }
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPolicySignedResponse,
    cc: TpmCc::PolicySigned,
    handles: {},
    parameters: {
        pub timeout: Tpm2bTimeout,
        pub policy_ticket: TpmtTkAuth,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicySecretCommand,
    cc: TpmCc::PolicySecret,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub nonce_tpm: Tpm2bNonce,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub expiration: i32,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicySecretResponse,
    cc: TpmCc::PolicySecret,
    handles: {},
    parameters: {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTicketCommand,
    cc: TpmCc::PolicyTicket,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub timeout: Tpm2bTimeout,
        pub cp_hash_a: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub auth_name: Tpm2bName,
        pub ticket: TpmtTkAuth,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTicketResponse,
    cc: TpmCc::PolicyTicket,
    handles: {},
    parameters: {}
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyOrCommand,
    cc: TpmCc::PolicyOR,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub p_hash_list: TpmlDigest,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyOrResponse,
    cc: TpmCc::PolicyOR,
    handles: {},
    parameters: {}
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyPcrCommand,
    cc: TpmCc::PolicyPcr,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub pcr_digest: Tpm2bDigest,
        pub pcrs: TpmlPcrSelection,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPcrResponse,
    cc: TpmCc::PolicyPcr,
    handles: {},
    parameters: {}
);

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyLocalityCommand,
    cc: TpmCc::PolicyLocality,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub locality: TpmaLocality,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyLocalityResponse,
    cc: TpmCc::PolicyLocality,
    handles: {},
    parameters: {}
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyNvCommand,
    cc: TpmCc::PolicyNv,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: u16,
        pub operation: TpmEo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNvResponse,
    cc: TpmCc::PolicyNv,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCounterTimerCommand,
    cc: TpmCc::PolicyCounterTimer,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub operand_b: Tpm2bMaxBuffer,
        pub offset: u16,
        pub operation: TpmEo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCounterTimerResponse,
    cc: TpmCc::PolicyCounterTimer,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    kind: Command,
    name: TpmPolicyCommandCodeCommand,
    cc: TpmCc::PolicyCommandCode,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub code: TpmCc,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCommandCodeResponse,
    cc: TpmCc::PolicyCommandCode,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyPhysicalPresenceCommand,
    cc: TpmCc::PolicyPhysicalPresence,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPhysicalPresenceResponse,
    cc: TpmCc::PolicyPhysicalPresence,
    handles: {},
    parameters: {}
}

tpm_struct! (
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCpHashCommand,
    cc: TpmCc::PolicyCpHash,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub cp_hash_a: Tpm2bDigest,
    }
);

tpm_struct! (
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCpHashResponse,
    cc: TpmCc::PolicyCpHash,
    handles: {},
    parameters: {}
);

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyNameHashCommand,
    cc: TpmCc::PolicyNameHash,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub name_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNameHashResponse,
    cc: TpmCc::PolicyNameHash,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyDuplicationSelectCommand,
    cc: TpmCc::PolicyDuplicationSelect,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub object_name: Tpm2bName,
        pub new_parent_name: Tpm2bName,
        pub include_object: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyDuplicationSelectResponse,
    cc: TpmCc::PolicyDuplicationSelect,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyAuthorizeCommand,
    cc: TpmCc::PolicyAuthorize,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub approved_policy: Tpm2bDigest,
        pub policy_ref: Tpm2bNonce,
        pub key_sign: Tpm2bName,
        pub check_ticket: TpmtTkVerified,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthorizeResponse,
    cc: TpmCc::PolicyAuthorize,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyAuthValueCommand,
    cc: TpmCc::PolicyAuthValue,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthValueResponse,
    cc: TpmCc::PolicyAuthValue,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyPasswordCommand,
    cc: TpmCc::PolicyPassword,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyPasswordResponse,
    cc: TpmCc::PolicyPassword,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    kind: Response,
    name: TpmPolicyGetDigestResponse,
    cc: TpmCc::PolicyGetDigest,
    handles: {},
    parameters: {
        pub policy_digest: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyGetDigestCommand,
    cc: TpmCc::PolicyGetDigest,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyNvWrittenCommand,
    cc: TpmCc::PolicyNvWritten,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub written_set: TpmiYesNo,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyNvWrittenResponse,
    cc: TpmCc::PolicyNvWritten,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTemplateCommand,
    cc: TpmCc::PolicyTemplate,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub template_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTemplateResponse,
    cc: TpmCc::PolicyTemplate,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Command,
    name: TpmPolicyAuthorizeNvCommand,
    cc: TpmCc::PolicyAuthorizeNv,
    handles: {
        pub auth_handle: crate::data::TpmiDhObject,
        pub nv_index: u32,
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyAuthorizeNvResponse,
    cc: TpmCc::PolicyAuthorizeNv,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyCapabilityCommand,
    cc: TpmCc::PolicyCapability,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub capability: TpmCap,
        pub property: u32,
        pub op: TpmEo,
        pub operand_b: Tpm2bMaxBuffer,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyCapabilityResponse,
    cc: TpmCc::PolicyCapability,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyParametersCommand,
    cc: TpmCc::PolicyParameters,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub p_hash: Tpm2bDigest,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyParametersResponse,
    cc: TpmCc::PolicyParameters,
    handles: {},
    parameters: {}
}

tpm_struct! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    kind: Command,
    name: TpmPolicyTransportSpdmCommand,
    cc: TpmCc::PolicyTransportSpdm,
    handles: {
        pub policy_session: crate::data::TpmiShAuthSession,
    },
    parameters: {
        pub req_key_name: Tpm2bName,
        pub tpm_key_name: Tpm2bName,
    }
}

tpm_struct! {
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    kind: Response,
    name: TpmPolicyTransportSpdmResponse,
    cc: TpmCc::PolicyTransportSpdm,
    handles: {},
    parameters: {}
}
