// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{data, tpm_dispatch, TpmBuild, TpmList, TpmResult, TpmWriter};
use core::fmt::Debug;

mod asymmetric;
mod attached;
mod attestation;
mod audit;
mod build;
mod capability;
mod clocks_and_timers;
mod context;
mod dictionary_attack;
mod duplication;
mod enhanced_authorization;
mod ephemeral;
mod field_upgrade;
mod hierarchy;
mod integrity;
mod miscellaneous_management;
mod non_volatile;
mod object;
mod parse;
mod random_number;
mod sequence;
mod session;
mod signing;
mod startup;
mod symmetric;
mod testing;
mod vendor;

pub use self::{
    asymmetric::*, attached::*, attestation::*, audit::*, build::*, capability::*,
    clocks_and_timers::*, context::*, dictionary_attack::*, duplication::*,
    enhanced_authorization::*, ephemeral::*, field_upgrade::*, hierarchy::*, integrity::*,
    miscellaneous_management::*, non_volatile::*, object::*, parse::*, random_number::*,
    sequence::*, session::*, signing::*, startup::*, symmetric::*, testing::*, vendor::*,
};

use crate::constant::{MAX_HANDLES, MAX_SESSIONS};

/// A fixed-capacity list for TPM handles.
pub type TpmHandles = TpmList<u32, MAX_HANDLES>;

/// A fixed-capacity list for command authorization sessions.
pub type TpmAuthCommands = TpmList<data::TpmsAuthCommand, MAX_SESSIONS>;

/// A fixed-capacity list for response authorization sessions.
pub type TpmAuthResponses = TpmList<data::TpmsAuthResponse, MAX_SESSIONS>;

/// A trait for TPM commands and responses that provides header information.
pub trait TpmHeader: TpmBuild + Debug {
    const CC: data::TpmCc;
    const HANDLES: usize;

    fn cc(&self) -> data::TpmCc {
        Self::CC
    }
}

/// A trait for building command/response bodies in separate handle and parameter sections.
pub trait TpmBodyBuild {
    /// Builds the handle area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a build failure.
    fn build_handles(&self, writer: &mut TpmWriter) -> TpmResult<()>;

    /// Builds the parameter area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a build failure.
    fn build_parameters(&self, writer: &mut TpmWriter) -> TpmResult<()>;
}

/// Parses a command body from the slices point out to the handle area and
/// parameter area of the original buffer.
pub(crate) trait TpmCommandBodyParse: Sized {
    /// Parses the command body from the handle and parameter area.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a parse failure.
    fn parse_body<'a>(handles: &'a [u8], params: &'a [u8]) -> TpmResult<(Self, &'a [u8])>;
}

/// Parses a response body using the response tag to handle structural variations.
pub trait TpmResponseBodyParse: Sized {
    /// Parses the response body from a buffer, using the response tag
    /// dynamically to determine the structure.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a parse failure.
    fn parse_body(tag: data::TpmSt, buf: &[u8]) -> TpmResult<(Self, &[u8])>;
}

tpm_dispatch! {
    (TpmNvUndefineSpaceSpecialCommand, TpmNvUndefineSpaceSpecialResponse, NvUndefineSpaceSpecial),
    (TpmEvictControlCommand, TpmEvictControlResponse, EvictControl),
    (TpmHierarchyControlCommand, TpmHierarchyControlResponse, HierarchyControl),
    (TpmNvUndefineSpaceCommand, TpmNvUndefineSpaceResponse, NvUndefineSpace),
    (TpmChangeEpsCommand, TpmChangeEpsResponse, ChangeEps),
    (TpmChangePpsCommand, TpmChangePpsResponse, ChangePps),
    (TpmClearCommand, TpmClearResponse, Clear),
    (TpmClearControlCommand, TpmClearControlResponse, ClearControl),
    (TpmClockSetCommand, TpmClockSetResponse, ClockSet),
    (TpmHierarchyChangeAuthCommand, TpmHierarchyChangeAuthResponse, HierarchyChangeAuth),
    (TpmNvDefineSpaceCommand, TpmNvDefineSpaceResponse, NvDefineSpace),
    (TpmPcrAllocateCommand, TpmPcrAllocateResponse, PcrAllocate),
    (TpmPcrSetAuthPolicyCommand, TpmPcrSetAuthPolicyResponse, PcrSetAuthPolicy),
    (TpmPpCommandsCommand, TpmPpCommandsResponse, PpCommands),
    (TpmSetPrimaryPolicyCommand, TpmSetPrimaryPolicyResponse, SetPrimaryPolicy),
    (TpmFieldUpgradeStartCommand, TpmFieldUpgradeStartResponse, FieldUpgradeStart),
    (TpmClockRateAdjustCommand, TpmClockRateAdjustResponse, ClockRateAdjust),
    (TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, CreatePrimary),
    (TpmNvGlobalWriteLockCommand, TpmNvGlobalWriteLockResponse, NvGlobalWriteLock),
    (TpmGetCommandAuditDigestCommand, TpmGetCommandAuditDigestResponse, GetCommandAuditDigest),
    (TpmNvIncrementCommand, TpmNvIncrementResponse, NvIncrement),
    (TpmNvSetBitsCommand, TpmNvSetBitsResponse, NvSetBits),
    (TpmNvExtendCommand, TpmNvExtendResponse, NvExtend),
    (TpmNvWriteCommand, TpmNvWriteResponse, NvWrite),
    (TpmNvWriteLockCommand, TpmNvWriteLockResponse, NvWriteLock),
    (TpmDictionaryAttackLockResetCommand, TpmDictionaryAttackLockResetResponse, DictionaryAttackLockReset),
    (TpmDictionaryAttackParametersCommand, TpmDictionaryAttackParametersResponse, DictionaryAttackParameters),
    (TpmNvChangeAuthCommand, TpmNvChangeAuthResponse, NvChangeAuth),
    (TpmPcrEventCommand, TpmPcrEventResponse, PcrEvent),
    (TpmPcrResetCommand, TpmPcrResetResponse, PcrReset),
    (TpmSequenceCompleteCommand, TpmSequenceCompleteResponse, SequenceComplete),
    (TpmSetAlgorithmSetCommand, TpmSetAlgorithmSetResponse, SetAlgorithmSet),
    (TpmSetCommandCodeAuditStatusCommand, TpmSetCommandCodeAuditStatusResponse, SetCommandCodeAuditStatus),
    (TpmFieldUpgradeDataCommand, TpmFieldUpgradeDataResponse, FieldUpgradeData),
    (TpmIncrementalSelfTestCommand, TpmIncrementalSelfTestResponse, IncrementalSelfTest),
    (TpmSelfTestCommand, TpmSelfTestResponse, SelfTest),
    (TpmStartupCommand, TpmStartupResponse, Startup),
    (TpmShutdownCommand, TpmShutdownResponse, Shutdown),
    (TpmStirRandomCommand, TpmStirRandomResponse, StirRandom),
    (TpmActivateCredentialCommand, TpmActivateCredentialResponse, ActivateCredential),
    (TpmCertifyCommand, TpmCertifyResponse, Certify),
    (TpmPolicyNvCommand, TpmPolicyNvResponse, PolicyNv),
    (TpmCertifyCreationCommand, TpmCertifyCreationResponse, CertifyCreation),
    (TpmDuplicateCommand, TpmDuplicateResponse, Duplicate),
    (TpmGetTimeCommand, TpmGetTimeResponse, GetTime),
    (TpmGetSessionAuditDigestCommand, TpmGetSessionAuditDigestResponse, GetSessionAuditDigest),
    (TpmNvReadCommand, TpmNvReadResponse, NvRead),
    (TpmNvReadLockCommand, TpmNvReadLockResponse, NvReadLock),
    (TpmObjectChangeAuthCommand, TpmObjectChangeAuthResponse, ObjectChangeAuth),
    (TpmPolicySecretCommand, TpmPolicySecretResponse, PolicySecret),
    (TpmRewrapCommand, TpmRewrapResponse, Rewrap),
    (TpmCreateCommand, TpmCreateResponse, Create),
    (TpmEcdhZGenCommand, TpmEcdhZGenResponse, EcdhZGen),
    (TpmHmacCommand, TpmHmacResponse, Hmac),
    (TpmImportCommand, TpmImportResponse, Import),
    (TpmLoadCommand, TpmLoadResponse, Load),
    (TpmQuoteCommand, TpmQuoteResponse, Quote),
    (TpmRsaDecryptCommand, TpmRsaDecryptResponse, RsaDecrypt),
    (TpmHmacStartCommand, TpmHmacStartResponse, HmacStart),
    (TpmSequenceUpdateCommand, TpmSequenceUpdateResponse, SequenceUpdate),
    (TpmSignCommand, TpmSignResponse, Sign),
    (TpmUnsealCommand, TpmUnsealResponse, Unseal),
    (TpmPolicySignedCommand, TpmPolicySignedResponse, PolicySigned),
    (TpmContextLoadCommand, TpmContextLoadResponse, ContextLoad),
    (TpmContextSaveCommand, TpmContextSaveResponse, ContextSave),
    (TpmEcdhKeyGenCommand, TpmEcdhKeyGenResponse, EcdhKeyGen),
    (TpmEncryptDecryptCommand, TpmEncryptDecryptResponse, EncryptDecrypt),
    (TpmFlushContextCommand, TpmFlushContextResponse, FlushContext),
    (TpmLoadExternalCommand, TpmLoadExternalResponse, LoadExternal),
    (TpmMakeCredentialCommand, TpmMakeCredentialResponse, MakeCredential),
    (TpmNvReadPublicCommand, TpmNvReadPublicResponse, NvReadPublic),
    (TpmPolicyAuthorizeCommand, TpmPolicyAuthorizeResponse, PolicyAuthorize),
    (TpmPolicyAuthValueCommand, TpmPolicyAuthValueResponse, PolicyAuthValue),
    (TpmPolicyCommandCodeCommand, TpmPolicyCommandCodeResponse, PolicyCommandCode),
    (TpmPolicyCounterTimerCommand, TpmPolicyCounterTimerResponse, PolicyCounterTimer),
    (TpmPolicyCpHashCommand, TpmPolicyCpHashResponse, PolicyCpHash),
    (TpmPolicyLocalityCommand, TpmPolicyLocalityResponse, PolicyLocality),
    (TpmPolicyNameHashCommand, TpmPolicyNameHashResponse, PolicyNameHash),
    (TpmPolicyOrCommand, TpmPolicyOrResponse, PolicyOr),
    (TpmPolicyTicketCommand, TpmPolicyTicketResponse, PolicyTicket),
    (TpmReadPublicCommand, TpmReadPublicResponse, ReadPublic),
    (TpmRsaEncryptCommand, TpmRsaEncryptResponse, RsaEncrypt),
    (TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, StartAuthSession),
    (TpmVerifySignatureCommand, TpmVerifySignatureResponse, VerifySignature),
    (TpmEccParametersCommand, TpmEccParametersResponse, EccParameters),
    (TpmFirmwareReadCommand, TpmFirmwareReadResponse, FirmwareRead),
    (TpmGetCapabilityCommand, TpmGetCapabilityResponse, GetCapability),
    (TpmGetRandomCommand, TpmGetRandomResponse, GetRandom),
    (TpmGetTestResultCommand, TpmGetTestResultResponse, GetTestResult),
    (TpmHashCommand, TpmHashResponse, Hash),
    (TpmPcrReadCommand, TpmPcrReadResponse, PcrRead),
    (TpmPolicyPcrCommand, TpmPolicyPcrResponse, PolicyPcr),
    (TpmPolicyRestartCommand, TpmPolicyRestartResponse, PolicyRestart),
    (TpmReadClockCommand, TpmReadClockResponse, ReadClock),
    (TpmPcrExtendCommand, TpmPcrExtendResponse, PcrExtend),
    (TpmPcrSetAuthValueCommand, TpmPcrSetAuthValueResponse, PcrSetAuthValue),
    (TpmNvCertifyCommand, TpmNvCertifyResponse, NvCertify),
    (TpmEventSequenceCompleteCommand, TpmEventSequenceCompleteResponse, EventSequenceComplete),
    (TpmHashSequenceStartCommand, TpmHashSequenceStartResponse, HashSequenceStart),
    (TpmPolicyPhysicalPresenceCommand, TpmPolicyPhysicalPresenceResponse, PolicyPhysicalPresence),
    (TpmPolicyDuplicationSelectCommand, TpmPolicyDuplicationSelectResponse, PolicyDuplicationSelect),
    (TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse, PolicyGetDigest),
    (TpmTestParmsCommand, TpmTestParmsResponse, TestParms),
    (TpmCommitCommand, TpmCommitResponse, Commit),
    (TpmPolicyPasswordCommand, TpmPolicyPasswordResponse, PolicyPassword),
    (TpmZGen2PhaseCommand, TpmZGen2PhaseResponse, ZGen2Phase),
    (TpmEcEphemeralCommand, TpmEcEphemeralResponse, EcEphemeral),
    (TpmPolicyNvWrittenCommand, TpmPolicyNvWrittenResponse, PolicyNvWritten),
    (TpmPolicyTemplateCommand, TpmPolicyTemplateResponse, PolicyTemplate),
    (TpmCreateLoadedCommand, TpmCreateLoadedResponse, CreateLoaded),
    (TpmPolicyAuthorizeNvCommand, TpmPolicyAuthorizeNvResponse, PolicyAuthorizeNv),
    (TpmEncryptDecrypt2Command, TpmEncryptDecrypt2Response, EncryptDecrypt2),
    (TpmAcGetCapabilityCommand, TpmAcGetCapabilityResponse, AcGetCapability),
    (TpmAcSendCommand, TpmAcSendResponse, AcSend),
    (TpmPolicyAcSendSelectCommand, TpmPolicyAcSendSelectResponse, PolicyAcSendSelect),
    (TpmActSetTimeoutCommand, TpmActSetTimeoutResponse, ActSetTimeout),
    (TpmPolicyCapabilityCommand, TpmPolicyCapabilityResponse, PolicyCapability),
    (TpmPolicyParametersCommand, TpmPolicyParametersResponse, PolicyParameters),
    (TpmNvDefineSpace2Command, TpmNvDefineSpace2Response, NvDefineSpace2),
    (TpmNvReadPublic2Command, TpmNvReadPublic2Response, NvReadPublic2),
    (TpmReadOnlyControlCommand, TpmReadOnlyControlResponse, ReadOnlyControl),
    (TpmPolicyTransportSpdmCommand, TpmPolicyTransportSpdmResponse, PolicyTransportSpdm),
    (TpmVendorTcgTestCommand, TpmVendorTcgTestResponse, VendorTcgTest),
}

impl TpmCommandBody {
    /// Builds a command body into a writer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a build failure.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        &self,
        tag: crate::data::TpmSt,
        sessions: &TpmAuthCommands,
        writer: &mut TpmWriter,
    ) -> TpmResult<()> {
        match self {
            Self::NvUndefineSpaceSpecial(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EvictControl(c) => tpm_build_command(c, tag, sessions, writer),
            Self::HierarchyControl(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvUndefineSpace(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ChangeEps(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ChangePps(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Clear(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ClearControl(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ClockSet(c) => tpm_build_command(c, tag, sessions, writer),
            Self::HierarchyChangeAuth(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvDefineSpace(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrAllocate(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrSetAuthPolicy(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PpCommands(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SetPrimaryPolicy(c) => tpm_build_command(c, tag, sessions, writer),
            Self::FieldUpgradeStart(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ClockRateAdjust(c) => tpm_build_command(c, tag, sessions, writer),
            Self::CreatePrimary(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvGlobalWriteLock(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetCommandAuditDigest(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvIncrement(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvSetBits(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvExtend(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvWrite(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvWriteLock(c) => tpm_build_command(c, tag, sessions, writer),
            Self::DictionaryAttackLockReset(c) => tpm_build_command(c, tag, sessions, writer),
            Self::DictionaryAttackParameters(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvChangeAuth(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrEvent(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrReset(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SequenceComplete(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SetAlgorithmSet(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SetCommandCodeAuditStatus(c) => tpm_build_command(c, tag, sessions, writer),
            Self::FieldUpgradeData(c) => tpm_build_command(c, tag, sessions, writer),
            Self::IncrementalSelfTest(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SelfTest(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Startup(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Shutdown(c) => tpm_build_command(c, tag, sessions, writer),
            Self::StirRandom(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ActivateCredential(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Certify(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyNv(c) => tpm_build_command(c, tag, sessions, writer),
            Self::CertifyCreation(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Duplicate(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetTime(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetSessionAuditDigest(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvRead(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvReadLock(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ObjectChangeAuth(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicySecret(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Rewrap(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Create(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EcdhZGen(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Hmac(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Import(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Load(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Quote(c) => tpm_build_command(c, tag, sessions, writer),
            Self::RsaDecrypt(c) => tpm_build_command(c, tag, sessions, writer),
            Self::HmacStart(c) => tpm_build_command(c, tag, sessions, writer),
            Self::SequenceUpdate(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Sign(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Unseal(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicySigned(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ContextLoad(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ContextSave(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EcdhKeyGen(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EncryptDecrypt(c) => tpm_build_command(c, tag, sessions, writer),
            Self::FlushContext(c) => tpm_build_command(c, tag, sessions, writer),
            Self::LoadExternal(c) => tpm_build_command(c, tag, sessions, writer),
            Self::MakeCredential(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvReadPublic(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyAuthorize(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyAuthValue(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyCommandCode(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyCounterTimer(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyCpHash(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyLocality(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyNameHash(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyOr(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyTicket(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ReadPublic(c) => tpm_build_command(c, tag, sessions, writer),
            Self::RsaEncrypt(c) => tpm_build_command(c, tag, sessions, writer),
            Self::StartAuthSession(c) => tpm_build_command(c, tag, sessions, writer),
            Self::VerifySignature(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EccParameters(c) => tpm_build_command(c, tag, sessions, writer),
            Self::FirmwareRead(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetCapability(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetRandom(c) => tpm_build_command(c, tag, sessions, writer),
            Self::GetTestResult(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Hash(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrRead(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyPcr(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyRestart(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ReadClock(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrExtend(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PcrSetAuthValue(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvCertify(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EventSequenceComplete(c) => tpm_build_command(c, tag, sessions, writer),
            Self::HashSequenceStart(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyPhysicalPresence(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyDuplicationSelect(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyGetDigest(c) => tpm_build_command(c, tag, sessions, writer),
            Self::TestParms(c) => tpm_build_command(c, tag, sessions, writer),
            Self::Commit(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyPassword(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ZGen2Phase(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EcEphemeral(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyNvWritten(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyTemplate(c) => tpm_build_command(c, tag, sessions, writer),
            Self::CreateLoaded(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyAuthorizeNv(c) => tpm_build_command(c, tag, sessions, writer),
            Self::EncryptDecrypt2(c) => tpm_build_command(c, tag, sessions, writer),
            Self::AcGetCapability(c) => tpm_build_command(c, tag, sessions, writer),
            Self::AcSend(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyAcSendSelect(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ActSetTimeout(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyCapability(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyParameters(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvDefineSpace2(c) => tpm_build_command(c, tag, sessions, writer),
            Self::NvReadPublic2(c) => tpm_build_command(c, tag, sessions, writer),
            Self::ReadOnlyControl(c) => tpm_build_command(c, tag, sessions, writer),
            Self::PolicyTransportSpdm(c) => tpm_build_command(c, tag, sessions, writer),
            Self::VendorTcgTest(c) => tpm_build_command(c, tag, sessions, writer),
        }
    }
}

impl TpmResponseBody {
    /// Builds a response body into a writer.
    ///
    /// # Errors
    ///
    /// Returns `Err(TpmErrorKind)` on a build failure.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        &self,
        rc: crate::data::TpmRc,
        sessions: &TpmAuthResponses,
        writer: &mut TpmWriter,
    ) -> TpmResult<()> {
        match self {
            Self::NvUndefineSpaceSpecial(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EvictControl(r) => tpm_build_response(r, sessions, rc, writer),
            Self::HierarchyControl(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvUndefineSpace(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ChangeEps(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ChangePps(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Clear(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ClearControl(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ClockSet(r) => tpm_build_response(r, sessions, rc, writer),
            Self::HierarchyChangeAuth(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvDefineSpace(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrAllocate(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrSetAuthPolicy(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PpCommands(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SetPrimaryPolicy(r) => tpm_build_response(r, sessions, rc, writer),
            Self::FieldUpgradeStart(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ClockRateAdjust(r) => tpm_build_response(r, sessions, rc, writer),
            Self::CreatePrimary(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvGlobalWriteLock(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetCommandAuditDigest(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvIncrement(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvSetBits(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvExtend(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvWrite(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvWriteLock(r) => tpm_build_response(r, sessions, rc, writer),
            Self::DictionaryAttackLockReset(r) => tpm_build_response(r, sessions, rc, writer),
            Self::DictionaryAttackParameters(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvChangeAuth(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrEvent(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrReset(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SequenceComplete(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SetAlgorithmSet(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SetCommandCodeAuditStatus(r) => tpm_build_response(r, sessions, rc, writer),
            Self::FieldUpgradeData(r) => tpm_build_response(r, sessions, rc, writer),
            Self::IncrementalSelfTest(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SelfTest(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Startup(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Shutdown(r) => tpm_build_response(r, sessions, rc, writer),
            Self::StirRandom(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ActivateCredential(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Certify(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyNv(r) => tpm_build_response(r, sessions, rc, writer),
            Self::CertifyCreation(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Duplicate(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetTime(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetSessionAuditDigest(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvRead(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvReadLock(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ObjectChangeAuth(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicySecret(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Rewrap(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Create(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EcdhZGen(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Hmac(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Import(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Load(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Quote(r) => tpm_build_response(r, sessions, rc, writer),
            Self::RsaDecrypt(r) => tpm_build_response(r, sessions, rc, writer),
            Self::HmacStart(r) => tpm_build_response(r, sessions, rc, writer),
            Self::SequenceUpdate(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Sign(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Unseal(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicySigned(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ContextLoad(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ContextSave(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EcdhKeyGen(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EncryptDecrypt(r) => tpm_build_response(r, sessions, rc, writer),
            Self::FlushContext(r) => tpm_build_response(r, sessions, rc, writer),
            Self::LoadExternal(r) => tpm_build_response(r, sessions, rc, writer),
            Self::MakeCredential(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvReadPublic(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyAuthorize(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyAuthValue(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyCommandCode(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyCounterTimer(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyCpHash(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyLocality(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyNameHash(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyOr(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyTicket(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ReadPublic(r) => tpm_build_response(r, sessions, rc, writer),
            Self::RsaEncrypt(r) => tpm_build_response(r, sessions, rc, writer),
            Self::StartAuthSession(r) => tpm_build_response(r, sessions, rc, writer),
            Self::VerifySignature(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EccParameters(r) => tpm_build_response(r, sessions, rc, writer),
            Self::FirmwareRead(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetCapability(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetRandom(r) => tpm_build_response(r, sessions, rc, writer),
            Self::GetTestResult(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Hash(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrRead(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyPcr(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyRestart(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ReadClock(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrExtend(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PcrSetAuthValue(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvCertify(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EventSequenceComplete(r) => tpm_build_response(r, sessions, rc, writer),
            Self::HashSequenceStart(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyPhysicalPresence(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyDuplicationSelect(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyGetDigest(r) => tpm_build_response(r, sessions, rc, writer),
            Self::TestParms(r) => tpm_build_response(r, sessions, rc, writer),
            Self::Commit(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyPassword(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ZGen2Phase(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EcEphemeral(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyNvWritten(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyTemplate(r) => tpm_build_response(r, sessions, rc, writer),
            Self::CreateLoaded(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyAuthorizeNv(r) => tpm_build_response(r, sessions, rc, writer),
            Self::EncryptDecrypt2(r) => tpm_build_response(r, sessions, rc, writer),
            Self::AcGetCapability(r) => tpm_build_response(r, sessions, rc, writer),
            Self::AcSend(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyAcSendSelect(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ActSetTimeout(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyCapability(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyParameters(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvDefineSpace2(r) => tpm_build_response(r, sessions, rc, writer),
            Self::NvReadPublic2(r) => tpm_build_response(r, sessions, rc, writer),
            Self::ReadOnlyControl(r) => tpm_build_response(r, sessions, rc, writer),
            Self::PolicyTransportSpdm(r) => tpm_build_response(r, sessions, rc, writer),
            Self::VendorTcgTest(r) => tpm_build_response(r, sessions, rc, writer),
        }
    }
}
