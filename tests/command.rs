// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::{io::IsTerminal, panic, vec::Vec};
use tpm2_protocol::{
    message::{tpm_build_command, tpm_parse_command, TpmCommandBody},
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};

const COMMAND_DATA: &str = include_str!("command.txt");

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("invalid hex size");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "invalid hex character")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_ok() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[32mOK\x1B[0m");
    } else {
        println!("OK");
    }
}

fn print_failed() {
    if std::io::stderr().is_terminal() {
        println!("\x1B[31mFAILED\x1B[0m");
    } else {
        println!("FAILED");
    }
}

fn run_test(name: &str, test_fn: impl FnOnce() + panic::UnwindSafe) -> bool {
    print!("Test {name} ... ");
    let result = panic::catch_unwind(test_fn);
    if result.is_err() {
        print_failed();
        false
    } else {
        print_ok();
        true
    }
}

fn main() {
    let mut failed_count = 0;
    let mut test_count = 0;

    for (i, line) in COMMAND_DATA.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        test_count += 1;
        let test_name = format!("command_{}", i + 1);
        let success = run_test(&test_name, || {
            let original_bytes = hex_to_bytes(trimmed).unwrap();
            let (_handles, body, sessions) = tpm_parse_command(&original_bytes).unwrap();

            let mut built_bytes = [0u8; TPM_MAX_COMMAND_SIZE];
            let built_len = {
                let mut writer = TpmWriter::new(&mut built_bytes);
                let tag = if sessions.is_empty() {
                    tpm2_protocol::data::TpmSt::NoSessions
                } else {
                    tpm2_protocol::data::TpmSt::Sessions
                };

                let cmd_struct = match body {
                    TpmCommandBody::NvUndefineSpaceSpecial(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EvictControl(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::HierarchyControl(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvUndefineSpace(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ChangeEps(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ChangePps(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Clear(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::ClearControl(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ClockSet(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::HierarchyChangeAuth(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvDefineSpace(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrAllocate(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrSetAuthPolicy(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PpCommands(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SetPrimaryPolicy(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::FieldUpgradeStart(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ClockRateAdjust(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::CreatePrimary(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvGlobalWriteLock(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetCommandAuditDigest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvIncrement(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvSetBits(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvExtend(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvWrite(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvWriteLock(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::DictionaryAttackLockReset(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::DictionaryAttackParameters(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvChangeAuth(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrEvent(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrReset(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SequenceComplete(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SetAlgorithmSet(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SetCommandCodeAuditStatus(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::FieldUpgradeData(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::IncrementalSelfTest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SelfTest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Startup(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Shutdown(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::StirRandom(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ActivateCredential(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Certify(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyNv(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::CertifyCreation(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Duplicate(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetTime(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetSessionAuditDigest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvRead(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::NvReadLock(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ObjectChangeAuth(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicySecret(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Rewrap(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::Create(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::EcdhZGen(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Hmac(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::Import(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::Load(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::Quote(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::RsaDecrypt(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::HmacStart(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::SequenceUpdate(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Sign(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::Unseal(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::PolicySigned(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ContextLoad(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ContextSave(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EcdhKeyGen(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EncryptDecrypt(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::FlushContext(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::LoadExternal(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::MakeCredential(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvReadPublic(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyAuthorize(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyAuthValue(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyCommandCode(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyCounterTimer(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyCpHash(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyLocality(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyNameHash(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyOr(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyTicket(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ReadPublic(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::RsaEncrypt(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::StartAuthSession(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::VerifySignature(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EccParameters(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::FirmwareRead(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetCapability(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetRandom(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::GetTestResult(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Hash(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::PcrRead(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyPcr(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyRestart(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ReadClock(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrExtend(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PcrSetAuthValue(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvCertify(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EventSequenceComplete(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::HashSequenceStart(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyPhysicalPresence(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyDuplicationSelect(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyGetDigest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::TestParms(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::Commit(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::PolicyPassword(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ZGen2Phase(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EcEphemeral(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyNvWritten(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyTemplate(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::CreateLoaded(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyAuthorizeNv(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::EncryptDecrypt2(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::AcGetCapability(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::AcSend(c) => tpm_build_command(&c, tag, &sessions, &mut writer),
                    TpmCommandBody::PolicyAcSendSelect(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ActSetTimeout(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyCapability(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyParameters(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvDefineSpace2(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::NvReadPublic2(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::ReadOnlyControl(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::PolicyTransportSpdm(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                    TpmCommandBody::VendorTcgTest(c) => {
                        tpm_build_command(&c, tag, &sessions, &mut writer)
                    }
                };

                cmd_struct.unwrap();
                writer.len()
            };
            let rebuilt_slice = &built_bytes[..built_len];

            assert_eq!(
                rebuilt_slice,
                original_bytes.as_slice(),
                "\nOriginal: {}\nRebuilt:  {}\n",
                bytes_to_hex(&original_bytes),
                bytes_to_hex(rebuilt_slice)
            );
        });
        if !success {
            failed_count += 1;
        }
    }

    eprintln!("\n{test_count} tests run.");
    if failed_count > 0 {
        eprintln!("{failed_count} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("All tests passed.");
}
