// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};
    use std::{collections::HashMap, fs};
    use tempfile::{tempdir, TempDir};
    use tpm2_crypto::tpm_make_name;
    use tpm2_protocol::{
        basic::TpmBuffer,
        constant::TPM_MAX_COMMAND_SIZE,
        data::{
            Tpm2bDigest, Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmHt, TpmRh, TpmaObject, TpmsContext,
            TpmsRsaParms, TpmtPublic, TpmuPublicId, TpmuPublicParms,
        },
        TpmHandle, TpmMarshal, TpmSized, TpmUnmarshal, TpmWriter,
    };
    use tpm2_vtpm::{
        VtpmCache, VtpmError, VtpmPolicyCommand, VtpmPolicyDefaultCommand, VtpmPolicySecretCommand,
    };

    #[fixture]
    fn cache_dir() -> TempDir {
        tempdir().expect("Failed to create temp directory")
    }

    #[fixture]
    fn test_data() -> (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic) {
        let null_parent = TpmtPublic {
            object_type: TpmAlgId::Null,
            ..Default::default()
        };

        let parent_public = TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                key_bits: 2048,
                ..Default::default()
            }),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
            ..Default::default()
        };

        let child_public = TpmtPublic {
            object_type: TpmAlgId::Rsa,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::USER_WITH_AUTH,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                key_bits: 2048,
                ..Default::default()
            }),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
            ..Default::default()
        };

        let child_context = TpmsContext {
            sequence: 12345,
            saved_handle: TpmHandle(0x8000_0001),
            hierarchy: TpmRh::Owner,
            context_blob: TpmBuffer::try_from(b"\x01\x02\x03\x04\x05" as &[u8]).unwrap(),
        };

        (parent_public, child_public, child_context, null_parent)
    }

    /// Test 1: `cache_lifecycle`
    #[rstest]
    fn cache_lifecycle(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
    ) {
        let (parent_public, child_public, child_context, null_parent) = test_data;
        let cache_path = cache_dir.path();

        let child_policy = Vec::new();

        let mut cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");

        let parent_vhandle = cache
            .save_context(
                TpmsContext {
                    sequence: 0,
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                true,
                &None,
            )
            .expect("Failed to save parent");

        let child_vhandle = cache
            .save_context(
                child_context.clone(),
                &child_public,
                &parent_public,
                false,
                &Some(child_policy),
            )
            .expect("Failed to save child");

        cache.flush().expect("Failed to flush cache");
        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to reload cache");
        assert_eq!(
            cache.key_iter().count(),
            2,
            "Cache did not persist contexts"
        );

        let parent_key = cache
            .find_by_vhandle(parent_vhandle)
            .expect("Failed to find parent by vhandle");
        assert_eq!(parent_key.public, parent_public);

        let child_key = cache
            .find_by_vhandle(child_vhandle)
            .expect("Failed to find child by vhandle");
        assert_eq!(child_key.public, child_public);
        assert_eq!(child_key.context, child_context);

        let child_key_pub = cache
            .find_by_public(&child_public)
            .expect("Failed to find child by public");
        assert_eq!(child_key_pub.handle.0, child_vhandle);

        let child_name = tpm_make_name(&child_public).unwrap();
        let child_key_name = cache
            .find_by_name(&child_name)
            .expect("find_by_name failed")
            .expect("Failed to find child by name");
        assert_eq!(child_key_name.handle.0, child_vhandle);

        let key = cache.find_by_vhandle(child_vhandle).unwrap();
        let policy_bytes = key.policy_into_bytes().unwrap();

        let (count, remainder) =
            u32::unmarshal(&policy_bytes).expect("Failed to unmarshal policy header");
        assert_eq!(count, 0, "Expected empty policy list");
        assert!(
            remainder.is_empty(),
            "Policy encoding has unexpected trailing bytes"
        );

        let chain = cache
            .fetch_ancestor_chain(child_vhandle)
            .expect("Failed to fetch ancestor chain");
        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain[0].value().unwrap(),
            parent_vhandle,
            "Ancestor chain root is incorrect"
        );
        assert_eq!(
            chain[1].value().unwrap(),
            child_vhandle,
            "Ancestor chain target is incorrect"
        );

        drop(cache);
        let mut cache =
            VtpmCache::new(cache_path, HashMap::new()).expect("Failed to reload cache for removal");

        let deleted_handles = cache
            .remove(parent_vhandle)
            .expect("Failed to remove parent");

        assert_eq!(deleted_handles.len(), 2, "Subtree removal failed");
        assert!(deleted_handles.contains(&parent_vhandle));
        assert!(deleted_handles.contains(&child_vhandle));
        assert!(
            cache.key_iter().next().is_none(),
            "Cache was not empty after removal"
        );

        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new())
            .expect("Failed to reload cache after deletion");
        assert!(
            cache.key_iter().next().is_none(),
            "Contexts were not deleted from disk"
        );
    }

    /// Test 2: `cache_allocation`
    #[rstest]
    fn cache_allocation(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
    ) {
        let (parent_public, _, _, null_parent) = test_data;
        let cache_path = cache_dir.path();
        let mut cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");

        let err = cache.find_by_vhandle(0x8000_0000).err().unwrap();
        assert!(matches!(err, VtpmError::HandleNotFound(_)));

        let err = cache.fetch_ancestor_chain(0x8000_0000).err().unwrap();
        assert!(matches!(err, VtpmError::HandleNotFound(_)));

        let h1 = cache
            .save_context(
                TpmsContext {
                    sequence: 0,
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                true,
                &None,
            )
            .expect("Failed to save h1");
        assert_eq!(h1, 0x8000_0000, "First handle was not 0x8000_0000");

        let h2 = cache
            .save_context(
                TpmsContext {
                    sequence: 0,
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                true,
                &None,
            )
            .expect("Failed to save h2");
        assert_eq!(h2, 0x8000_0001, "Second handle was not 0x8000_0001");

        cache.remove(h1).expect("Failed to remove h1");
        assert!(
            cache.find_by_vhandle(h1).is_err(),
            "h1 was not removed from map"
        );

        let h3 = cache
            .save_context(
                TpmsContext {
                    sequence: 0,
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                true,
                &None,
            )
            .expect("Failed to save h3");

        assert_eq!(
            h3, 0x8000_0002,
            "Handle allocation did not resume from the next available slot"
        );
    }

    /// Test 3: `load` handling of stale transient entries
    #[rstest]
    fn load_removes_stale_transient_entries(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let stale_path = cache_path.join("80000000.bin");

        let mut buffer = vec![0u8; u32::SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut buffer);
            let stale_version = 0x0000_0002_u32;
            stale_version
                .marshal(&mut writer)
                .expect("Failed to marshal stale version");
            writer.len()
        };
        buffer.truncate(len);

        fs::write(&stale_path, &buffer).expect("Failed to write stale vtpm file");

        let cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");
        assert!(
            cache.key_iter().next().is_none(),
            "Stale key should not be loaded"
        );
        assert!(
            !stale_path.exists(),
            "Stale vtpm file was not removed from disk"
        );
    }

    /// Test 4: `load` handling of session files (data-driven for HMAC and Policy)
    #[rstest]
    #[case(TpmHt::HmacSession)]
    #[case(TpmHt::PolicySession)]
    fn load_removes_session_files(cache_dir: TempDir, #[case] ht: TpmHt) {
        let cache_path = cache_dir.path();
        let vhandle = (u32::from(ht as u8)) << 24;
        let filename = format!("{vhandle:08x}.bin");
        let file_path = cache_path.join(&filename);

        fs::write(&file_path, b"session").expect("Failed to write session file");

        let cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");
        assert!(
            cache.key_iter().next().is_none(),
            "Session contexts should not be loaded"
        );
        assert!(
            !file_path.exists(),
            "Session file {filename} was not removed from disk"
        );
    }

    /// Test 5: `load` keeps non-transient, non-session files for diagnosis
    #[rstest]
    fn load_keeps_non_transient_non_session_files(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let ht = TpmHt::Permanent as u8;
        let vhandle = (u32::from(ht)) << 24;
        let filename = format!("{vhandle:08x}.bin");
        let file_path = cache_path.join(&filename);

        fs::write(&file_path, b"other").expect("Failed to write test file");

        let cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");
        assert!(
            cache.key_iter().next().is_none(),
            "File should not be loaded as a context"
        );
        assert!(
            file_path.exists(),
            "File with other handle type should be kept"
        );
    }

    /// Test 6: `fetch_ancestor_chain` with persistent root and missing parent (data-driven)
    #[rstest]
    #[case(true)]
    #[case(false)]
    fn fetch_ancestor_chain_with_persistent_root(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
        #[case] has_persistent_parent: bool,
    ) {
        let (parent_public, child_public, child_context, _) = test_data;
        let cache_path = cache_dir.path();

        let mut persistent_keys = HashMap::new();

        if has_persistent_parent {
            let mut buffer = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
            let len = {
                let mut writer = TpmWriter::new(&mut buffer);
                parent_public
                    .marshal(&mut writer)
                    .expect("Failed to marshal parent_public");
                writer.len()
            };
            buffer.truncate(len);

            let persistent_handle = TpmHandle(0x8100_0000);
            persistent_keys.insert(buffer, persistent_handle);
        }

        let mut cache =
            VtpmCache::new(cache_path, persistent_keys).expect("Failed to create cache");

        let child_vhandle = cache
            .save_context(child_context, &child_public, &parent_public, false, &None)
            .expect("Failed to save child context");

        if has_persistent_parent {
            let chain = cache
                .fetch_ancestor_chain(child_vhandle)
                .expect("Failed to fetch ancestor chain with persistent root");
            assert_eq!(chain.len(), 2);
            assert_eq!(
                chain[0].value().unwrap(),
                0x8100_0000,
                "Root of ancestor chain should be persistent handle"
            );
            assert_eq!(
                chain[1].value().unwrap(),
                child_vhandle,
                "Target of ancestor chain should be child handle"
            );
        } else {
            let err = cache
                .fetch_ancestor_chain(child_vhandle)
                .expect_err("Expected fetch_ancestor_chain to fail");
            assert!(matches!(err, VtpmError::ParentNotFound));
        }
    }

    /// Test 7: `remove` on a missing handle returns an empty list
    #[rstest]
    fn remove_nonexistent_handle(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let mut cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");

        let deleted = cache
            .remove(0x8000_0000)
            .expect("remove should succeed for missing handle");
        assert!(
            deleted.is_empty(),
            "No handles should be reported as deleted"
        );
        assert!(
            cache.key_iter().next().is_none(),
            "Cache should remain empty"
        );
    }

    /// Test 8: policies with bodies round-trip via disk
    #[rstest]
    fn policy_roundtrip(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
    ) {
        let (_parent_public, child_public, child_context, null_parent) = test_data;
        let cache_path = cache_dir.path();

        let object_name =
            tpm_make_name(&child_public).expect("Failed to compute object name for policy");
        let policy_ref = Tpm2bDigest::default();

        let policy_secret = VtpmPolicySecretCommand {
            object_handle_hint: TpmHandle(0x8100_0000),
            object_name,
            policy_ref,
        };

        let policy_auth = VtpmPolicyDefaultCommand {
            cc: TpmCc::PolicyAuthValue,
            body: Vec::new(),
        };

        let policy: Vec<Box<dyn VtpmPolicyCommand>> = vec![
            Box::new(policy_auth.clone()),
            Box::new(policy_secret.clone()),
        ];

        let mut cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to create cache");

        let child_vhandle = cache
            .save_context(
                child_context,
                &child_public,
                &null_parent,
                false,
                &Some(policy.clone()),
            )
            .expect("Failed to save child context with policy");

        cache.flush().expect("Failed to flush cache with policy");
        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new()).expect("Failed to reload cache");
        let key = cache
            .find_by_vhandle(child_vhandle)
            .expect("Failed to find child by vhandle after reload");

        assert_eq!(
            key.policy, policy,
            "Policy commands did not round-trip via disk"
        );
    }
}
