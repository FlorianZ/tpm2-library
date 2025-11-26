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
        basic::{TpmBuffer, TpmHandle, TpmUint16, TpmUint32, TpmUint64},
        data::{
            Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmHt, TpmRh, TpmaObject,
            TpmsContext, TpmsRsaParms, TpmtPublic, TpmuPublicId, TpmuPublicParms,
        },
    };
    use tpm2_vtpm::{
        VtpmCache, VtpmError, VtpmPolicyCommand, VtpmPolicyDefaultCommand, VtpmPolicySecretCommand,
    };

    #[fixture]
    fn cache_dir() -> TempDir {
        tempdir().unwrap()
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
                key_bits: TpmUint16(2048),
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
                key_bits: TpmUint16(2048),
                ..Default::default()
            }),
            unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default()),
            ..Default::default()
        };

        let child_context = TpmsContext {
            sequence: TpmUint64(12345),
            saved_handle: TpmUint32(0x8000_0001),
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

        let mut cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        let parent_vhandle = cache
            .save_key(
                TpmsContext {
                    sequence: TpmUint64(0),
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                &None,
            )
            .unwrap();

        let child_vhandle = cache
            .save_key(
                child_context.clone(),
                &child_public,
                &parent_public,
                &Some(child_policy),
            )
            .unwrap();

        cache.flush().unwrap();
        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();
        assert_eq!(cache.key_iter().count(), 2,);

        let parent_key = cache.find_by_handle(TpmUint32(parent_vhandle)).unwrap();
        assert_eq!(*parent_key.public(), parent_public);

        let child_key = cache.find_by_handle(TpmUint32(child_vhandle)).unwrap();
        assert_eq!(*child_key.public(), child_public);
        assert_eq!(*child_key.context(), child_context);

        let child_name = tpm_make_name(&child_public).unwrap();
        let child_key_name = cache.find_by_name(&child_name).unwrap();
        assert_eq!(child_key_name.handle().value(), child_vhandle);

        let chain = cache.fetch_ancestors(TpmUint32(child_vhandle)).unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].0, parent_vhandle,);
        assert_eq!(chain[1].0, child_vhandle,);

        drop(cache);
        let mut cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        let deleted_handles = cache.remove(parent_vhandle).unwrap();

        assert_eq!(deleted_handles.len(), 2);
        assert!(deleted_handles.contains(&parent_vhandle));
        assert!(deleted_handles.contains(&child_vhandle));
        assert!(cache.key_iter().next().is_none(),);

        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        assert!(cache.key_iter().next().is_none(),);
    }

    /// Test 2: `cache_allocation`
    #[rstest]
    fn cache_allocation(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
    ) {
        let (parent_public, _, _, null_parent) = test_data;
        let cache_path = cache_dir.path();
        let mut cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        let err = cache.find_by_handle(TpmUint32(0x8000_0000));
        assert!(err.is_none());

        let err = cache.fetch_ancestors(TpmUint32(0x8000_0000)).err().unwrap();
        assert!(matches!(err, VtpmError::HandleNotFound(_)));

        let h1 = cache
            .save_key(
                TpmsContext {
                    sequence: TpmUint64(0),
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                &None,
            )
            .unwrap();
        assert_eq!(h1, 0x8000_0000);

        let h2 = cache
            .save_key(
                TpmsContext {
                    sequence: TpmUint64(0),
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                &None,
            )
            .unwrap();
        assert_eq!(h2, 0x8000_0001);

        cache.remove(h1).unwrap();
        assert!(cache.find_by_handle(TpmUint32(h1)).is_none(),);

        let h3 = cache
            .save_key(
                TpmsContext {
                    sequence: TpmUint64(0),
                    saved_handle: TpmHandle::default(),
                    hierarchy: TpmRh::default(),
                    context_blob: TpmBuffer::default(),
                },
                &parent_public,
                &null_parent,
                &None,
            )
            .unwrap();

        assert_eq!(h3, 0x8000_0002,);
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

        fs::write(&file_path, b"session").unwrap();

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        assert!(cache.key_iter().next().is_none(),);

        assert!(!file_path.exists(),);
    }

    /// Test 5: `load` keeps non-transient, non-session files for diagnosis
    #[rstest]
    fn load_keeps_non_transient_non_session_files(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let ht = TpmHt::Permanent as u8;
        let vhandle = (u32::from(ht)) << 24;
        let filename = format!("{vhandle:08x}.bin");
        let file_path = cache_path.join(&filename);

        fs::write(&file_path, b"other").unwrap();

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        assert!(cache.key_iter().next().is_none(),);

        assert!(file_path.exists(),);
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
            let parent_name = tpm_make_name(&parent_public).unwrap();
            persistent_keys.insert(parent_name, TpmUint32(0x8100_0000));
        }

        let mut cache = VtpmCache::new(cache_path, persistent_keys).unwrap();

        let child_vhandle = cache
            .save_key(child_context, &child_public, &parent_public, &None)
            .unwrap();

        if has_persistent_parent {
            let chain = cache.fetch_ancestors(TpmUint32(child_vhandle)).unwrap();
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].0, 0x8100_0000,);
            assert_eq!(chain[1].0, child_vhandle,);
        } else {
            let err = cache.fetch_ancestors(TpmUint32(child_vhandle)).unwrap_err();
            assert!(matches!(err, VtpmError::ParentNotFound));
        }
    }

    /// Test 6b: `new` validates persistent handles
    #[rstest]
    fn new_validates_persistent_handles(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let mut handles = HashMap::new();
        handles.insert(Tpm2bName::default(), TpmUint32(0x8000_0000));

        let err = VtpmCache::new(cache_path, handles).unwrap_err();

        assert!(matches!(err, VtpmError::InvalidHandleType(_)));
    }

    /// Test 7: `remove` on a missing handle returns an empty list
    #[rstest]
    fn remove_nonexistent_handle(cache_dir: TempDir) {
        let cache_path = cache_dir.path();
        let mut cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        let deleted = cache.remove(0x8000_0000).unwrap();
        assert!(deleted.is_empty(),);
        assert!(cache.key_iter().next().is_none(),);
    }

    /// Test 8: policies with bodies round-trip via disk
    #[rstest]
    fn policy_roundtrip(
        cache_dir: TempDir,
        test_data: (TpmtPublic, TpmtPublic, TpmsContext, TpmtPublic),
    ) {
        let (_parent_public, child_public, child_context, null_parent) = test_data;
        let cache_path = cache_dir.path();

        let object_name = tpm_make_name(&child_public).unwrap();
        let policy_ref = Tpm2bDigest::default();

        let policy_secret = VtpmPolicySecretCommand {
            object_handle_hint: TpmUint32(0x8100_0000),
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

        let mut cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();

        let child_vhandle = cache
            .save_key(
                child_context,
                &child_public,
                &null_parent,
                &Some(policy.clone()),
            )
            .unwrap();

        cache.flush().unwrap();
        drop(cache);

        let cache = VtpmCache::new(cache_path, HashMap::new()).unwrap();
        let key = cache.find_by_handle(TpmUint32(child_vhandle)).unwrap();

        assert_eq!(*key.policy(), policy);
    }
}
