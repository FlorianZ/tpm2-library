// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

use tpm2_protocol::{
    TpmError, TpmField,
    data::{Tpm2bAuth, Tpm2bSensitiveCreateWire, Tpm2bSensitiveData},
};

#[test]
fn nested_views_borrow_original_memory() {
    let buf = [0, 8, 0, 2, 0xaa, 0xbb, 0, 2, 0xcc, 0xdd];

    let wrapper = Tpm2bSensitiveCreateWire::cast(&buf).unwrap();
    let inner = wrapper.inner().unwrap();
    let (user_auth, rest) = <Tpm2bAuth as TpmField>::cast_prefix_field(inner.as_bytes()).unwrap();
    let (data, rest) = <Tpm2bSensitiveData as TpmField>::cast_prefix_field(rest).unwrap();

    assert_eq!(wrapper.as_bytes().as_ptr(), buf.as_ptr());
    assert_eq!(inner.as_bytes().as_ptr(), buf.as_ptr().wrapping_add(2));
    assert_eq!(user_auth.as_bytes().as_ptr(), buf.as_ptr().wrapping_add(2));
    assert_eq!(user_auth.payload().as_ptr(), buf.as_ptr().wrapping_add(4));
    assert_eq!(data.as_bytes().as_ptr(), buf.as_ptr().wrapping_add(6));
    assert_eq!(data.payload().as_ptr(), buf.as_ptr().wrapping_add(8));
    assert!(rest.is_empty());
}

#[test]
fn nested_view_rejects_short_inner_payload() {
    assert!(matches!(
        Tpm2bSensitiveCreateWire::cast(&[0, 7, 0, 2, 0xaa, 0xbb, 0, 2, 0xcc]),
        Err(TpmError::UnexpectedEnd(_))
    ));
}

#[test]
fn nested_view_rejects_inner_trailing_data() {
    assert!(matches!(
        Tpm2bSensitiveCreateWire::cast(&[0, 5, 0, 0, 0, 0, 0xee]),
        Err(TpmError::TrailingData(_))
    ));
}
