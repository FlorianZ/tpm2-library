// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

#[path = "common/message_bytes_by_header.rs"]
mod message_bytes_by_header;

use crate::message_bytes_by_header::message_bytes_by_header;
use tpm2_protocol::{
    TpmError, TpmField,
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bSensitiveCreateWire, Tpm2bSensitiveData,
        TpmCc, TpmsAuthCommand, TpmsAuthResponse,
    },
    frame::{TpmCommandView, TpmResponseView},
};

const MESSAGE_DATA: &str = include_str!("message.txt");

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
        Err(TpmError::UnexpectedEnd { .. })
    ));
}

#[test]
fn nested_view_rejects_inner_trailing_data() {
    assert!(matches!(
        Tpm2bSensitiveCreateWire::cast(&[0, 5, 0, 0, 0, 0, 0xee]),
        Err(TpmError::TrailingData { .. })
    ));
}

#[test]
fn command_view_borrows_handles_sessions_and_parameters() {
    let bytes = message_bytes_by_header(
        MESSAGE_DATA,
        "00000176",
        "Command",
        "0000",
        "8002",
        "0000003f",
    );

    let view = TpmCommandView::cast_frame(&bytes).unwrap();

    assert_eq!(view.cc(), TpmCc::StartAuthSession);

    let command = match view {
        TpmCommandView::StartAuthSession(command) => command,
        _ => panic!("unexpected command view"),
    };
    let handles = command.handles().unwrap();
    let auth_area = command.auth_area().unwrap();
    let parameters = command.parameters().unwrap();
    let (tpm_key, handle_rest) = TpmHandle::cast_prefix(handles).unwrap();
    let (bind, handle_rest) = TpmHandle::cast_prefix(handle_rest).unwrap();
    let (auth, auth_rest) = <TpmsAuthCommand as TpmField>::cast_prefix_field(auth_area).unwrap();
    let (nonce_caller, parameter_rest) =
        <Tpm2bNonce as TpmField>::cast_prefix_field(parameters).unwrap();
    let (encrypted_salt, _) =
        <Tpm2bEncryptedSecret as TpmField>::cast_prefix_field(parameter_rest).unwrap();

    assert_eq!(command.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(handles.as_ptr(), bytes.as_ptr().wrapping_add(10));
    assert_eq!(tpm_key.as_bytes().as_ptr(), bytes.as_ptr().wrapping_add(10));
    assert_eq!(tpm_key.get(), 0x4000_0001);
    assert_eq!(bind.as_bytes().as_ptr(), bytes.as_ptr().wrapping_add(14));
    assert_eq!(bind.get(), 0x4000_0001);
    assert!(handle_rest.is_empty());
    assert_eq!(auth_area.as_ptr(), bytes.as_ptr().wrapping_add(22));
    assert_eq!(auth.as_bytes().as_ptr(), bytes.as_ptr().wrapping_add(22));
    assert_eq!(
        auth.session_handle().unwrap().as_bytes().as_ptr(),
        bytes.as_ptr().wrapping_add(22)
    );
    assert!(auth_rest.is_empty());
    assert_eq!(parameters.as_ptr(), bytes.as_ptr().wrapping_add(38));
    assert_eq!(
        nonce_caller.as_bytes().as_ptr(),
        bytes.as_ptr().wrapping_add(38)
    );
    assert_eq!(
        nonce_caller.payload().as_ptr(),
        bytes.as_ptr().wrapping_add(40)
    );
    assert_eq!(
        encrypted_salt.as_bytes().as_ptr(),
        bytes.as_ptr().wrapping_add(56)
    );
    assert_eq!(handles, &[0x40, 0, 0, 1, 0x40, 0, 0, 1]);
    assert_eq!(
        auth_area,
        &[
            0x40, 0, 0, 9, 0, 0, 0x80, 0, 7, b'a', b'u', b't', b'h', b'1', b'2', b'3'
        ]
    );
    assert_eq!(parameters, &bytes[38..]);
}

#[test]
fn response_view_borrows_handles_sessions_and_parameters() {
    let bytes = message_bytes_by_header(
        MESSAGE_DATA,
        "00000176",
        "Response",
        "0000",
        "8002",
        "00000051",
    );

    let view = TpmResponseView::cast_frame(TpmCc::StartAuthSession, &bytes)
        .unwrap()
        .unwrap();

    assert_eq!(view.cc(), TpmCc::StartAuthSession);

    let response = match view {
        TpmResponseView::StartAuthSession(response) => response,
        _ => panic!("unexpected response view"),
    };
    let body = response.body();
    let (handle, body_rest) = TpmHandle::cast_prefix(body).unwrap();
    let (parameter_size, body_rest) = TpmUint32::cast_prefix(body_rest).unwrap();
    let parameter_size = usize::try_from(parameter_size.get()).unwrap();
    let (parameters, auth_area) = body_rest.split_at(parameter_size);
    let (nonce_tpm, parameter_rest) =
        <Tpm2bNonce as TpmField>::cast_prefix_field(parameters).unwrap();
    let (auth, auth_rest) = <TpmsAuthResponse as TpmField>::cast_prefix_field(auth_area).unwrap();

    assert_eq!(response.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(body.as_ptr(), bytes.as_ptr().wrapping_add(10));
    assert_eq!(handle.as_bytes().as_ptr(), bytes.as_ptr().wrapping_add(10));
    assert_eq!(handle.get(), 0x8002_0000);
    assert_eq!(parameter_size, 18);
    assert_eq!(parameters.as_ptr(), bytes.as_ptr().wrapping_add(18));
    assert_eq!(
        nonce_tpm.as_bytes().as_ptr(),
        bytes.as_ptr().wrapping_add(18)
    );
    assert_eq!(
        nonce_tpm.payload().as_ptr(),
        bytes.as_ptr().wrapping_add(20)
    );
    assert!(parameter_rest.is_empty());
    assert_eq!(auth_area.as_ptr(), bytes.as_ptr().wrapping_add(36));
    assert_eq!(auth.as_bytes().as_ptr(), bytes.as_ptr().wrapping_add(36));
    assert!(auth_rest.is_empty());
    assert_eq!(&body[..4], &[0x80, 2, 0, 0]);
    assert_eq!(&body[4..8], &[0, 0, 0, 18]);
    assert_eq!(&body[8..26], &bytes[18..36]);
    assert_eq!(&body[26..], &bytes[36..]);
}
