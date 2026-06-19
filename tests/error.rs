use std::{
    cell::{Cell, RefCell},
    path::Path,
    rc::Rc,
};

use rstest::rstest;
use tpm2_device::{TpmDevice, TpmDeviceError, with_device};

#[derive(Debug)]
enum WithDeviceError {
    Device(TpmDeviceError),
}

impl From<TpmDeviceError> for WithDeviceError {
    fn from(err: TpmDeviceError) -> Self {
        WithDeviceError::Device(err)
    }
}

#[derive(Clone, Copy)]
enum WithDeviceCase {
    NoDevice,
    AlreadyBorrowed,
}

#[rstest]
#[case(WithDeviceCase::NoDevice)]
#[case(WithDeviceCase::AlreadyBorrowed)]
fn with_device_errors(#[case] scenario: WithDeviceCase) {
    match scenario {
        WithDeviceCase::NoDevice => {
            let result: Result<(), WithDeviceError> =
                with_device::<_, (), WithDeviceError>(None, |_device| Ok(()));
            assert!(matches!(
                result,
                Err(WithDeviceError::Device(TpmDeviceError::NotAvailable))
            ));
        }
        WithDeviceCase::AlreadyBorrowed => {
            let device = TpmDevice::builder()
                .with_path(Path::new("/dev/null"))
                .build()
                .expect("failed to open /dev/null for TpmDevice");
            let device = Rc::new(RefCell::new(device));
            let _guard = device.borrow_mut();

            let result: Result<(), WithDeviceError> =
                with_device::<_, (), WithDeviceError>(Some(device.clone()), |_device| Ok(()));
            assert!(matches!(
                result,
                Err(WithDeviceError::Device(TpmDeviceError::AlreadyBorrowed))
            ));
        }
    }
}

#[test]
fn with_device_success() {
    let device = TpmDevice::builder()
        .with_path(Path::new("/dev/null"))
        .build()
        .expect("failed to open /dev/null for TpmDevice");
    let device = Rc::new(RefCell::new(device));
    let called = Cell::new(false);

    let result: Result<u32, WithDeviceError> = with_device(Some(device.clone()), |_dev| {
        called.set(true);
        Ok(7)
    });

    assert!(called.get());
    assert!(matches!(result, Ok(7)));
}
