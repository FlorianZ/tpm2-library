use std::{cell::RefCell, path::Path, rc::Rc};

use rstest::rstest;
use tpm2_device::{with_device, TpmDevice, TpmDeviceError};

#[rstest]
#[case(TpmDeviceError::AlreadyBorrowed, "device is already borrowed")]
#[case(TpmDeviceError::Interrupted, "operation interrupted by user")]
#[case(TpmDeviceError::InvalidResponse, "invalid response")]
#[case(TpmDeviceError::NotAvailable, "device not available")]
#[case(TpmDeviceError::Timeout, "TPM command timed out")]
#[case(TpmDeviceError::UnexpectedEof, "unexpected EOF")]
fn tpm_device_error_display(#[case] error: TpmDeviceError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

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
            let device = TpmDevice::open(Path::new("/dev/null"), Box::new(|| false))
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
