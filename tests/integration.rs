// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2025 Jarkko Sakkinen

use tpm2_device::TpmDevice;

#[test]
fn test_fetch_pcr_bank_list() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut device = TpmDevice::builder()
        .build()
        .expect("Failed to open TPM device");

    let (algs, _mask) = device
        .fetch_pcr_bank_list()
        .expect("Failed to fetch PCR bank list");

    assert!(!algs.is_empty());
}
