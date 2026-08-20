// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

crate::integer!(TpmUint8, u8, 1);
crate::integer!(TpmInt8, i8, 1);
crate::integer!(TpmUint16, u16, 2);
crate::integer!(TpmUint32, u32, 4);
crate::integer!(TpmUint64, u64, 8);
crate::integer!(TpmInt32, i32, 4);

pub type TpmHandle = crate::basic::TpmUint32;
