# tpm2-library

Cargo workspace for the TPM 2.0 protocol crates and `tpm2sh`.

The libraries are a unipolar TPM 2.0 stack: marshal/unmarshal, crypto,
device access, policy language, TPMKey files, and a virtual context
cache. `tpm2sh` is the Linux command-line tool that uses them.

Crate names on crates.io stay `tpm2-*`. Sources live under `crates/`.

## Crates

| Crate | Path | Description | License |
| --- | --- | --- | --- |
| `tpm2-protocol` | [`crates/protocol`](crates/protocol) | `no_std` marshaler/unmarshaler, zero dependencies | MIT OR Apache-2.0 |
| `tpm2-crypto` | [`crates/crypto`](crates/crypto) | TPM 2.0 cryptographic routines | MIT OR Apache-2.0 |
| `tpm2-policy-language` | [`crates/policy-language`](crates/policy-language) | Policy language interpreter | MIT OR Apache-2.0 |
| `tpm2-device` | [`crates/device`](crates/device) | TPM device interface | MIT OR Apache-2.0 |
| `tpm2-tpmkey` | [`crates/tpmkey`](crates/tpmkey) | TPM 2.0 key ASN.1 reader/writer | MIT OR Apache-2.0 |
| `tpm2-vtpm` | [`crates/vtpm`](crates/vtpm) | Virtual TPM context cache | MIT OR Apache-2.0 |
| `tpm2sh` | [`crates/sh`](crates/sh) | Command-line interface for Linux TPM 2.0 devices | GPL-3.0-or-later |

Internal crates depend on each other by path. All crates share one
workspace version.

## Build

```
make
make ci
CI_MSRV=1 make ci
make update
make install
```

`tpm2sh` integration tests need a TPM device and are not run by `make ci`.

## Versioning

- Major versions contain API or ABI breaks.
- Minor versions contain non-exhaustive additive changes.
- Patch versions contain only bug fixes.

The workspace is versioned as a whole. Release with:

```
scripts/release.sh <next-version>
```

Publish to crates.io from the bottom of the dependency graph first:
`tpm2-protocol`, then `tpm2-crypto` and `tpm2-tpmkey`, then
`tpm2-policy-language`, `tpm2-device`, and `tpm2-vtpm`, then `tpm2sh`.

## Submitting patches

Contributions can be submitted as merge requests.

Commit messages should follow simple kernel alike format. Write a clear
summary of the change to the long description.

## Mailing List

For broader discussions there is a mailing list.

The list can be subscribed by sending an empty message to
`tpm-protocol+subscribe@lists.linux.dev`. Unsubscribing follows the same
pattern except that the subaddress is `+unsubscribe`.

Emails must be in `text/plain`.

## Licensing

Library crates are `MIT OR Apache-2.0`. `tpm2sh` is `GPL-3.0-or-later`.
See the `LICENSE*` files in each crate directory.
