# TPM 2.0 library crate

A unipolar `no_std` TPM 2.0 implementation that does not require heap allocator
and has zero dependencies.

## Development

* Patches and discussion: tpm-protocol@lists.linux.dev
  * Archive: https://lore.kernel.org/tpm-protocol/
* Commits: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  specification.
* New commits should include a `Signed-off-by` trailer.
* Versioning: [Semantic Versioning](https://semver.org/).

### Build System

The project provides a `Makefile` with `make test` target. The unit test is by
design compiling with GNU make and rustc, and it outputs kselftest compatible
exit codes. This ensures that is code that can be imported to Linux kernel.

## Architecture

`tpm2_protocol` is a low-level and policy-free library for TPM 2.0 command and
response building and parsing.

The primary design goal is to be correct against TCG specifications, and to be
usable in constrained environments.

The correctness is validated to the point that no rules will be introduced that
could be considered as policy. In particular the number of sessions is limited
against `MAX_SESSIONS` but not against number of allowed sessions specified for
a particular command.

## Licensing

The `tpm2-protocol` library is licensed under the permissive `MIT OR Apache-2.0`
license to allow for wide adoption.
