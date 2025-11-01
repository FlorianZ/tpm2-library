# TPM 2.0 marshaler/unmarshaler

A unipolar `no_std` TPM 2.0 implementation that does not require heap allocator
and has zero dependencies.

## Development

* Git: https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/tpm2-protocol.git
* Contributions: patches can be submitted to `tpm-protocol@lists.linux.dev`.
* Commits follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  specification.
* New commits should include a `Signed-off-by` trailer.
* Versioning scheme uses [Semantic Versioning](https://semver.org/).

## Mailing List

The list can be subscribed by sending an empty message to
`tpm-protocol+subscribe@lists.linux.dev`, Unsubscribing follows the same exact
pattern except that the subaddress is `+unsubscribe`. With that all out of the
way it is good to remark that the process is relaxed in the sense that opening a
thread in the list, or submitting a patch does not require a subscription.

As already denoted in the previous section, patches and other messages can be
posted to `tpm-protocol@lists.linux.dev`. The mailing list archive is available
at https://lore.kernel.org/tpm-protocol/.

**NOTE**: emails must be in `text/plain`.  format. Emails in any other format,
e.g. `text/html`, will be automatically discarded by the list server, and they
won't appear in the mailing list.

### Build System

The project provides a `Makefile` with `make test` target. The unit test is by
design compiling with GNU make and rustc, and it outputs kselftest compatible
exit codes. This ensures that is code that can be imported to Linux kernel.

## Architecture

`tpm2_protocol` is a low-level and policy-free library for TPM 2.0 command and
response marshaling and unmarshaling.

The primary design goal is to be correct against TCG specifications, and to be
usable in constrained environments.

The correctness is validated to the point that no rules will be introduced that
could be considered as policy. In particular the number of sessions is limited
against `MAX_SESSIONS` but not against number of allowed sessions specified for
a particular command.

## Licensing

The `tpm2-protocol` library is licensed under the permissive `MIT OR Apache-2.0`
license to allow for wide adoption.
