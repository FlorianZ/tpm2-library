# tpm2sh

`tpm2sh` is a command-line interface for interacting with TPM 2.0 chips.

## Development

* Git: https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/tpm2sh.git
* Contributions: patches can be submitted to `tpm-protocol@lists.linux.dev`.
* Commits follow the
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  specification.
* New commits must include a `Signed-off-by` trailer.
* Versioning scheme uses [Semantic Versioning](https://semver.org/).

## Architecture

Constraints:

1. Panics are disallowed on new commits, and fixing them is feasible.
2. Nested subcommands are disallowed, as they encourage to inefficient
   subcommand design.

## Licensing

`tpm2sh` is licensed under the `GPL-3.0-or-later` license.
