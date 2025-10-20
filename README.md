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

### Error types

Variant declaration order in error types:

1. Custom variants.
2. Variants for internal module error types.
3. Variants for external module error types.

Within each subcategory variants are ordered alphabetically.

## Licensing

`tpm2sh` is licensed under the `GPL-3.0-or-later` license.
