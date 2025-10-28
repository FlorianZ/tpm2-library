# tpm2sh

`tpm2sh` is a command-line tool for accessing TPM 2.0 chips.

## Overview

* Git: https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/tpm2sh.git
* Contributions: patches can be submitted to `tpm-protocol@lists.linux.dev`.
* Commits follow the
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  specification.
* New commits must include a `Signed-off-by` trailer.
* Versioning scheme uses [Semantic Versioning](https://semver.org/).

## Development

### Documentation

Inline comments (`//`) are not allowed. Take advantage of either `///` or `//!`
when something needs to be documented to the source code.

Errors are documented with this convention:

```
/// # Errors
///
/// Returns [ErrorName1](crate::module::ErrorEnum::Error1) when <this> happens
/// Returns [ErrorName2](crate::module::ErrorEnum::Error2) when <this> happens
///
```

## Licensing

`tpm2sh` is licensed under the `GPL-3.0-or-later` license.
