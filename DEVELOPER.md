# Development

## Overview

All commits must follow the conventions presented in the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification, and they must also include a `Signed-off-by` tag as the
trailer.

## Documenting API

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```
