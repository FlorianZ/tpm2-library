# Development

## Overview

Commits should follow loosely kernel commit style i.e. subsystem tag followed by
short summary, and then long description.

## Documenting API

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```
