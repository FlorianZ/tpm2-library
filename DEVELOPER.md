# Development

## Documentation

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
