# TPM 2.0 cryptographic routines

## Semantic versions

- Major versions contain API or ABI breaks.
- Minor versions contain non-exhaustive additive changes.
- Patch versions contain only bug fixes.

## Submitting patches

Contributions can be submitted as merge requests.

Commit messages should follow simple kernel alike format. Write a clear summary
of the change to the long description. NOTE: conventional commit messages have
been abandoned despite used in the early development.

## Mailing List

For broader discussions there is a mailing list.

The list can be subscribed by sending an empty message to
`tpm-protocol+subscribe@lists.linux.dev`, Unsubscribing follows the same exact
pattern except that the subaddress is `+unsubscribe`.

Emails must be in `text/plain` (instead of e.g., `text/html`) .

## Documenting errors

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```

## Licensing

The `tpm2-crypto` library is licensed under the permissive `MIT OR Apache-2.0`
license to allow for wide adoption.
