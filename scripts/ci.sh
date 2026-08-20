#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

CARGO="${CARGO:-cargo}"

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_command "$CARGO"
require_command git

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
	|| die "not inside a Git repository"
cd "$repo_root"

printf '==> cargo build\n'
$CARGO build --workspace --locked

printf '==> cargo test\n'
$CARGO test --workspace --locked --all-targets --exclude tpm2sh
$CARGO test -p tpm2sh --locked --bins

printf '==> cargo clippy\n'
$CARGO clippy --workspace --all-targets --locked

printf '==> cargo fmt --check\n'
$CARGO fmt --check

if [[ -n "${CI_MSRV:-}" ]]; then
	version="$(sed -n 's/^rust-version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml)"
	[[ -n "$version" ]] || die "no rust-version in Cargo.toml"
	printf '==> MSRV cargo +%s\n' "$version"
	require_command rustup
	rustup toolchain install "$version"
	cargo +"$version" build --workspace --locked
	cargo +"$version" test --workspace --locked --all-targets --exclude tpm2sh
	cargo +"$version" test -p tpm2sh --locked --bins
fi

printf 'local CI passed\n'
