#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Jarkko Sakkinen

set -euo pipefail

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

ver_gt() {
	if (( $1 > $4 )); then return 0
	elif (( $1 == $4 && $2 > $5 )); then return 0
	elif (( $1 == $4 && $2 == $5 && $3 > $6 )); then return 0
	else return 1
	fi
}

version_parts() {
	[[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
		|| die "invalid version: $1"
	VERSION_A="${BASH_REMATCH[1]}"
	VERSION_B="${BASH_REMATCH[2]}"
	VERSION_C="${BASH_REMATCH[3]}"
}

release_files=(
	Cargo.toml
	Cargo.lock
	crates/sh/tpm2sh.1
)

committed=0
signing_check_tag=""

cleanup() {
	local status=$?

	if [[ -n "$signing_check_tag" ]] \
		&& git rev-parse --verify --quiet "refs/tags/$signing_check_tag" >/dev/null; then
		git tag -d "$signing_check_tag" >/dev/null 2>&1 || true
	fi
	if (( status != 0 && !committed )); then
		git restore --staged -- "${release_files[@]}" 2>/dev/null || true
		git restore -- "${release_files[@]}" 2>/dev/null || true
	fi
	return "$status"
}

trap cleanup EXIT

next_ver="${1:-}"
[[ -n "$next_ver" ]] || die "usage: scripts/release.sh <next-version>"
version_parts "$next_ver"
next_a="$VERSION_A"
next_b="$VERSION_B"
next_c="$VERSION_C"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
	|| die "not inside a Git repository"
cd "$repo_root"

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" \
	|| die "HEAD is detached; check out a branch before releasing"
[[ "$branch" == "main" ]] || die "release from main (on $branch)"
[[ -z "$(git status --porcelain)" ]] \
	|| die "working directory is not clean"
[[ -z "$(git tag -l "$next_ver")" ]] \
	|| die "tag $next_ver already exists"

signing_check_tag="tpm2-library-signing-check-$next_ver-$$"
[[ -z "$(git tag -l "$signing_check_tag")" ]] \
	|| die "temporary signing-check tag already exists: $signing_check_tag"
git tag -s "$signing_check_tag" -m "tpm2-library release signing check" \
	|| die "cannot sign release tags; renew or configure the Git signing key"
git tag -d "$signing_check_tag" >/dev/null
signing_check_tag=""

cur_ver="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' Cargo.toml | head -1)"
[[ -n "$cur_ver" ]] || die "cannot find version in Cargo.toml"
version_parts "$cur_ver"
ver_gt "$next_a" "$next_b" "$next_c" "$VERSION_A" "$VERSION_B" "$VERSION_C" \
	|| die "$next_ver is not greater than current $cur_ver"

log="$(git log --first-parent --format='- %s (%an)' --no-merges "$cur_ver"..HEAD 2>/dev/null || true)"
if [[ -z "$log" ]]; then
	log="$(git log --first-parent --format='- %s (%an)' --no-merges HEAD)"
fi
[[ -n "$log" ]] || log='- No source changes.'

python3 - "$cur_ver" "$next_ver" <<'PY'
import pathlib, re, sys

cur_ver, next_ver = sys.argv[1], sys.argv[2]
path = pathlib.Path("Cargo.toml")
text = path.read_text()
new, n = re.subn(
    rf'(?m)^(version = "){re.escape(cur_ver)}(")$',
    rf'\g<1>{next_ver}\2',
    text,
    count=1,
)
if n != 1:
    raise SystemExit("failed to update workspace.package version")
new, n = re.subn(
    rf'(version = "){re.escape(cur_ver)}(")',
    rf'\g<1>{next_ver}\2',
    new,
)
if n < 1:
    raise SystemExit("failed to update workspace.dependencies versions")
path.write_text(new)
PY

grep -q "^version = \"$next_ver\"" Cargo.toml \
	|| die "failed to update version in Cargo.toml"

man_page="crates/sh/tpm2sh.1"
[[ -f "$man_page" ]] || die "missing man page: $man_page"
date="$(date +%Y-%m-%d)"
sed -i -E "s/^\.TH[[:space:]]+TPM2SH[[:space:]]+1[[:space:]]+\"[^\"]*\"[[:space:]]+\"tpm2sh [^\"]*\"/.TH TPM2SH 1 \"$date\" \"tpm2sh $next_ver\"/" \
	"$man_page"
grep -Eq "^\.TH[[:space:]]+TPM2SH[[:space:]]+1[[:space:]]+\"$date\"[[:space:]]+\"tpm2sh $next_ver\"" "$man_page" \
	|| die "failed to update $man_page"

cargo metadata --format-version 1 >/dev/null
grep -A2 '^name = "tpm2-protocol"' Cargo.lock | grep -q "^version = \"$next_ver\"" \
	|| die "failed to update version in Cargo.lock"

CARGO="${CARGO:-cargo}" ./scripts/ci.sh

git add -- "${release_files[@]}"
git commit -s -m "Bump the version to $next_ver"
committed=1

sob="Signed-off-by: $(git config user.name) <$(git config user.email)>"
release_notes="$(git rev-parse --git-path "tpm2-library-$next_ver-tag-message.txt")"
cat >"$release_notes" <<EOF
tpm2-library $next_ver

$log

$sob
EOF

git tag -s "$next_ver" -F "$release_notes"

printf 'tagged %s\n' "$next_ver"
printf 'push the commit and tag, then publish crates from the bottom of the graph\n'
