#!/bin/sh

# SPDX-License-Identifier: GPL-3-0-or-later
# Copyright (c) 2024-2025 Jarkko Sakkinen
# Copyright (c) 2025 Opinsys Oy

set -e

PREVIOUS="${1:-$PREV}"
NEXT="${2:-$NEXT}"

if [ -z "$NEXT" ] || [ -z "$PREVIOUS" ]; then
  echo "Usage: $0 <PREVIOUS> <NEXT>"
  exit 1
fi

if git status --porcelain | grep .; then
  echo "Working directory $PWD is not clean"
  exit 1
fi

if grep "^version = $NEXT" Cargo.toml >/dev/null; then
  echo "Version $NEXT is already set"
fi

sed -i "s/^version =.*/version = \"$NEXT\"/g" Cargo.toml
cargo clippy --all-targets

git commit -a -s -m "chore: bump version to $NEXT"

MESSAGE=$(
  echo "tpm-vtpm $NEXT"
  echo ""
  git log --pretty=format:"- %s" --no-merges "$PREVIOUS..HEAD"
)

printf "%s" "$MESSAGE" | git tag -s "$NEXT" -F -
