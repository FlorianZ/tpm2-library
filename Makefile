# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Jarkko Sakkinen

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
CARGO ?= cargo
INSTALL ?= install

.PHONY: all check ci clippy update install uninstall clean

all:
	$(CARGO) build

check:
	$(CARGO) build
	$(CARGO) clippy --workspace --all-targets

ci:
	CARGO="$(CARGO)" ./scripts/ci.sh

clippy:
	$(CARGO) clippy --workspace --all-targets

update:
	$(CARGO) update

install:
	$(CARGO) build --release -p tpm2sh
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(MANDIR)/man1"
	$(INSTALL) -m 755 target/release/tpm2sh "$(DESTDIR)$(BINDIR)/tpm2sh"
	$(INSTALL) -m 644 crates/sh/tpm2sh.1 "$(DESTDIR)$(MANDIR)/man1/tpm2sh.1"

uninstall:
	$(RM) "$(DESTDIR)$(BINDIR)/tpm2sh"
	$(RM) "$(DESTDIR)$(MANDIR)/man1/tpm2sh.1"

clean:
	$(CARGO) clean
