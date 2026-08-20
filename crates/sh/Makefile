# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Opinsys Oy
# Copyright (c) 2025 Jarkko Sakkinen

PREFIX ?= /usr/local
DESTDIR ?=

BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man
MAN1DIR = $(MANDIR)/man1

TARGET = tpm2sh

.PHONY: all build install uninstall clean

all: build

build:
	cargo build --release

install: build
	@echo "Installing $(TARGET) to $(DESTDIR)$(BINDIR)"
	@install -d "$(DESTDIR)$(BINDIR)"
	@install -m 755 "target/release/$(TARGET)" "$(DESTDIR)$(BINDIR)/$(TARGET)"
	@echo "Installing man page to $(DESTDIR)$(MAN1DIR)"
	@install -d "$(DESTDIR)$(MAN1DIR)"
	@install -m 644 "$(TARGET).1" "$(DESTDIR)$(MAN1DIR)/$(TARGET).1"

uninstall:
	@echo "Removing $(TARGET) from $(DESTDIR)$(BINDIR)"
	@rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	@echo "Removing man page from $(DESTDIR)$(MAN1DIR)"
	@rm -f "$(DESTDIR)$(MAN1DIR)/$(TARGET).1"

clean:
	cargo clean
