# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2025 Opinsys Oy
# Copyright (c) 2024-2025 Jarkko Sakkinen

.PHONY: test

TARGET_DIR := target
TARGET := $(TARGET_DIR)/libtpm2_protocol.rlib
TEST := $(TARGET_DIR)/adhoc
MESSAGE_TEST := $(TARGET_DIR)/message_adhoc

test: $(TEST) $(MESSAGE_TEST)
	@echo "Running kselftests..."
	@./$(TEST)
	@echo "Running message tests..."
	@./$(MESSAGE_TEST)

$(MESSAGE_TEST): tests/message.rs tests/message.txt $(TARGET)
	@echo "Compiling message test adhoc..."
	@rustc tests/message.rs --crate-name message_adhoc --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(MESSAGE_TEST)

$(TEST): $(TARGET) tests/adhoc.rs
	@echo "Compiling test adhoc..."
	@rustc tests/adhoc.rs --crate-name adhoc --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(TEST)

$(TARGET): $(wildcard src/*.rs)
	@echo "Compiling protocol library..."
	@mkdir -p $(TARGET_DIR)
	@rustc --crate-type lib --crate-name tpm2_protocol src/lib.rs --edition=2021 --out-dir $(TARGET_DIR)
