# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2025 Opinsys Oy
# Copyright (c) 2024-2025 Jarkko Sakkinen

.PHONY: test

TARGET_DIR := target
TARGET := $(TARGET_DIR)/libtpm2_protocol.rlib

# Test programs:
MESSAGE := $(TARGET_DIR)/message_return_code
RETURN_CODE := $(TARGET_DIR)/return_code

test: $(RETURN_CODE) $(MESSAGE)
	@echo "Running kselftests..."
	@./$(MESSAGE)
	@./$(RETURN_CODE)

$(MESSAGE): tests/message.rs tests/message.txt $(TARGET)
	@echo "Compiling test: message..."
	@rustc tests/message.rs --crate-name message_return_code --edition=2024 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(MESSAGE)

$(RETURN_CODE): $(TARGET) tests/return_code.rs
	@echo "Compiling test: return_code..."
	@rustc tests/return_code.rs --crate-name return_code --edition=2024 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(RETURN_CODE)

$(TARGET): $(wildcard src/*.rs)
	@echo "Compiling tpm2-protocol..."
	@mkdir -p $(TARGET_DIR)
	@rustc --crate-type lib --crate-name tpm2_protocol src/lib.rs --edition=2024 --out-dir $(TARGET_DIR)
