# Copyright (c) 2025 Opinsys Oy

.PHONY: test

TARGET_DIR := target
TARGET := $(TARGET_DIR)/libtpm2_protocol.rlib
TEST := $(TARGET_DIR)/runner
COMMAND_TEST := $(TARGET_DIR)/command_runner
RESPONSE_TEST := $(TARGET_DIR)/response_runner

test: $(TEST) $(COMMAND_TEST) $(RESPONSE_TEST)
	@echo "Running kselftests..."
	@./$(TEST)
	@echo "Running command tests..."
	@./$(COMMAND_TEST)
	@echo "Running response tests..."
	@./$(RESPONSE_TEST)

$(COMMAND_TEST): tests/command.rs tests/command.txt $(TARGET)
	@echo "Compiling command test runner..."
	@rustc tests/command.rs --crate-name command_runner --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(COMMAND_TEST)

$(RESPONSE_TEST): tests/response.rs tests/response.txt $(TARGET)
	@echo "Compiling response test runner..."
	@rustc tests/response.rs --crate-name response_runner --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(RESPONSE_TEST)

$(TEST): $(TARGET) tests/runner.rs
	@echo "Compiling test runner..."
	@rustc tests/runner.rs --crate-name runner --edition=2021 --extern tpm2_protocol=$(TARGET) -L $(TARGET_DIR) -o $(TEST)

$(TARGET): $(wildcard src/*.rs)
	@echo "Compiling protocol library..."
	@mkdir -p $(TARGET_DIR)
	@rustc --crate-type lib --crate-name tpm2_protocol src/lib.rs --edition=2021 --out-dir $(TARGET_DIR)
