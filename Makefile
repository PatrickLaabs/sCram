# Copyright © 2024 Patrick Laabs patrick.laabs@me.com

# Enables shell script tracing. Enable by running: TRACE=1 make <target>
TRACE ?= 0

CC = gcc
OPTIONS = -std=c11 -I/opt/homebrew/Cellar/openssl@3/3.4.1/include -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib -lssl -lcrypto
CFLAGS = -Wall -Iinclude
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/sCram
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } \
	/^[a-zA-Z0-9_-]+:/&&!/##/ { printf "  \033[36m%-30s\033[0m (no description)\n", $$1 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Building binary
	@echo "Building sCram binary..."
	mkdir -p $(BUILD_DIR)
	$(CC) $(OPTIONS) $(CFLAGS) $(SRC_FILES) -o $(TARGET)

.PHONY: clean
clean: ## Cleaning up Build directory
	rm -f $(BUILD_DIR)/*.o $(TARGET)
	rm -rf $(BUILD_DIR)
