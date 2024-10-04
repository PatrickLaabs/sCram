# Makefile

CC = gcc
OPTIONS = -std=c11 -I/opt/homebrew/Cellar/openssl@3/3.3.2/include -L/opt/homebrew/Cellar/openssl@3/3.3.2/lib -lssl -lcrypto
CFLAGS = -Wall -Iinclude
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/scram_sha256
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)

all: $(TARGET)

$(TARGET):
	mkdir $(BUILD_DIR)
	$(CC) $(OPTIONS) $(CFLAGS) $(SRC_FILES) -o $(TARGET)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(OPTIONS) $(CFLAGS) -c $< -o $%.o

clean:
	rm -f $(TARGET)
	rm -r $(BUILD_DIR)

.PHONY: all clean
