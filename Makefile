# Makefile

CC = gcc
OPTIONS = -std=c11 -I/opt/homebrew/Cellar/openssl@3/3.4.0/include -L/opt/homebrew/Cellar/openssl@3/3.4.0/lib -lssl -lcrypto
CFLAGS = -Wall -Iinclude
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/scram_sha256
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)

all: $(TARGET)

$(TARGET):
	mkdir -p $(BUILD_DIR)
	$(CC) $(OPTIONS) $(CFLAGS) $(SRC_FILES) -o $(TARGET)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(OPTIONS) $(CFLAGS) -c $< -o $(BUILD_DIR)/$*.o

clean:
	rm -f $(BUILD_DIR)/*.o $(TARGET)
	rm -rf $(BUILD_DIR)

.PHONY: all clean $(TARGET)
