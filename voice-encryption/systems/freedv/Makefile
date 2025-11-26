# Makefile for FreeDV Encryption Test
# Author: FGcom-mumble Development Team
# Date: 2025

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
INCLUDES = -I./include
SOURCES = src/freedv.cpp src/chacha20_poly1305.cpp
HEADERS = include/freedv.h include/chacha20_poly1305.h
TEST_SOURCE = test_freedv_encryption.cpp
TEST_TARGET = test_freedv_encryption

.PHONY: all clean test

all: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCE) $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(TEST_SOURCE) $(SOURCES)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TEST_TARGET)

install: $(TEST_TARGET)
	@echo "FreeDV encryption test compiled successfully"
	@echo "Run './$(TEST_TARGET)' to test encryption functionality"
