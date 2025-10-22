# Fuzzing Build Makefile
# Compiles fuzzing targets with libFuzzer

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
FUZZ_FLAGS = -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp
INCLUDES = -I../../client/mumble-plugin/lib -I../../client/mumble-plugin
LIBS = -lm -lpthread

# Fuzzing targets
FUZZ_TARGETS = fuzz_radio_propagation

.PHONY: all clean

all: $(FUZZ_TARGETS)

fuzz_radio_propagation: fuzz_radio_propagation.cpp
	$(CXX) $(CXXFLAGS) $(FUZZ_FLAGS) $(INCLUDES) -o $@ $< $(LIBS)

clean:
	rm -f $(FUZZ_TARGETS) *.o

# Test compilation
test-compile:
	$(CXX) $(CXXFLAGS) -c fuzz_radio_propagation.cpp -o fuzz_test.o $(INCLUDES)

