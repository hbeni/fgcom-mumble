# AFL++ and Mull Fuzzing Guide

## Overview

This guide explains how to use AFL++ (American Fuzzy Lop++) and Mull mutation testing in the FGCom-mumble project. These tools provide comprehensive fuzzing and mutation testing capabilities to discover bugs and evaluate test quality.

## What is Fuzzing?

Fuzzing is an automated testing technique that provides invalid, unexpected, or random data as inputs to a program to find bugs and security vulnerabilities. AFL++ is a state-of-the-art fuzzing tool that uses genetic algorithms to efficiently explore the program's input space.

## What is Mutation Testing?

Mutation testing is a method of evaluating the quality of test suites by introducing small changes (mutations) to the code and checking if the tests catch these changes. Mull is a mutation testing tool that helps identify weak spots in your test coverage.

## AFL++ Integration

### Setup

AFL++ has been integrated into all test modules in the FGCom-mumble project. Each test module now includes:

1. **AFL++ Fuzzing Targets**: Located in `test/fuzzing_tests/afl++/targets/`
2. **CMakeLists.txt Updates**: All test modules include AFL++ build configuration
3. **Fuzzing Scripts**: Automated scripts for building and running fuzzing

### Project Structure

```
test/
├── fuzzing_tests/
│   ├── afl++/
│   │   ├── targets/                    # AFL++ fuzzing targets
│   │   │   ├── fuzz_radio_propagation.cpp
│   │   │   ├── fuzz_audio_processing.cpp
│   │   │   └── fuzz_antenna_patterns.cpp
│   │   └── CMakeLists.txt              # AFL++ build configuration
│   ├── mull/
│   │   ├── targets/                    # Mull mutation testing targets
│   │   └── CMakeLists.txt              # Mull build configuration
│   ├── corpus/                         # Initial test cases
│   ├── outputs/                        # Fuzzing results
│   ├── build_afl_targets.sh           # Build AFL++ targets
│   ├── build_mull_targets.sh          # Build Mull targets
│   ├── run_afl_fuzzing.sh             # Run AFL++ fuzzing
│   ├── run_mull_mutation.sh           # Run Mull mutation testing
│   └── run_all_fuzzing.sh             # Run everything
├── agc_squelch_tests/
│   ├── fuzz_agc_squelch_tests.cpp     # AFL++ fuzzing target
│   ├── mutation_agc_squelch_tests.cpp # Mull mutation testing target
│   └── CMakeLists.txt                 # Updated with fuzzing support
└── ... (all other test modules)
```

## Writing AFL++ Fuzzing Targets

### Basic Structure

```cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>

// Functions to be fuzzed
class MyProcessor {
public:
    static double processData(double input, double param) {
        return input * param;
    }
    
    static bool validateInput(double value) {
        return value >= 0.0 && value <= 100.0;
    }
};

// AFL++ main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    
    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open input file" << std::endl;
        return 1;
    }
    
    // Read input data
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();
    
    if (buffer.size() < 8) {
        return 1; // Need at least 8 bytes
    }
    
    // Extract parameters from input
    double* params = reinterpret_cast<double*>(buffer.data());
    double input = params[0];
    double param = params[1];
    
    // Fuzz the functions
    try {
        double result = MyProcessor::processData(input, param);
        bool valid = MyProcessor::validateInput(input);
        
        // Check for invalid results
        if (std::isnan(result) || std::isinf(result)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
```

### Key Components

1. **Input Reading**: Read binary data from AFL++ input file
2. **Parameter Extraction**: Extract test parameters from input data
3. **Function Execution**: Call the functions to be fuzzed
4. **Result Validation**: Check for invalid results (NaN, infinity, crashes)
5. **Return Codes**: Return 0 for success, 1 for failure/crash

### FGCom-mumble Specific Examples

#### Radio Propagation Fuzzing

```cpp
// Fuzz radio propagation calculations
RC_GTEST_PROP(RadioPropagationTests,
              PathLossIncreasesWithDistance,
              (double frequency_hz, double distance1_m, double distance2_m)) {
    RC_PRE(frequency_hz > 1e6);
    RC_PRE(distance1_m < distance2_m);
    
    double loss1 = calculatePathLoss(frequency_hz, distance1_m);
    double loss2 = calculatePathLoss(frequency_hz, distance2_m);
    
    RC_ASSERT(loss2 > loss1);
}
```

#### Audio Processing Fuzzing

```cpp
// Fuzz audio processing functions
RC_GTEST_PROP(AudioProcessingTests,
              GainApplicationIsLinear,
              (AudioBuffer buffer, float gain_db)) {
    RC_PRE(gain_db >= -60.0f && gain_db <= 60.0f);
    
    AudioBuffer original = buffer;
    applyGain(buffer, gain_db);
    
    float gain_linear = std::pow(10.0f, gain_db / 20.0f);
    for (size_t i = 0; i < buffer.samples.size(); ++i) {
        RC_ASSERT(std::abs(buffer.samples[i].left - 
                          original.samples[i].left * gain_linear) < 1e-6f);
    }
}
```

## Mull Mutation Testing

### Setup

Mull has been integrated into all test modules. Each module includes:

1. **Mutation Testing Targets**: Located in `test/[module]/mutation_[module].cpp`
2. **CMakeLists.txt Updates**: Mull build configuration
3. **Mutation Scripts**: Automated scripts for running mutation testing

### Writing Mutation Testing Targets

```cpp
#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>

// Functions to be mutated
class MyProcessor {
public:
    static double processData(double input, double param) {
        return input * param;  // This will be mutated
    }
    
    static bool validateInput(double value) {
        return value >= 0.0 && value <= 100.0;  // This will be mutated
    }
};

// Unit tests for mutation testing
TEST(MyProcessorTests, DataProcessing) {
    double result = MyProcessor::processData(5.0, 2.0);
    EXPECT_EQ(result, 10.0);
}

TEST(MyProcessorTests, InputValidation) {
    EXPECT_TRUE(MyProcessor::validateInput(50.0));
    EXPECT_FALSE(MyProcessor::validateInput(150.0));
}

// Property-based tests for mutation testing
RC_GTEST_PROP(MyProcessorTests,
              DataProcessingProperty,
              (double input, double param)) {
    RC_PRE(input >= 0.0);
    RC_PRE(param > 0.0);
    
    double result = MyProcessor::processData(input, param);
    RC_ASSERT(result >= 0.0);
    RC_ASSERT(result == input * param);
}
```

## Running Fuzzing and Mutation Testing

### Building Targets

```bash
# Navigate to fuzzing directory
cd test/fuzzing_tests

# Build AFL++ targets
./build_afl_targets.sh

# Build Mull targets
./build_mull_targets.sh

# Or build everything
./run_all_fuzzing.sh
```

### Running AFL++ Fuzzing

```bash
# Run AFL++ fuzzing
./run_afl_fuzzing.sh

# Or run specific targets
afl-fuzz -i corpus/radio_propagation -o outputs/radio_propagation -t 10000 -- ./fuzz_radio_propagation @@
```

### Running Mull Mutation Testing

```bash
# Run Mull mutation testing
./run_mull_mutation.sh

# Or run specific targets
mull-cxx -compilation-flags="-O2 -g" -compilation-database compile_commands.json \
         -reporters=json -reporters=html \
         -output=outputs/mull/mutation_report.json \
         -output=outputs/mull/mutation_report.html
```

### Individual Module Fuzzing

```bash
# Navigate to specific module
cd test/agc_squelch_tests

# Build with fuzzing enabled
mkdir build && cd build
cmake .. -DENABLE_FUZZING=ON
make

# Run AFL++ fuzzing
./fuzz_agc_squelch_tests <input_file>

# Run Mull mutation testing
./mutation_agc_squelch_tests
```

## Fuzzing Results Analysis

### AFL++ Results

AFL++ results are stored in the `outputs/` directory:

```
outputs/
├── radio_propagation/
│   ├── fuzzer_stats          # Fuzzing statistics
│   ├── queue/                # Test cases that found new paths
│   ├── crashes/              # Crashes found
│   └── hangs/                # Hangs found
└── audio_processing/
    ├── fuzzer_stats
    ├── queue/
    ├── crashes/
    └── hangs/
```

### Key Metrics

- **Exec Speed**: Executions per second
- **Cycles Done**: Number of fuzzing cycles completed
- **Unique Crashes**: Number of unique crashes found
- **Unique Hangs**: Number of unique hangs found
- **Total Execs**: Total number of executions

### Analyzing Results

```bash
# View fuzzing statistics
cat outputs/radio_propagation/fuzzer_stats

# Analyze crashes
ls outputs/radio_propagation/crashes/

# Minimize corpus
afl-cmin -i corpus/radio_propagation -o corpus_min/radio_propagation -- ./fuzz_radio_propagation @@

# Generate plots
afl-plot outputs/radio_propagation/radio_propagation_plot
```

## Mull Mutation Testing Results

### Results Format

Mull generates both JSON and HTML reports:

```
outputs/mull/
├── mutation_report.json      # JSON report
└── mutation_report.html      # HTML report
```

### Key Metrics

- **Mutation Score**: Percentage of mutations caught by tests
- **Surviving Mutations**: Mutations not caught by tests
- **Test Coverage**: Coverage analysis
- **Performance**: Execution time metrics

### Analyzing Results

```bash
# View HTML report
firefox outputs/mull/mutation_report.html

# Parse JSON report
python3 -m json.tool outputs/mull/mutation_report.json
```

## Best Practices

### 1. Effective Fuzzing Targets

```cpp
// Good: Comprehensive input validation
int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    
    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) return 1;
    
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();
    
    if (buffer.size() < 8) return 1;
    
    // Extract and validate parameters
    double* params = reinterpret_cast<double*>(buffer.data());
    double input = params[0];
    double param = params[1];
    
    // Check for reasonable bounds
    if (std::isnan(input) || std::isinf(input)) return 1;
    if (std::isnan(param) || std::isinf(param)) return 1;
    
    // Fuzz the function
    try {
        double result = processData(input, param);
        if (std::isnan(result) || std::isinf(result)) return 1;
    } catch (...) {
        return 1;
    }
    
    return 0;
}
```

### 2. Comprehensive Test Cases

```cpp
// Good: Test multiple scenarios
TEST(MyProcessorTests, VariousScenarios) {
    // Normal case
    EXPECT_EQ(processData(5.0, 2.0), 10.0);
    
    // Edge cases
    EXPECT_EQ(processData(0.0, 2.0), 0.0);
    EXPECT_EQ(processData(5.0, 0.0), 0.0);
    
    // Boundary cases
    EXPECT_EQ(processData(100.0, 1.0), 100.0);
}
```

### 3. Property-Based Testing

```cpp
// Good: Test properties that should always hold
RC_GTEST_PROP(MyProcessorTests,
              ResultIsNonNegative,
              (double input, double param)) {
    RC_PRE(input >= 0.0);
    RC_PRE(param >= 0.0);
    
    double result = processData(input, param);
    RC_ASSERT(result >= 0.0);
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Fuzzing and Mutation Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake clang llvm git python3
    
    - name: Setup AFL++
      run: |
        git clone https://github.com/AFLplusplus/AFLplusplus.git
        cd AFLplusplus
        make clean
        make -j$(nproc)
        sudo make install
    
    - name: Setup Mull
      run: |
        git clone https://github.com/mull-project/mull.git
        cd mull
        mkdir build && cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release
        make -j$(nproc)
        sudo make install
    
    - name: Run AFL++ fuzzing
      run: |
        cd test/fuzzing_tests
        ./build_afl_targets.sh
        timeout 300 ./run_afl_fuzzing.sh || true
    
    - name: Run Mull mutation testing
      run: |
        cd test/fuzzing_tests
        ./build_mull_targets.sh
        ./run_mull_mutation.sh
    
    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: fuzzing-results
        path: test/fuzzing_tests/outputs/
```

## Troubleshooting

### Common Issues

1. **AFL++ Not Found**: Ensure AFL++ is properly installed and in PATH
2. **Mull Not Found**: Ensure Mull is properly installed and in PATH
3. **Compilation Errors**: Check that all dependencies are installed
4. **Fuzzing Hangs**: Adjust timeout values in AFL++ configuration
5. **Memory Issues**: Reduce corpus size or increase memory limits

### Debugging

```bash
# Debug AFL++ fuzzing
afl-fuzz -i corpus -o outputs -t 10000 -m 1024 -- ./fuzz_target @@

# Debug Mull mutation testing
mull-cxx -compilation-flags="-O2 -g" -compilation-database compile_commands.json \
         -reporters=console -debug
```

### Performance Optimization

```bash
# Optimize AFL++ performance
export AFL_HARDEN=1
export AFL_USE_ASAN=1
export AFL_USE_MSAN=1
export AFL_USE_UBSAN=1

# Optimize Mull performance
export MULL_WORKERS=4
export MULL_TIMEOUT=300
```

## Conclusion

AFL++ and Mull provide powerful fuzzing and mutation testing capabilities for the FGCom-mumble project. By automatically generating test cases and evaluating test quality, these tools help ensure the robustness and reliability of the radio communication simulation system.

The integration is complete across all test modules, providing comprehensive fuzzing and mutation testing capabilities for the entire project.
