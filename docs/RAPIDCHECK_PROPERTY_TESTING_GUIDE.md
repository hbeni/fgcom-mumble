# RapidCheck Property-Based Testing Guide

## Overview

This guide explains how to use RapidCheck for property-based testing in the FGCom-mumble project. Property-based testing is a powerful testing methodology that automatically generates test cases and verifies that certain properties hold for all possible inputs.

## What is Property-Based Testing?

Property-based testing differs from traditional unit testing in that instead of writing specific test cases, you write properties that should hold for all valid inputs. RapidCheck automatically generates thousands of test cases and verifies that your properties are always true.

### Benefits

- **Comprehensive Coverage**: Tests millions of possible inputs automatically
- **Bug Discovery**: Finds edge cases and boundary conditions you might miss
- **Documentation**: Properties serve as executable documentation
- **Regression Prevention**: Catches regressions across all possible inputs

## RapidCheck Integration

### Setup

RapidCheck has been integrated into all test modules in the FGCom-mumble project. Each test module now includes:

1. **RapidCheck Library**: Located in `test/rapidcheck_tests/lib/rapidcheck/`
2. **CMakeLists.txt Updates**: All test modules include RapidCheck in their build configuration
3. **Property Test Files**: Each module has a `test_[module]_properties.cpp` file

### Project Structure

```
test/
├── rapidcheck_tests/
│   ├── lib/rapidcheck/          # RapidCheck library
│   ├── CMakeLists.txt           # RapidCheck build configuration
│   ├── test_radio_propagation_properties.cpp
│   ├── test_audio_processing_properties.cpp
│   └── test_antenna_pattern_properties.cpp
├── agc_squelch_tests/
│   ├── test_agc_squelch_properties.cpp
│   └── CMakeLists.txt           # Updated with RapidCheck
├── frequency_management_tests/
│   ├── test_frequency_management_properties.cpp
│   └── CMakeLists.txt           # Updated with RapidCheck
└── ... (all other test modules)
```

## Writing Property-Based Tests

### Basic Structure

```cpp
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <gtest/gtest.h>

// Property-based test
RC_GTEST_PROP(TestSuiteName,
              PropertyName,
              (InputType1 param1, InputType2 param2)) {
    // Preconditions
    RC_PRE(param1 > 0);
    RC_PRE(param2 != nullptr);
    
    // Test logic
    auto result = functionUnderTest(param1, param2);
    
    // Assertions
    RC_ASSERT(result >= 0);
    RC_ASSERT(result < 1000);
}
```

### Key Components

1. **RC_GTEST_PROP**: Macro for defining property-based tests
2. **RC_PRE**: Preconditions that must be true for the test to run
3. **RC_ASSERT**: Assertions that must be true for the property to hold
4. **Custom Generators**: Define how to generate test data for custom types

### Example: Radio Propagation Properties

```cpp
RC_GTEST_PROP(RadioPropagationTests,
              PathLossIncreasesWithDistance,
              (double frequency_hz, double distance1_m, double distance2_m)) {
    RC_PRE(frequency_hz > 1e6); // At least 1 MHz
    RC_PRE(distance1_m > 0);
    RC_PRE(distance2_m > 0);
    RC_PRE(distance1_m < distance2_m);
    
    double loss1 = calculatePathLoss(frequency_hz, distance1_m);
    double loss2 = calculatePathLoss(frequency_hz, distance2_m);
    
    RC_ASSERT(loss2 > loss1);
}
```

## Custom Data Generators

### Basic Generators

```cpp
// Primitive types
gen::inRange(0, 100)           // Integer in range
gen::inRange(0.0, 100.0)       // Double in range
gen::arbitrary<bool>()         // Boolean
gen::arbitrary<std::string>()  // String

// Containers
gen::container<std::vector<int>>(
    gen::inRange(1, 10),       // Size range
    gen::inRange(0, 100)        // Element generator
)
```

### Custom Type Generators

```cpp
// Define custom generator for your types
namespace rc {
    template<>
    struct Arbitrary<MyCustomType> {
        static Gen<MyCustomType> arbitrary() {
            return gen::construct<MyCustomType>(
                gen::inRange(0.0, 100.0),      // field1
                gen::arbitrary<std::string>(),  // field2
                gen::arbitrary<bool>()         // field3
            );
        }
    };
}
```

## Property Categories

### 1. Mathematical Properties

```cpp
// Commutativity: a + b = b + a
RC_GTEST_PROP(MathTests, AdditionIsCommutative, (double a, double b)) {
    RC_ASSERT(add(a, b) == add(b, a));
}

// Associativity: (a + b) + c = a + (b + c)
RC_GTEST_PROP(MathTests, AdditionIsAssociative, (double a, double b, double c)) {
    RC_ASSERT(add(add(a, b), c) == add(a, add(b, c)));
}
```

### 2. Bounds and Invariants

```cpp
// Result is always positive
RC_GTEST_PROP(ProcessingTests, ResultIsPositive, (InputData input)) {
    auto result = process(input);
    RC_ASSERT(result >= 0.0);
}

// Output size is bounded
RC_GTEST_PROP(ProcessingTests, OutputSizeIsBounded, (InputData input)) {
    auto result = process(input);
    RC_ASSERT(result.size() <= MAX_SIZE);
}
```

### 3. Idempotency

```cpp
// Applying function twice gives same result
RC_GTEST_PROP(ProcessingTests, FunctionIsIdempotent, (InputData input)) {
    auto result1 = process(input);
    auto result2 = process(result1);
    RC_ASSERT(result1 == result2);
}
```

### 4. Monotonicity

```cpp
// Function is monotonic
RC_GTEST_PROP(ProcessingTests, FunctionIsMonotonic, (double x1, double x2)) {
    RC_PRE(x1 < x2);
    auto y1 = process(x1);
    auto y2 = process(x2);
    RC_ASSERT(y1 <= y2);
}
```

## FGCom-mumble Specific Properties

### Radio Propagation Properties

```cpp
// Path loss increases with distance
RC_GTEST_PROP(RadioPropagationTests,
              PathLossIncreasesWithDistance,
              (double frequency_hz, double distance1_m, double distance2_m)) {
    RC_PRE(frequency_hz > 1e6);
    RC_PRE(distance1_m < distance2_m);
    
    double loss1 = calculatePathLoss(frequency_hz, distance1_m);
    double loss2 = calculatePathLoss(frequency_hz, distance2_m);
    
    RC_ASSERT(loss2 > loss1);
}

// Frequency-dependent rain effects
RC_GTEST_PROP(RadioPropagationTests,
              HigherFrequenciesMoreAffectedByRain,
              (double frequency1_hz, double frequency2_hz, 
               AtmosphericConditions conditions)) {
    RC_PRE(frequency1_hz < frequency2_hz);
    RC_PRE(conditions.rain_rate_mmh > 0);
    
    double attenuation1 = calculateRainAttenuation(frequency1_hz, conditions);
    double attenuation2 = calculateRainAttenuation(frequency2_hz, conditions);
    
    RC_ASSERT(attenuation2 > attenuation1);
}
```

### Audio Processing Properties

```cpp
// Gain application is linear
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

### Antenna Pattern Properties

```cpp
// Maximum gain is largest
RC_GTEST_PROP(AntennaPatternTests,
              MaximumGainIsLargest,
              (AntennaPattern3D pattern)) {
    RC_PRE(!pattern.points.empty());
    
    double max_gain = getMaximumGain(pattern);
    
    for (const auto& point : pattern.points) {
        RC_ASSERT(point.gain_db <= max_gain);
    }
}
```

## Running Property-Based Tests

### Building Tests

```bash
# Navigate to test module
cd test/agc_squelch_tests

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build tests
make
```

### Running Tests

```bash
# Run all tests (including property-based)
./agc_squelch_tests

# Run with verbose output
./agc_squelch_tests --verbose

# Run with specific seed (for reproducible results)
./agc_squelch_tests --seed=12345

# Run only property-based tests
./agc_squelch_tests --gtest_filter="*Properties*"
```

### Test Output

```
[==========] Running 150 tests from 8 test suites.
[----------] Global test environment set-up.
[----------] 1 test from AGCProcessorTests
[ RUN      ] AGCProcessorTests.AGCGainIsBounded
[       OK ] AGCProcessorTests.AGCGainIsBounded (1000 ms)
[----------] 1 test from AGCProcessorTests (1000 ms total)

[----------] 1 test from RadioPropagationTests
[ RUN      ] RadioPropagationTests.PathLossIncreasesWithDistance
[       OK ] RadioPropagationTests.PathLossIncreasesWithDistance (2000 ms)
[----------] 1 test from RadioPropagationTests (2000 ms total)

[----------] Global test environment tear-down
[==========] 150 tests from 8 test suites ran. (15000 ms total)
[  PASSED  ] 150 tests.
```

## Best Practices

### 1. Write Clear Properties

```cpp
// Good: Clear property name and logic
RC_GTEST_PROP(AudioTests, CompressionReducesPeakLevel, 
              (AudioBuffer buffer, float threshold, float ratio)) {
    float original_peak = calculatePeak(buffer);
    applyCompression(buffer, threshold, ratio);
    float compressed_peak = calculatePeak(buffer);
    
    RC_ASSERT(compressed_peak <= original_peak);
}

// Bad: Unclear property
RC_GTEST_PROP(AudioTests, TestCompression, (AudioBuffer buffer)) {
    // Vague test logic
}
```

### 2. Use Appropriate Preconditions

```cpp
// Good: Specific preconditions
RC_GTEST_PROP(ProcessingTests, ValidInputs, (InputData input)) {
    RC_PRE(input.value >= 0.0);
    RC_PRE(input.value <= 100.0);
    RC_PRE(!input.name.empty());
    
    auto result = process(input);
    RC_ASSERT(result.isValid());
}

// Bad: No preconditions or too restrictive
RC_GTEST_PROP(ProcessingTests, AllInputs, (InputData input)) {
    // No preconditions - might fail on invalid inputs
    auto result = process(input);
    RC_ASSERT(result.isValid());
}
```

### 3. Test Edge Cases

```cpp
// Test boundary conditions
RC_GTEST_PROP(MathTests, DivisionByZero, (double numerator)) {
    RC_PRE(numerator != 0.0);
    
    // This should not crash
    auto result = safeDivide(numerator, 0.0);
    RC_ASSERT(std::isinf(result) || std::isnan(result));
}
```

### 4. Use Custom Generators for Complex Types

```cpp
// Define realistic generators
namespace rc {
    template<>
    struct Arbitrary<RadioFrequency> {
        static Gen<RadioFrequency> arbitrary() {
            return gen::construct<RadioFrequency>(
                gen::inRange(30e6, 300e6),      // VHF range
                gen::element<std::string>("Aviation", "Maritime", "Amateur"),
                gen::inRange(0.0, 100.0)        // power
            );
        }
    };
}
```

## Debugging Failed Properties

### Shrinking

When a property fails, RapidCheck automatically shrinks the input to find the minimal failing case:

```
Falsifiable after 1 test:
std::tuple<double, double, double>:
(0.0, 0.0, 0.0)

The property failed for input: (0.0, 0.0, 0.0)
```

### Reproducing Failures

```cpp
// Use specific seed to reproduce failures
RC_GTEST_PROP(MyTests, MyProperty, (int x, int y)) {
    // Set seed for reproducible results
    rc::detail::setGlobalSeed(12345);
    
    RC_ASSERT(x + y == y + x);
}
```

### Verbose Output

```bash
# Run with verbose output to see generated values
./tests --verbose
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Property-Based Tests
on: [push, pull_request]

jobs:
  property-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake libgtest-dev
    
    - name: Build and run property-based tests
      run: |
        cd test/agc_squelch_tests
        mkdir build && cd build
        cmake ..
        make
        ./agc_squelch_tests --gtest_filter="*Properties*"
```

## Performance Considerations

### Test Execution Time

- Property-based tests run longer than unit tests
- Each property runs 100-1000 test cases by default
- Use `RC_PRE` to filter out invalid inputs early
- Consider running property tests separately from unit tests

### Memory Usage

- RapidCheck generates many test cases
- Monitor memory usage for large test suites
- Use appropriate container sizes in generators

## Troubleshooting

### Common Issues

1. **Compilation Errors**: Ensure RapidCheck is properly linked
2. **Test Failures**: Check preconditions and assertions
3. **Performance**: Reduce test case count if needed
4. **Memory**: Use smaller test data generators

### Getting Help

- RapidCheck Documentation: https://github.com/emil-e/rapidcheck
- FGCom-mumble Issues: Create GitHub issue with property test details
- Community: Join FGCom-mumble Discord for discussions

## Conclusion

Property-based testing with RapidCheck provides comprehensive test coverage for the FGCom-mumble project. By writing properties that should hold for all valid inputs, we can catch bugs that traditional unit tests might miss and ensure the robustness of our radio communication simulation system.

The integration is complete across all test modules, providing a solid foundation for reliable software development.
