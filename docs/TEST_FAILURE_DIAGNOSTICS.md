# Test Failure Diagnostics

## Overview

This document provides comprehensive guidance on creating informative test failures that help developers quickly identify and fix issues. Well-written test failures include context, expected values, actual values, and diagnostic suggestions.

## Best Practices for Test Failures

### 1. Include Context Information

```cpp
TEST(Radio, TransmissionRange) {
    double frequency = 118.5;
    double altitude = 10000;
    double range = calculate_range(frequency, altitude);
    
    ASSERT_GT(range, 150.0) 
        << "Range too short!\n"
        << "  Calculated: " << range << " nm\n"
        << "  Expected: > 150 nm\n"
        << "  Frequency: " << frequency << " MHz\n"
        << "  Altitude: " << altitude << " ft\n"
        << "  This might indicate: power calculation error, "
        << "atmospheric absorption too high, or antenna gain incorrect";
}
```

### 2. Provide Diagnostic Suggestions

```cpp
TEST(Audio, SignalQuality) {
    double snr = calculate_signal_to_noise_ratio(input_signal, noise_floor);
    
    ASSERT_GT(snr, 20.0)
        << "Signal-to-noise ratio too low!\n"
        << "  Calculated SNR: " << snr << " dB\n"
        << "  Expected SNR: > 20 dB\n"
        << "  Input signal level: " << input_signal << " dBm\n"
        << "  Noise floor: " << noise_floor << " dBm\n"
        << "  Possible causes:\n"
        << "    - Transmitter power too low\n"
        << "    - Receiver sensitivity too low\n"
        << "    - Interference from other sources\n"
        << "    - Antenna gain insufficient\n"
        << "    - Atmospheric conditions affecting propagation";
}
```

### 3. Include Calculation Details

```cpp
TEST(Propagation, PathLoss) {
    double frequency = 2.4e9;
    double distance = 1000;
    double path_loss = calculate_path_loss(frequency, distance);
    
    ASSERT_LT(path_loss, 120.0)
        << "Path loss too high!\n"
        << "  Calculated path loss: " << path_loss << " dB\n"
        << "  Expected path loss: < 120 dB\n"
        << "  Frequency: " << frequency / 1e9 << " GHz\n"
        << "  Distance: " << distance << " m\n"
        << "  Free space path loss: " << calculate_free_space_path_loss(frequency, distance) << " dB\n"
        << "  Additional attenuation: " << (path_loss - calculate_free_space_path_loss(frequency, distance)) << " dB\n"
        << "  Check: atmospheric conditions, terrain effects, antenna heights";
}
```

## Comprehensive Test Failure Examples

### Radio Propagation Tests

```cpp
TEST(RadioPropagation, WeatherImpact) {
    WeatherConditions clear_weather = {20.0, 50.0, 0.0, 0.0, 0.0};
    WeatherConditions rain_weather = {15.0, 95.0, 25.0, 0.0, 0.0};
    
    double clear_range = calculate_range(118.5e6, clear_weather);
    double rain_range = calculate_range(118.5e6, rain_weather);
    
    ASSERT_GT(clear_range, rain_range)
        << "Weather should reduce radio range!\n"
        << "  Clear weather range: " << clear_range << " km\n"
        << "  Rain weather range: " << rain_range << " km\n"
        << "  Range reduction: " << (clear_range - rain_range) << " km\n"
        << "  Frequency: 118.5 MHz (VHF)\n"
        << "  Rain rate: 25 mm/h\n"
        << "  Expected: VHF should be minimally affected by rain\n"
        << "  If range reduction > 10%, check:\n"
        << "    - Rain attenuation calculation\n"
        << "    - Frequency dependence implementation\n"
        << "    - Weather effect scaling factors";
}

TEST(RadioPropagation, FrequencyDependence) {
    std::vector<double> frequencies = {118.5e6, 225e6, 2.4e9, 10e9};
    std::vector<std::string> freq_names = {"VHF", "UHF", "2.4GHz", "10GHz"};
    
    for (size_t i = 0; i < frequencies.size(); ++i) {
        double range = calculate_range(frequencies[i], clear_weather);
        
        ASSERT_GT(range, 0.0)
            << "Range calculation failed for " << freq_names[i] << "!\n"
            << "  Frequency: " << frequencies[i] / 1e6 << " MHz\n"
            << "  Calculated range: " << range << " km\n"
            << "  Expected: > 0 km\n"
            << "  Check: frequency-dependent calculations\n"
            << "    - Base range calculation\n"
            << "    - Atmospheric attenuation\n"
            << "    - Antenna gain factors\n"
            << "    - Power budget calculations";
    }
}
```

### Audio Processing Tests

```cpp
TEST(AudioProcessing, GainApplication) {
    AudioBuffer input_buffer = create_test_buffer(0.5, 1000);
    double gain_db = 6.0;
    
    apply_gain(input_buffer, gain_db);
    double output_level = calculate_rms(input_buffer);
    double expected_level = 0.5 * std::pow(10.0, gain_db / 20.0);
    
    ASSERT_NEAR(output_level, expected_level, 0.01)
        << "Gain application incorrect!\n"
        << "  Input level: 0.5\n"
        << "  Gain: " << gain_db << " dB\n"
        << "  Expected output: " << expected_level << "\n"
        << "  Actual output: " << output_level << "\n"
        << "  Difference: " << std::abs(output_level - expected_level) << "\n"
        << "  Check: gain calculation, linear/logarithmic conversion\n"
        << "    - Gain formula: output = input * 10^(gain_db/20)\n"
        << "    - Buffer processing\n"
        << "    - Floating point precision";
}

TEST(AudioProcessing, Compression) {
    AudioBuffer input_buffer = create_test_buffer(0.8, 1000);
    double threshold = -10.0;
    double ratio = 4.0;
    
    apply_compression(input_buffer, threshold, ratio);
    double output_level = calculate_rms(input_buffer);
    
    ASSERT_LT(output_level, 0.8)
        << "Compression not working!\n"
        << "  Input level: 0.8\n"
        << "  Threshold: " << threshold << " dB\n"
        << "  Ratio: " << ratio << ":1\n"
        << "  Output level: " << output_level << "\n"
        << "  Expected: output < input (compression)\n"
        << "  Check: compression algorithm\n"
        << "    - Threshold detection\n"
        << "    - Ratio application\n"
        << "    - Attack/release times\n"
        << "    - Makeup gain";
}
```

### Frequency Management Tests

```cpp
TEST(FrequencyManagement, ChannelSeparation) {
    double freq1 = 118.5e6;
    double freq2 = 118.525e6;
    double min_separation = 25e3;
    
    double separation = std::abs(freq1 - freq2);
    bool compliant = separation >= min_separation;
    
    ASSERT_TRUE(compliant)
        << "Channel separation insufficient!\n"
        << "  Frequency 1: " << freq1 / 1e6 << " MHz\n"
        << "  Frequency 2: " << freq2 / 1e6 << " MHz\n"
        << "  Separation: " << separation / 1e3 << " kHz\n"
        << "  Minimum required: " << min_separation / 1e3 << " kHz\n"
        << "  Difference: " << (min_separation - separation) / 1e3 << " kHz\n"
        << "  Check: frequency allocation algorithm\n"
        << "    - Channel spacing calculation\n"
        << "    - Adjacent channel protection\n"
        << "    - Interference calculations";
}

TEST(FrequencyManagement, InterferenceDetection) {
    Radio radio1(118.5e6, 25.0);
    Radio radio2(118.525e6, 25.0);
    
    radio1.transmit(20.0);
    double interference = radio2.measure_interference(radio1);
    
    ASSERT_LT(interference, -40.0)
        << "Adjacent channel interference too high!\n"
        << "  Transmitter frequency: 118.5 MHz\n"
        << "  Receiver frequency: 118.525 MHz\n"
        << "  Channel separation: 25 kHz\n"
        << "  Interference level: " << interference << " dB\n"
        << "  Expected: < -40 dB\n"
        << "  Transmitter power: 20 dBm\n"
        << "  Check: interference calculation\n"
        << "    - Frequency separation factor\n"
        << "    - Power level scaling\n"
        << "    - Bandwidth considerations\n"
        << "    - Antenna pattern effects";
}
```

### Weather Impact Tests

```cpp
TEST(WeatherImpact, RainAttenuation) {
    double frequency = 10e9;
    double rain_rate = 25.0;
    double attenuation = calculate_rain_attenuation(frequency, rain_rate);
    
    ASSERT_GT(attenuation, 0.0)
        << "Rain attenuation calculation failed!\n"
        << "  Frequency: " << frequency / 1e9 << " GHz\n"
        << "  Rain rate: " << rain_rate << " mm/h\n"
        << "  Calculated attenuation: " << attenuation << " dB\n"
        << "  Expected: > 0 dB (rain should cause attenuation)\n"
        << "  Check: rain attenuation model\n"
        << "    - ITU-R P.838-3 implementation\n"
        << "    - Frequency dependence\n"
        << "    - Rain rate scaling\n"
        << "    - Atmospheric conditions";
}

TEST(WeatherImpact, FrequencyDependence) {
    std::vector<double> frequencies = {118.5e6, 225e6, 2.4e9, 10e9};
    double rain_rate = 25.0;
    
    for (size_t i = 0; i < frequencies.size() - 1; ++i) {
        double att1 = calculate_rain_attenuation(frequencies[i], rain_rate);
        double att2 = calculate_rain_attenuation(frequencies[i+1], rain_rate);
        
        ASSERT_GT(att2, att1)
            << "Rain attenuation should increase with frequency!\n"
            << "  Frequency 1: " << frequencies[i] / 1e6 << " MHz\n"
            << "  Frequency 2: " << frequencies[i+1] / 1e6 << " MHz\n"
            << "  Attenuation 1: " << att1 << " dB\n"
            << "  Attenuation 2: " << att2 << " dB\n"
            << "  Difference: " << (att2 - att1) << " dB\n"
            << "  Rain rate: " << rain_rate << " mm/h\n"
            << "  Check: frequency dependence implementation\n"
            << "    - Higher frequencies should have more attenuation\n"
            << "    - Rain drop size vs. wavelength relationship\n"
            << "    - Scattering calculations";
    }
}
```

### Antenna Pattern Tests

```cpp
TEST(AntennaPattern, GainCalculation) {
    AntennaPattern pattern = load_antenna_pattern("dipole.txt");
    double azimuth = 0.0;
    double elevation = 0.0;
    
    double gain = pattern.get_gain(azimuth, elevation);
    
    ASSERT_GT(gain, 0.0)
        << "Antenna gain calculation failed!\n"
        << "  Azimuth: " << azimuth << " degrees\n"
        << "  Elevation: " << elevation << " degrees\n"
        << "  Calculated gain: " << gain << " dBi\n"
        << "  Expected: > 0 dBi\n"
        << "  Check: antenna pattern data\n"
        << "    - Pattern file format\n"
        << "    - Interpolation algorithm\n"
        << "    - Coordinate system\n"
        << "    - Gain units (dBi vs dBd)";
}

TEST(AntennaPattern, Symmetry) {
    AntennaPattern pattern = load_antenna_pattern("dipole.txt");
    double azimuth = 45.0;
    double elevation = 0.0;
    
    double gain1 = pattern.get_gain(azimuth, elevation);
    double gain2 = pattern.get_gain(-azimuth, elevation);
    
    ASSERT_NEAR(gain1, gain2, 0.1)
        << "Antenna pattern not symmetric!\n"
        << "  Azimuth 1: " << azimuth << " degrees\n"
        << "  Azimuth 2: " << -azimuth << " degrees\n"
        << "  Elevation: " << elevation << " degrees\n"
        << "  Gain 1: " << gain1 << " dBi\n"
        << "  Gain 2: " << gain2 << " dBi\n"
        << "  Difference: " << std::abs(gain1 - gain2) << " dBi\n"
        << "  Expected: < 0.1 dBi difference\n"
        << "  Check: antenna pattern symmetry\n"
        << "    - Pattern data quality\n"
        << "    - Interpolation consistency\n"
        << "    - Coordinate system alignment";
}
```

### Network Protocol Tests

```cpp
TEST(NetworkProtocol, MessageParsing) {
    std::string message = "FREQ:118.5,PWR:25.0,GAIN:3.0";
    RadioMessage parsed = parse_radio_message(message);
    
    ASSERT_EQ(parsed.frequency, 118.5e6)
        << "Frequency parsing failed!\n"
        << "  Message: " << message << "\n"
        << "  Parsed frequency: " << parsed.frequency / 1e6 << " MHz\n"
        << "  Expected frequency: 118.5 MHz\n"
        << "  Check: message parsing\n"
        << "    - Delimiter handling\n"
        << "    - Number conversion\n"
        << "    - Unit conversion (MHz to Hz)\n"
        << "    - Error handling";
}

TEST(NetworkProtocol, MessageValidation) {
    std::string invalid_message = "FREQ:999999,PWR:999999,GAIN:999999";
    bool is_valid = validate_radio_message(invalid_message);
    
    ASSERT_FALSE(is_valid)
        << "Invalid message should be rejected!\n"
        << "  Message: " << invalid_message << "\n"
        << "  Validation result: " << (is_valid ? "valid" : "invalid") << "\n"
        << "  Expected: invalid (values out of range)\n"
        << "  Check: message validation\n"
        << "    - Range checking\n"
        << "    - Format validation\n"
        << "    - Security checks\n"
        << "    - Error reporting";
}
```

## Property-Based Test Failures

```cpp
RC_GTEST_PROP(RadioPropagationTests,
              PathLossIncreasesWithDistance,
              (double frequency_hz, double distance1_m, double distance2_m)) {
    RC_PRE(frequency_hz > 1e6);
    RC_PRE(distance1_m < distance2_m);
    RC_PRE(distance1_m > 0);
    RC_PRE(distance2_m > 0);
    
    double loss1 = calculate_path_loss(frequency_hz, distance1_m);
    double loss2 = calculate_path_loss(frequency_hz, distance2_m);
    
    RC_ASSERT(loss2 > loss1)
        << "Path loss should increase with distance!\n"
        << "  Frequency: " << frequency_hz / 1e6 << " MHz\n"
        << "  Distance 1: " << distance1_m << " m\n"
        << "  Distance 2: " << distance2_m << " m\n"
        << "  Path loss 1: " << loss1 << " dB\n"
        << "  Path loss 2: " << loss2 << " dB\n"
        << "  Difference: " << (loss2 - loss1) << " dB\n"
        << "  Expected: loss2 > loss1\n"
        << "  Check: path loss calculation\n"
        << "    - Free space path loss formula\n"
        << "    - Distance dependence\n"
        << "    - Frequency dependence\n"
        << "    - Atmospheric effects";
}
```

## Debugging Tips

### 1. Include Intermediate Values

```cpp
TEST(ComplexCalculation, MultiStepProcess) {
    double input = 100.0;
    double step1 = calculate_step1(input);
    double step2 = calculate_step2(step1);
    double result = calculate_final(step2);
    
    ASSERT_GT(result, 50.0)
        << "Final result too low!\n"
        << "  Input: " << input << "\n"
        << "  Step 1 result: " << step1 << "\n"
        << "  Step 2 result: " << step2 << "\n"
        << "  Final result: " << result << "\n"
        << "  Expected: > 50.0\n"
        << "  Check each step:\n"
        << "    - Step 1: " << (step1 > 0 ? "OK" : "FAILED") << "\n"
        << "    - Step 2: " << (step2 > 0 ? "OK" : "FAILED") << "\n"
        << "    - Final: " << (result > 0 ? "OK" : "FAILED");
}
```

### 2. Provide Context for Edge Cases

```cpp
TEST(EdgeCase, ZeroInput) {
    double input = 0.0;
    double result = calculate_something(input);
    
    ASSERT_FALSE(std::isnan(result))
        << "Zero input caused NaN result!\n"
        << "  Input: " << input << "\n"
        << "  Result: " << result << "\n"
        << "  Expected: valid number (not NaN)\n"
        << "  Check: zero input handling\n"
        << "    - Division by zero protection\n"
        << "    - Logarithm of zero\n"
        << "    - Square root of negative\n"
        << "    - Edge case validation";
}
```

### 3. Include Performance Context

```cpp
TEST(Performance, CalculationSpeed) {
    auto start = std::chrono::high_resolution_clock::now();
    double result = calculate_complex_thing(1000);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    ASSERT_LT(duration.count(), 100)
        << "Calculation too slow!\n"
        << "  Result: " << result << "\n"
        << "  Execution time: " << duration.count() << " ms\n"
        << "  Expected: < 100 ms\n"
        << "  Check: algorithm efficiency\n"
        << "    - Loop optimization\n"
        << "    - Memory allocation\n"
        << "    - Mathematical operations\n"
        << "    - Data structure choices";
}
```

## Conclusion

Well-written test failures are essential for efficient debugging. They should:

1. **Provide Context**: Include all relevant input values and parameters
2. **Show Calculations**: Display intermediate values and expected results
3. **Suggest Solutions**: Offer specific debugging steps and potential causes
4. **Include Units**: Always show units for physical quantities
5. **Be Actionable**: Give developers clear next steps to investigate

This approach significantly reduces debugging time and helps maintain code quality throughout the development process.
