#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <vector>
#include <string>
#include <chrono>

// Mock classes for diagnostic testing examples
class RadioPropagation {
public:
    struct WeatherConditions {
        double temperature_c;
        double humidity_percent;
        double rain_rate_mmh;
        double fog_density;
        double snow_rate_mmh;
    };
    
    // Calculate radio range with weather effects
    double calculateRange(double frequency_hz, const WeatherConditions& weather) {
        // Simplified range calculation with weather effects
        double base_range = 1000.0; // Base range in km
        
        // Weather attenuation
        double rain_attenuation = calculateRainAttenuation(frequency_hz, weather.rain_rate_mmh);
        double fog_attenuation = calculateFogAttenuation(frequency_hz, weather.fog_density);
        double snow_attenuation = calculateSnowAttenuation(frequency_hz, weather.snow_rate_mmh);
        
        double total_attenuation = rain_attenuation + fog_attenuation + snow_attenuation;
        
        // Apply attenuation to range
        return base_range * std::pow(10.0, -total_attenuation / 20.0);
    }
    
    // Calculate rain attenuation (frequency dependent)
    double calculateRainAttenuation(double frequency_hz, double rain_rate_mmh) {
        if (frequency_hz < 1e9) return 0.0; // Minimal effect below 1 GHz
        
        double k = 0.0001 * std::pow(frequency_hz / 1e9, 1.5);
        double alpha = 0.8;
        return k * std::pow(rain_rate_mmh, alpha);
    }
    
    // Calculate fog attenuation (frequency dependent)
    double calculateFogAttenuation(double frequency_hz, double fog_density) {
        if (frequency_hz < 10e9) return 0.0; // Minimal effect below 10 GHz
        
        double wavelength = 299792458.0 / frequency_hz;
        double droplet_size = 0.01e-3; // 10 micron droplets
        double scattering = 4 * M_PI * fog_density * std::pow(droplet_size / wavelength, 4);
        return 10 * std::log10(1 + scattering);
    }
    
    // Calculate snow attenuation (frequency dependent)
    double calculateSnowAttenuation(double frequency_hz, double snow_rate_mmh) {
        if (frequency_hz < 3e9) return 0.0; // Minimal effect below 3 GHz
        
        double k = 0.00005 * std::pow(frequency_hz / 1e9, 1.2);
        double alpha = 0.6;
        return k * std::pow(snow_rate_mmh, alpha);
    }
    
    // Calculate path loss
    double calculatePathLoss(double frequency_hz, double distance_m) {
        const double c = 299792458.0; // speed of light
        double wavelength = c / frequency_hz;
        return 20 * std::log10(4 * M_PI * distance_m / wavelength);
    }
};

class AudioProcessor {
public:
    struct AudioBuffer {
        std::vector<float> samples;
        double sample_rate;
        int channels;
    };
    
    // Apply gain to audio buffer
    void applyGain(AudioBuffer& buffer, double gain_db) {
        double gain_linear = std::pow(10.0, gain_db / 20.0);
        for (auto& sample : buffer.samples) {
            sample *= gain_linear;
        }
    }
    
    // Apply compression to audio buffer
    void applyCompression(AudioBuffer& buffer, double threshold_db, double ratio) {
        double threshold_linear = std::pow(10.0, threshold_db / 20.0);
        for (auto& sample : buffer.samples) {
            if (std::abs(sample) > threshold_linear) {
                double excess = std::abs(sample) - threshold_linear;
                double compressed_excess = excess / ratio;
                sample = std::copysign(threshold_linear + compressed_excess, sample);
            }
        }
    }
    
    // Calculate RMS level
    double calculateRMS(const AudioBuffer& buffer) {
        if (buffer.samples.empty()) return 0.0;
        
        double sum_squares = 0.0;
        for (float sample : buffer.samples) {
            sum_squares += sample * sample;
        }
        return std::sqrt(sum_squares / buffer.samples.size());
    }
    
    // Create test buffer
    AudioBuffer createTestBuffer(double amplitude, int samples) {
        AudioBuffer buffer;
        buffer.samples.resize(samples);
        buffer.sample_rate = 44100.0;
        buffer.channels = 1;
        
        for (int i = 0; i < samples; ++i) {
            buffer.samples[i] = amplitude * std::sin(2 * M_PI * 1000 * i / 44100.0);
        }
        
        return buffer;
    }
};

class FrequencyManager {
public:
    // Check if frequencies are too close
    bool areFrequenciesTooClose(double freq1_hz, double freq2_hz, double min_separation_hz) {
        return std::abs(freq1_hz - freq2_hz) < min_separation_hz;
    }
    
    // Calculate channel separation
    double calculateChannelSeparation(double freq1_hz, double freq2_hz) {
        return std::abs(freq1_hz - freq2_hz);
    }
    
    // Calculate interference between channels
    double calculateInterference(double freq1_hz, double freq2_hz, double power1_watts, double power2_watts) {
        double frequency_separation = std::abs(freq1_hz - freq2_hz);
        double power1_db = 10 * std::log10(power1_watts);
        double power2_db = 10 * std::log10(power2_watts);
        
        if (frequency_separation < 25e3) {
            return power1_db - 20 * std::log10(frequency_separation / 25e3 + 0.1);
        } else {
            return power1_db - 40 * std::log10(frequency_separation / 25e3);
        }
    }
};

// Diagnostic test examples
class DiagnosticTestExamples : public ::testing::Test {
protected:
    RadioPropagation prop;
    AudioProcessor audio;
    FrequencyManager freq_mgr;
};

// Example 1: Radio Propagation with Weather Effects
TEST_F(DiagnosticTestExamples, RadioTransmissionRange) {
    double frequency = 118.5e6; // VHF aviation frequency
    double altitude = 10000; // 10,000 ft
    RadioPropagation::WeatherConditions weather = {20.0, 50.0, 0.0, 0.0, 0.0}; // Clear weather
    
    double range = prop.calculateRange(frequency, weather);
    
    ASSERT_GT(range, 150.0) 
        << "Range too short!\n"
        << "  Calculated: " << range << " km\n"
        << "  Expected: > 150 km\n"
        << "  Frequency: " << frequency / 1e6 << " MHz\n"
        << "  Altitude: " << altitude << " ft\n"
        << "  Weather: Clear (temp: " << weather.temperature_c << "°C, humidity: " << weather.humidity_percent << "%)\n"
        << "  This might indicate:\n"
        << "    - Power calculation error\n"
        << "    - Atmospheric absorption too high\n"
        << "    - Antenna gain incorrect\n"
        << "    - Weather effects not properly implemented\n"
        << "    - Base range calculation needs adjustment";
}

// Example 2: Weather Impact on Different Frequencies
TEST_F(DiagnosticTestExamples, WeatherImpactFrequencyDependence) {
    RadioPropagation::WeatherConditions clear_weather = {20.0, 50.0, 0.0, 0.0, 0.0};
    RadioPropagation::WeatherConditions rain_weather = {15.0, 95.0, 25.0, 0.0, 0.0};
    
    std::vector<double> frequencies = {118.5e6, 225e6, 2.4e9, 10e9};
    std::vector<std::string> freq_names = {"VHF", "UHF", "2.4GHz", "10GHz"};
    
    for (size_t i = 0; i < frequencies.size(); ++i) {
        double clear_range = prop.calculateRange(frequencies[i], clear_weather);
        double rain_range = prop.calculateRange(frequencies[i], rain_weather);
        double range_reduction = (clear_range - rain_range) / clear_range * 100.0;
        
        ASSERT_GT(clear_range, rain_range)
            << "Weather should reduce radio range!\n"
            << "  Frequency: " << freq_names[i] << " (" << frequencies[i] / 1e6 << " MHz)\n"
            << "  Clear weather range: " << clear_range << " km\n"
            << "  Rain weather range: " << rain_range << " km\n"
            << "  Range reduction: " << range_reduction << "%\n"
            << "  Rain rate: " << rain_weather.rain_rate_mmh << " mm/h\n"
            << "  Expected behavior:\n"
            << "    - VHF: Minimal reduction (< 5%)\n"
            << "    - UHF: Moderate reduction (5-15%)\n"
            << "    - 2.4GHz: Significant reduction (15-30%)\n"
            << "    - 10GHz: Severe reduction (30-50%)\n"
            << "  If reduction is too high for VHF, check:\n"
            << "    - Rain attenuation calculation\n"
            << "    - Frequency dependence implementation\n"
            << "    - Weather effect scaling factors";
    }
}

// Example 3: Audio Processing with Gain
TEST_F(DiagnosticTestExamples, AudioGainApplication) {
    double input_amplitude = 0.5;
    double gain_db = 6.0;
    int buffer_size = 1000;
    
    AudioProcessor::AudioBuffer buffer = audio.createTestBuffer(input_amplitude, buffer_size);
    double input_rms = audio.calculateRMS(buffer);
    
    audio.applyGain(buffer, gain_db);
    double output_rms = audio.calculateRMS(buffer);
    
    double expected_output = input_amplitude * std::pow(10.0, gain_db / 20.0);
    double gain_error = std::abs(output_rms - expected_output);
    
    ASSERT_NEAR(output_rms, expected_output, 0.01)
        << "Gain application incorrect!\n"
        << "  Input amplitude: " << input_amplitude << "\n"
        << "  Input RMS: " << input_rms << "\n"
        << "  Gain: " << gain_db << " dB\n"
        << "  Expected output: " << expected_output << "\n"
        << "  Actual output: " << output_rms << "\n"
        << "  Gain error: " << gain_error << "\n"
        << "  Linear gain factor: " << std::pow(10.0, gain_db / 20.0) << "\n"
        << "  Check: gain calculation\n"
        << "    - Formula: output = input * 10^(gain_db/20)\n"
        << "    - Buffer processing\n"
        << "    - Floating point precision\n"
        << "    - Sample rate handling";
}

// Example 4: Audio Compression
TEST_F(DiagnosticTestExamples, AudioCompression) {
    double input_amplitude = 0.8;
    double threshold_db = -10.0;
    double ratio = 4.0;
    int buffer_size = 1000;
    
    AudioProcessor::AudioBuffer buffer = audio.createTestBuffer(input_amplitude, buffer_size);
    double input_rms = audio.calculateRMS(buffer);
    
    audio.applyCompression(buffer, threshold_db, ratio);
    double output_rms = audio.calculateRMS(buffer);
    
    double compression_ratio_actual = input_rms / output_rms;
    
    ASSERT_LT(output_rms, input_rms)
        << "Compression not working!\n"
        << "  Input amplitude: " << input_amplitude << "\n"
        << "  Input RMS: " << input_rms << "\n"
        << "  Threshold: " << threshold_db << " dB\n"
        << "  Ratio: " << ratio << ":1\n"
        << "  Output RMS: " << output_rms << "\n"
        << "  Actual compression ratio: " << compression_ratio_actual << ":1\n"
        << "  Expected: output < input (compression)\n"
        << "  Check: compression algorithm\n"
        << "    - Threshold detection\n"
        << "    - Ratio application\n"
        << "    - Attack/release times\n"
        << "    - Makeup gain\n"
        << "    - Peak vs RMS detection";
}

// Example 5: Frequency Management
TEST_F(DiagnosticTestExamples, FrequencyChannelSeparation) {
    double freq1 = 118.5e6;
    double freq2 = 118.525e6;
    double min_separation = 25e3; // 25 kHz
    
    double separation = freq_mgr.calculateChannelSeparation(freq1, freq2);
    bool compliant = separation >= min_separation;
    
    ASSERT_TRUE(compliant)
        << "Channel separation insufficient!\n"
        << "  Frequency 1: " << freq1 / 1e6 << " MHz\n"
        << "  Frequency 2: " << freq2 / 1e6 << " MHz\n"
        << "  Separation: " << separation / 1e3 << " kHz\n"
        << "  Minimum required: " << min_separation / 1e3 << " kHz\n"
        << "  Difference: " << (min_separation - separation) / 1e3 << " kHz\n"
        << "  Compliance: " << (compliant ? "PASS" : "FAIL") << "\n"
        << "  Check: frequency allocation algorithm\n"
        << "    - Channel spacing calculation\n"
        << "    - Adjacent channel protection\n"
        << "    - Interference calculations\n"
        << "    - Regulatory compliance";
}

// Example 6: Interference Detection
TEST_F(DiagnosticTestExamples, FrequencyInterferenceDetection) {
    double freq1 = 118.5e6;
    double freq2 = 118.525e6;
    double power1 = 25.0; // watts
    double power2 = 25.0; // watts
    
    double interference = freq_mgr.calculateInterference(freq1, freq2, power1, power2);
    double max_acceptable_interference = -40.0; // dB
    
    ASSERT_LT(interference, max_acceptable_interference)
        << "Adjacent channel interference too high!\n"
        << "  Transmitter frequency: " << freq1 / 1e6 << " MHz\n"
        << "  Receiver frequency: " << freq2 / 1e6 << " MHz\n"
        << "  Channel separation: " << (freq2 - freq1) / 1e3 << " kHz\n"
        << "  Transmitter power: " << power1 << " W (" << 10 * std::log10(power1) << " dBm)\n"
        << "  Receiver power: " << power2 << " W (" << 10 * std::log10(power2) << " dBm)\n"
        << "  Interference level: " << interference << " dB\n"
        << "  Maximum acceptable: " << max_acceptable_interference << " dB\n"
        << "  Difference: " << (interference - max_acceptable_interference) << " dB\n"
        << "  Check: interference calculation\n"
        << "    - Frequency separation factor\n"
        << "    - Power level scaling\n"
        << "    - Bandwidth considerations\n"
        << "    - Antenna pattern effects\n"
        << "    - Atmospheric conditions";
}

// Example 7: Performance Testing
TEST_F(DiagnosticTestExamples, CalculationPerformance) {
    int iterations = 10000;
    double frequency = 2.4e9;
    double distance = 1000.0;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    double total_path_loss = 0.0;
    for (int i = 0; i < iterations; ++i) {
        total_path_loss += prop.calculatePathLoss(frequency, distance);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double average_path_loss = total_path_loss / iterations;
    double execution_time_us = duration.count();
    double execution_time_ms = execution_time_us / 1000.0;
    
    ASSERT_LT(execution_time_ms, 100.0)
        << "Calculation too slow!\n"
        << "  Iterations: " << iterations << "\n"
        << "  Frequency: " << frequency / 1e9 << " GHz\n"
        << "  Distance: " << distance << " m\n"
        << "  Average path loss: " << average_path_loss << " dB\n"
        << "  Total execution time: " << execution_time_ms << " ms\n"
        << "  Time per calculation: " << execution_time_us / iterations << " μs\n"
        << "  Expected: < 100 ms total\n"
        << "  Check: algorithm efficiency\n"
        << "    - Loop optimization\n"
        << "    - Mathematical operations\n"
        << "    - Memory allocation\n"
        << "    - Data structure choices\n"
        << "    - Compiler optimization";
}

// Example 8: Edge Case Handling
TEST_F(DiagnosticTestExamples, ZeroInputHandling) {
    double frequency = 0.0;
    double distance = 1000.0;
    
    double path_loss = prop.calculatePathLoss(frequency, distance);
    
    ASSERT_FALSE(std::isnan(path_loss))
        << "Zero frequency caused NaN result!\n"
        << "  Frequency: " << frequency << " Hz\n"
        << "  Distance: " << distance << " m\n"
        << "  Result: " << path_loss << " dB\n"
        << "  Expected: valid number (not NaN)\n"
        << "  Check: zero input handling\n"
        << "    - Division by zero protection\n"
        << "    - Logarithm of zero\n"
        << "    - Square root of negative\n"
        << "    - Edge case validation\n"
        << "    - Input parameter checking";
}

// Example 9: Multi-Step Process
TEST_F(DiagnosticTestExamples, MultiStepCalculation) {
    double frequency = 118.5e6;
    double distance = 1000.0;
    RadioPropagation::WeatherConditions weather = {20.0, 50.0, 25.0, 0.0, 0.0};
    
    // Step 1: Calculate base path loss
    double base_path_loss = prop.calculatePathLoss(frequency, distance);
    
    // Step 2: Calculate weather attenuation
    double rain_attenuation = prop.calculateRainAttenuation(frequency, weather.rain_rate_mmh);
    
    // Step 3: Calculate total attenuation
    double total_attenuation = base_path_loss + rain_attenuation;
    
    // Step 4: Calculate effective range
    double effective_range = 1000.0 * std::pow(10.0, -total_attenuation / 20.0);
    
    ASSERT_GT(effective_range, 0.0)
        << "Multi-step calculation failed!\n"
        << "  Frequency: " << frequency / 1e6 << " MHz\n"
        << "  Distance: " << distance << " m\n"
        << "  Rain rate: " << weather.rain_rate_mmh << " mm/h\n"
        << "  Step 1 - Base path loss: " << base_path_loss << " dB\n"
        << "  Step 2 - Rain attenuation: " << rain_attenuation << " dB\n"
        << "  Step 3 - Total attenuation: " << total_attenuation << " dB\n"
        << "  Step 4 - Effective range: " << effective_range << " km\n"
        << "  Expected: range > 0 km\n"
        << "  Check each step:\n"
        << "    - Step 1: " << (base_path_loss > 0 ? "OK" : "FAILED") << "\n"
        << "    - Step 2: " << (rain_attenuation >= 0 ? "OK" : "FAILED") << "\n"
        << "    - Step 3: " << (total_attenuation > 0 ? "OK" : "FAILED") << "\n"
        << "    - Step 4: " << (effective_range > 0 ? "OK" : "FAILED") << "\n"
        << "  Possible issues:\n"
        << "    - Path loss calculation error\n"
        << "    - Weather attenuation too high\n"
        << "    - Range calculation formula\n"
        << "    - Unit conversion problems";
}

// Property-based test with diagnostics
TEST_F(DiagnosticTestExamples, PathLossIncreasesWithDistanceProperty) {
    rc::check("Path loss increases with distance", [](double frequency_hz, double distance1_m, double distance2_m) {
        RC_PRE(frequency_hz > 1e6);
        RC_PRE(distance1_m < distance2_m);
        RC_PRE(distance1_m > 0);
        RC_PRE(distance2_m > 0);
        
        RadioPropagation prop;
        double loss1 = prop.calculatePathLoss(frequency_hz, distance1_m);
        double loss2 = prop.calculatePathLoss(frequency_hz, distance2_m);
        
        RC_ASSERT(loss2 > loss1);
    });
}
