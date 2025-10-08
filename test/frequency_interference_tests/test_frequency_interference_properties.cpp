#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <cmath>
#include <vector>
#include <map>
#include <string>
#include <algorithm>

// Mock radio classes for property-based testing
class Radio {
public:
    struct RadioConfig {
        double frequency_hz;
        double power_watts;
        double bandwidth_hz;
        std::string modulation_type;
        double sensitivity_db;
    };
    
    struct InterferenceResult {
        double interference_db;
        double signal_to_noise_ratio;
        bool is_acceptable;
        double channel_separation_hz;
    };
    
    Radio(const RadioConfig& config) : config_(config), transmitting_(false), signal_level_(0.0) {}
    
    // Transmit signal
    void transmit(double signal_power_db) {
        transmitting_ = true;
        signal_level_ = signal_power_db;
    }
    
    void stopTransmitting() {
        transmitting_ = false;
        signal_level_ = 0.0;
    }
    
    // Measure interference from another radio
    double measureInterference(const Radio& other) {
        if (!other.transmitting_) return -100.0; // No interference if not transmitting
        
        double frequency_separation = std::abs(config_.frequency_hz - other.config_.frequency_hz);
        double channel_separation = frequency_separation;
        
        // Calculate interference based on frequency separation
        double interference = calculateInterference(other.signal_level_, frequency_separation, 
                                                   config_.bandwidth_hz, other.config_.bandwidth_hz);
        
        return interference;
    }
    
    // Calculate signal-to-noise ratio
    double calculateSNR(double desired_signal_db, double interference_db, double noise_floor_db) {
        double total_noise = 10 * std::log10(std::pow(10, noise_floor_db / 10) + std::pow(10, interference_db / 10));
        return desired_signal_db - total_noise;
    }
    
    // Check if interference is acceptable
    bool isInterferenceAcceptable(double interference_db, double desired_signal_db) {
        double snr = desired_signal_db - interference_db;
        return snr >= config_.sensitivity_db;
    }
    
    // Get current configuration
    const RadioConfig& getConfig() const { return config_; }
    
    // Check if transmitting
    bool isTransmitting() const { return transmitting_; }
    
    // Get signal level
    double getSignalLevel() const { return signal_level_; }
    
private:
    RadioConfig config_;
    bool transmitting_;
    double signal_level_;
    
    // Calculate interference based on frequency separation
    double calculateInterference(double transmitter_power_db, double frequency_separation_hz,
                                double receiver_bandwidth_hz, double transmitter_bandwidth_hz) {
        // Simplified interference calculation
        double separation_ratio = frequency_separation_hz / receiver_bandwidth_hz;
        
        if (separation_ratio < 0.5) {
            // Adjacent channel interference
            return transmitter_power_db - 20 * std::log10(separation_ratio + 0.1);
        } else if (separation_ratio < 2.0) {
            // Near-adjacent channel interference
            return transmitter_power_db - 40 * std::log10(separation_ratio);
        } else {
            // Distant channel interference
            return transmitter_power_db - 60 * std::log10(separation_ratio);
        }
    }
};

class FrequencyManager {
public:
    struct ChannelPlan {
        double start_frequency_hz;
        double channel_spacing_hz;
        int num_channels;
        double max_power_watts;
        double min_separation_hz;
    };
    
    // Check if frequencies are too close
    bool areFrequenciesTooClose(double freq1_hz, double freq2_hz, double min_separation_hz) {
        return std::abs(freq1_hz - freq2_hz) < min_separation_hz;
    }
    
    // Calculate channel separation
    double calculateChannelSeparation(double freq1_hz, double freq2_hz) {
        return std::abs(freq1_hz - freq2_hz);
    }
    
    // Check if frequency is in valid channel
    bool isFrequencyInChannel(double frequency_hz, const ChannelPlan& plan) {
        double offset = std::fmod(frequency_hz - plan.start_frequency_hz, plan.channel_spacing_hz);
        return std::abs(offset) < 1e-6 || std::abs(offset - plan.channel_spacing_hz) < 1e-6;
    }
    
    // Find next available frequency
    double findNextAvailableFrequency(double start_freq_hz, double spacing_hz, 
                                    const std::vector<double>& used_frequencies) {
        double current_freq = start_freq_hz;
        while (std::find(used_frequencies.begin(), used_frequencies.end(), current_freq) != used_frequencies.end()) {
            current_freq += spacing_hz;
        }
        return current_freq;
    }
    
    // Calculate interference between channels
    double calculateChannelInterference(double freq1_hz, double freq2_hz, 
                                       double power1_watts, double power2_watts,
                                       double bandwidth1_hz, double bandwidth2_hz) {
        double frequency_separation = std::abs(freq1_hz - freq2_hz);
        double power1_db = 10 * std::log10(power1_watts);
        double power2_db = 10 * std::log10(power2_watts);
        
        // Calculate interference based on frequency separation and power
        double separation_ratio = frequency_separation / std::max(bandwidth1_hz, bandwidth2_hz);
        double power_ratio = power1_db - power2_db;
        
        if (separation_ratio < 1.0) {
            return power1_db - 20 * std::log10(separation_ratio + 0.1) + power_ratio;
        } else {
            return power1_db - 40 * std::log10(separation_ratio) + power_ratio;
        }
    }
};

// Property-based tests for frequency interference
class FrequencyInterferencePropertyTests : public ::testing::Test {
protected:
    FrequencyManager freq_manager;
};

// Test that interference decreases with frequency separation
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceDecreasesWithSeparation,
              (double freq1_hz, double freq2_hz, double power_db)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(freq1_hz != freq2_hz);
    RC_PRE(power_db >= 0);
    
    Radio::RadioConfig config1 = {freq1_hz, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {freq2_hz, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    radio1.transmit(power_db);
    double interference = radio2.measureInterference(radio1);
    
    double separation = std::abs(freq1_hz - freq2_hz);
    
    // Interference should decrease with frequency separation
    if (separation > 25e3) { // Beyond adjacent channel
        RC_ASSERT(interference < -40.0);
    }
}

// Test that interference increases with power
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceIncreasesWithPower,
              (double freq1_hz, double freq2_hz, double power1_db, double power2_db)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(freq1_hz != freq2_hz);
    RC_PRE(power1_db >= 0);
    RC_PRE(power2_db >= 0);
    RC_PRE(power1_db < power2_db);
    
    Radio::RadioConfig config1 = {freq1_hz, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {freq2_hz, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    radio1.transmit(power1_db);
    double interference1 = radio2.measureInterference(radio1);
    
    radio1.transmit(power2_db);
    double interference2 = radio2.measureInterference(radio1);
    
    RC_ASSERT(interference2 > interference1);
}

// Test that channel separation is symmetric
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              ChannelSeparationIsSymmetric,
              (double freq1_hz, double freq2_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    
    double separation1 = freq_manager.calculateChannelSeparation(freq1_hz, freq2_hz);
    double separation2 = freq_manager.calculateChannelSeparation(freq2_hz, freq1_hz);
    
    RC_ASSERT(std::abs(separation1 - separation2) < 1e-6);
}

// Test that frequency plan compliance is consistent
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              FrequencyPlanCompliance,
              (double frequency_hz, double start_freq, double spacing)) {
    RC_PRE(frequency_hz > 0);
    RC_PRE(start_freq > 0);
    RC_PRE(spacing > 0);
    
    FrequencyManager::ChannelPlan plan = {start_freq, spacing, 100, 25.0, spacing};
    
    bool in_channel = freq_manager.isFrequencyInChannel(frequency_hz, plan);
    
    if (in_channel) {
        double offset = std::fmod(frequency_hz - start_freq, spacing);
        RC_ASSERT(std::abs(offset) < 1e-6 || std::abs(offset - spacing) < 1e-6);
    }
}

// Test that interference calculation is consistent
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceCalculationIsConsistent,
              (double freq1_hz, double freq2_hz, double power1_watts, double power2_watts,
               double bandwidth1_hz, double bandwidth2_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(freq1_hz != freq2_hz);
    RC_PRE(power1_watts > 0);
    RC_PRE(power2_watts > 0);
    RC_PRE(bandwidth1_hz > 0);
    RC_PRE(bandwidth2_hz > 0);
    
    double interference1 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power1_watts, power2_watts, bandwidth1_hz, bandwidth2_hz);
    double interference2 = freq_manager.calculateChannelInterference(
        freq2_hz, freq1_hz, power2_watts, power1_watts, bandwidth2_hz, bandwidth1_hz);
    
    // Interference should be symmetric
    RC_ASSERT(std::abs(interference1 - interference2) < 1e-6);
}

// Test that frequency separation requirements are met
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              FrequencySeparationRequirements,
              (double freq1_hz, double freq2_hz, double min_separation_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(min_separation_hz > 0);
    
    bool too_close = freq_manager.areFrequenciesTooClose(freq1_hz, freq2_hz, min_separation_hz);
    double separation = freq_manager.calculateChannelSeparation(freq1_hz, freq2_hz);
    
    if (too_close) {
        RC_ASSERT(separation < min_separation_hz);
    } else {
        RC_ASSERT(separation >= min_separation_hz);
    }
}

// Test that next available frequency is valid
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              NextAvailableFrequencyIsValid,
              (double start_freq_hz, double spacing_hz, std::vector<double> used_frequencies)) {
    RC_PRE(start_freq_hz > 0);
    RC_PRE(spacing_hz > 0);
    
    double next_freq = freq_manager.findNextAvailableFrequency(start_freq_hz, spacing_hz, used_frequencies);
    
    // Next frequency should not be in used frequencies
    RC_ASSERT(std::find(used_frequencies.begin(), used_frequencies.end(), next_freq) == used_frequencies.end());
    
    // Next frequency should be at least start_freq_hz
    RC_ASSERT(next_freq >= start_freq_hz);
}

// Test that interference is non-negative
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceIsNonNegative,
              (double freq1_hz, double freq2_hz, double power1_watts, double power2_watts,
               double bandwidth1_hz, double bandwidth2_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(power1_watts > 0);
    RC_PRE(power2_watts > 0);
    RC_PRE(bandwidth1_hz > 0);
    RC_PRE(bandwidth2_hz > 0);
    
    double interference = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power1_watts, power2_watts, bandwidth1_hz, bandwidth2_hz);
    
    RC_ASSERT(interference >= 0);
}

// Test that interference decreases with bandwidth
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceDecreasesWithBandwidth,
              (double freq1_hz, double freq2_hz, double power_watts, double bandwidth1_hz, double bandwidth2_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(freq1_hz != freq2_hz);
    RC_PRE(power_watts > 0);
    RC_PRE(bandwidth1_hz > 0);
    RC_PRE(bandwidth2_hz > 0);
    RC_PRE(bandwidth1_hz < bandwidth2_hz);
    
    double interference1 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power_watts, power_watts, bandwidth1_hz, bandwidth1_hz);
    double interference2 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power_watts, power_watts, bandwidth2_hz, bandwidth2_hz);
    
    // Wider bandwidth should have less interference
    RC_ASSERT(interference2 < interference1);
}

// Test that interference is monotonic with power
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceIsMonotonicWithPower,
              (double freq1_hz, double freq2_hz, double power1_watts, double power2_watts,
               double bandwidth_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(freq1_hz != freq2_hz);
    RC_PRE(power1_watts > 0);
    RC_PRE(power2_watts > 0);
    RC_PRE(power1_watts < power2_watts);
    RC_PRE(bandwidth_hz > 0);
    
    double interference1 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power1_watts, power1_watts, bandwidth_hz, bandwidth_hz);
    double interference2 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power2_watts, power2_watts, bandwidth_hz, bandwidth_hz);
    
    // Higher power should cause more interference
    RC_ASSERT(interference2 > interference1);
}

// Test that interference is continuous
RC_GTEST_PROP(FrequencyInterferencePropertyTests,
              InterferenceIsContinuous,
              (double freq1_hz, double freq2_hz, double power_watts, double bandwidth_hz,
               double freq_delta)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    RC_PRE(power_watts > 0);
    RC_PRE(bandwidth_hz > 0);
    RC_PRE(std::abs(freq_delta) < 1e3);
    
    double interference1 = freq_manager.calculateChannelInterference(
        freq1_hz, freq2_hz, power_watts, power_watts, bandwidth_hz, bandwidth_hz);
    double interference2 = freq_manager.calculateChannelInterference(
        freq1_hz + freq_delta, freq2_hz, power_watts, power_watts, bandwidth_hz, bandwidth_hz);
    
    // Small frequency changes should cause small interference changes
    RC_ASSERT(std::abs(interference1 - interference2) < 10.0);
}

// Custom generators for frequency interference testing
namespace rc {
    template<>
    struct Arbitrary<Radio::RadioConfig> {
        static Gen<Radio::RadioConfig> arbitrary() {
            return gen::construct<Radio::RadioConfig>(
                gen::inRange(100e6, 1000e6),     // frequency_hz
                gen::inRange(1.0, 100.0),        // power_watts
                gen::inRange(12.5e3, 100e3),     // bandwidth_hz
                gen::element<std::string>("AM", "FM", "SSB"),
                gen::inRange(-120.0, -80.0)      // sensitivity_db
            );
        }
    };
    
    template<>
    struct Arbitrary<FrequencyManager::ChannelPlan> {
        static Gen<FrequencyManager::ChannelPlan> arbitrary() {
            return gen::construct<FrequencyManager::ChannelPlan>(
                gen::inRange(100e6, 1000e6),     // start_frequency_hz
                gen::inRange(12.5e3, 100e3),     // channel_spacing_hz
                gen::inRange(10, 1000),          // num_channels
                gen::inRange(1.0, 1000.0),        // max_power_watts
                gen::inRange(12.5e3, 100e3)      // min_separation_hz
            );
        }
    };
}
