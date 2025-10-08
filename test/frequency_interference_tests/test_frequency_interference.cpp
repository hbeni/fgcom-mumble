#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <cmath>
#include <vector>
#include <map>
#include <string>
#include <algorithm>

// Mock radio classes for frequency interference testing
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

// Frequency Interference Tests
class FrequencyInterferenceTests : public ::testing::Test {
protected:
    void SetUp() override {
        // Aviation frequency plan
        aviation_plan = {118.0e6, 25e3, 200, 25.0, 25e3};
        
        // Maritime frequency plan
        maritime_plan = {156.0e6, 25e3, 100, 25.0, 25e3};
        
        // Amateur radio frequency plan
        amateur_plan = {144.0e6, 25e3, 400, 100.0, 25e3};
    }
    
    FrequencyManager::ChannelPlan aviation_plan;
    FrequencyManager::ChannelPlan maritime_plan;
    FrequencyManager::ChannelPlan amateur_plan;
    FrequencyManager freq_manager;
};

// Test adjacent channel interference
TEST_F(FrequencyInterferenceTests, AdjacentChannelInterference) {
    // Create two radios on adjacent channels
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {118.525e6, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    // Transmit on radio1
    radio1.transmit(20.0); // 20 dB signal
    
    // Measure interference on radio2
    double interference = radio2.measureInterference(radio1);
    
    // Adjacent channel should have minimal but measurable interference
    EXPECT_GT(interference, -80.0) << "Adjacent channel should have measurable interference";
    EXPECT_LT(interference, -20.0) << "Adjacent channel interference should be limited";
}

TEST_F(FrequencyInterferenceTests, SameChannelInterference) {
    // Create two radios on the same frequency
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    // Transmit on radio1
    radio1.transmit(20.0); // 20 dB signal
    
    // Measure interference on radio2
    double interference = radio2.measureInterference(radio1);
    
    // Same channel should have maximum interference
    EXPECT_GT(interference, -10.0) << "Same channel should have maximum interference";
}

TEST_F(FrequencyInterferenceTests, DistantChannelInterference) {
    // Create two radios on distant channels
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {119.0e6, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    // Transmit on radio1
    radio1.transmit(20.0); // 20 dB signal
    
    // Measure interference on radio2
    double interference = radio2.measureInterference(radio1);
    
    // Distant channel should have minimal interference
    EXPECT_LT(interference, -60.0) << "Distant channel should have minimal interference";
}

TEST_F(FrequencyInterferenceTests, PowerLevelInterference) {
    // Test interference with different power levels
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {118.525e6, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    
    // Test with different power levels
    std::vector<double> power_levels = {10.0, 20.0, 30.0, 40.0};
    std::vector<double> interferences;
    
    for (double power : power_levels) {
        radio1.transmit(power);
        double interference = radio2.measureInterference(radio1);
        interferences.push_back(interference);
    }
    
    // Higher power should cause more interference
    for (size_t i = 1; i < interferences.size(); ++i) {
        EXPECT_GT(interferences[i], interferences[i-1]) 
            << "Higher power should cause more interference";
    }
}

TEST_F(FrequencyInterferenceTests, BandwidthInterference) {
    // Test interference with different bandwidths
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2_narrow = {118.525e6, 25.0, 12.5e3, "AM", -100.0};
    Radio::RadioConfig config2_wide = {118.525e6, 25.0, 50e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2_narrow(config2_narrow);
    Radio radio2_wide(config2_wide);
    
    radio1.transmit(20.0);
    
    double interference_narrow = radio2_narrow.measureInterference(radio1);
    double interference_wide = radio2_wide.measureInterference(radio1);
    
    // Narrow bandwidth should have less interference
    EXPECT_LT(interference_narrow, interference_wide) 
        << "Narrow bandwidth should have less interference";
}

TEST_F(FrequencyInterferenceTests, ChannelSeparationRequirements) {
    // Test minimum channel separation requirements
    std::vector<double> test_frequencies = {118.5e6, 118.525e6, 118.55e6, 118.575e6};
    double min_separation = 25e3; // 25 kHz minimum separation
    
    for (size_t i = 0; i < test_frequencies.size() - 1; ++i) {
        double separation = freq_manager.calculateChannelSeparation(
            test_frequencies[i], test_frequencies[i+1]);
        
        EXPECT_GE(separation, min_separation) 
            << "Channel separation should meet minimum requirements";
    }
}

TEST_F(FrequencyInterferenceTests, FrequencyPlanCompliance) {
    // Test frequency plan compliance
    std::vector<double> valid_frequencies = {118.0e6, 118.025e6, 118.05e6, 118.075e6};
    std::vector<double> invalid_frequencies = {118.01e6, 118.03e6, 118.07e6};
    
    for (double freq : valid_frequencies) {
        EXPECT_TRUE(freq_manager.isFrequencyInChannel(freq, aviation_plan))
            << "Valid frequency should be in channel plan";
    }
    
    for (double freq : invalid_frequencies) {
        EXPECT_FALSE(freq_manager.isFrequencyInChannel(freq, aviation_plan))
            << "Invalid frequency should not be in channel plan";
    }
}

TEST_F(FrequencyInterferenceTests, InterferenceThresholds) {
    // Test interference thresholds for different services
    Radio::RadioConfig aviation_config = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig maritime_config = {156.8e6, 25.0, 25e3, "FM", -100.0};
    
    Radio aviation_radio(aviation_config);
    Radio maritime_radio(maritime_config);
    
    // Test interference between different services
    aviation_radio.transmit(20.0);
    double interference = maritime_radio.measureInterference(aviation_radio);
    
    // Different services should have minimal interference
    EXPECT_LT(interference, -80.0) << "Different services should have minimal interference";
}

TEST_F(FrequencyInterferenceTests, MultipleInterferenceSources) {
    // Test multiple interference sources
    Radio::RadioConfig config1 = {118.5e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config2 = {118.525e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig config3 = {118.55e6, 25.0, 25e3, "AM", -100.0};
    Radio::RadioConfig victim_config = {118.575e6, 25.0, 25e3, "AM", -100.0};
    
    Radio radio1(config1);
    Radio radio2(config2);
    Radio radio3(config3);
    Radio victim_radio(victim_config);
    
    // Transmit on all interfering radios
    radio1.transmit(20.0);
    radio2.transmit(18.0);
    radio3.transmit(16.0);
    
    // Measure total interference
    double interference1 = victim_radio.measureInterference(radio1);
    double interference2 = victim_radio.measureInterference(radio2);
    double interference3 = victim_radio.measureInterference(radio3);
    
    // Calculate combined interference
    double combined_interference = 10 * std::log10(
        std::pow(10, interference1 / 10) + 
        std::pow(10, interference2 / 10) + 
        std::pow(10, interference3 / 10)
    );
    
    EXPECT_GT(combined_interference, interference1) 
        << "Combined interference should be greater than individual interference";
}

// Property-based tests for frequency interference
RC_GTEST_PROP(FrequencyInterferenceTests,
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

RC_GTEST_PROP(FrequencyInterferenceTests,
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

RC_GTEST_PROP(FrequencyInterferenceTests,
              ChannelSeparationIsSymmetric,
              (double freq1_hz, double freq2_hz)) {
    RC_PRE(freq1_hz > 0);
    RC_PRE(freq2_hz > 0);
    
    double separation1 = freq_manager.calculateChannelSeparation(freq1_hz, freq2_hz);
    double separation2 = freq_manager.calculateChannelSeparation(freq2_hz, freq1_hz);
    
    RC_ASSERT(std::abs(separation1 - separation2) < 1e-6);
}

RC_GTEST_PROP(FrequencyInterferenceTests,
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
}
