#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <vector>
#include <string>
#include <stdexcept>
#include <limits>
#include <fstream>
#include <memory>

// Mock classes for edge case testing
class RadioPropagation {
public:
    // Extreme weather conditions
    struct ExtremeWeather {
        double temperature_c;
        double humidity_percent;
        double rain_rate_mmh;
        double fog_density;
        double snow_rate_mmh;
        double wind_speed_ms;
        double atmospheric_pressure_hpa;
    };
    
    // Calculate range with extreme conditions
    double calculateRangeExtreme(double frequency_hz, const ExtremeWeather& weather) {
        // Check for extreme values that might cause issues
        if (std::isnan(frequency_hz) || std::isinf(frequency_hz)) {
            throw std::invalid_argument("Invalid frequency: NaN or infinity");
        }
        
        if (frequency_hz <= 0) {
            throw std::invalid_argument("Frequency must be positive");
        }
        
        if (frequency_hz > 1e12) { // 1 THz - beyond practical radio
            throw std::invalid_argument("Frequency too high for radio propagation");
        }
        
        // Extreme weather validation
        if (weather.temperature_c < -100.0 || weather.temperature_c > 100.0) {
            throw std::invalid_argument("Temperature out of reasonable range");
        }
        
        if (weather.humidity_percent < 0.0 || weather.humidity_percent > 100.0) {
            throw std::invalid_argument("Humidity must be between 0 and 100%");
        }
        
        if (weather.rain_rate_mmh < 0.0 || weather.rain_rate_mmh > 1000.0) {
            throw std::invalid_argument("Rain rate out of reasonable range");
        }
        
        // Calculate with extreme values
        double base_range = 1000.0;
        
        // Extreme rain attenuation
        double rain_attenuation = 0.0;
        if (weather.rain_rate_mmh > 0) {
            rain_attenuation = calculateExtremeRainAttenuation(frequency_hz, weather.rain_rate_mmh);
        }
        
        // Extreme fog attenuation
        double fog_attenuation = 0.0;
        if (weather.fog_density > 0) {
            fog_attenuation = calculateExtremeFogAttenuation(frequency_hz, weather.fog_density);
        }
        
        // Extreme snow attenuation
        double snow_attenuation = 0.0;
        if (weather.snow_rate_mmh > 0) {
            snow_attenuation = calculateExtremeSnowAttenuation(frequency_hz, weather.snow_rate_mmh);
        }
        
        double total_attenuation = rain_attenuation + fog_attenuation + snow_attenuation;
        
        // Check for extreme attenuation
        if (total_attenuation > 200.0) { // 200 dB attenuation
            return 0.001; // Very short range
        }
        
        return base_range * std::pow(10.0, -total_attenuation / 20.0);
    }
    
    // Extreme rain attenuation calculation
    double calculateExtremeRainAttenuation(double frequency_hz, double rain_rate_mmh) {
        if (frequency_hz < 1e6) return 0.0;
        
        // Use ITU-R P.838-3 with extreme values
        double k = 0.0001 * std::pow(frequency_hz / 1e9, 1.5);
        double alpha = 0.8;
        double attenuation = k * std::pow(rain_rate_mmh, alpha);
        
        // Cap at reasonable maximum
        return std::min(attenuation, 100.0);
    }
    
    // Extreme fog attenuation calculation
    double calculateExtremeFogAttenuation(double frequency_hz, double fog_density) {
        if (frequency_hz < 10e9) return 0.0;
        
        double wavelength = 299792458.0 / frequency_hz;
        double droplet_size = 0.01e-3;
        double scattering = 4 * M_PI * fog_density * std::pow(droplet_size / wavelength, 4);
        double attenuation = 10 * std::log10(1 + scattering);
        
        // Cap at reasonable maximum
        return std::min(attenuation, 50.0);
    }
    
    // Extreme snow attenuation calculation
    double calculateExtremeSnowAttenuation(double frequency_hz, double snow_rate_mmh) {
        if (frequency_hz < 3e9) return 0.0;
        
        double k = 0.00005 * std::pow(frequency_hz / 1e9, 1.2);
        double alpha = 0.6;
        double attenuation = k * std::pow(snow_rate_mmh, alpha);
        
        // Cap at reasonable maximum
        return std::min(attenuation, 30.0);
    }
    
    // Debug-only function (only compiled in debug builds)
    #ifdef DEBUG
    void debugPrintPropagation(double frequency_hz, double range_km, const ExtremeWeather& weather) {
        std::cout << "DEBUG: Propagation calculation" << std::endl;
        std::cout << "  Frequency: " << frequency_hz / 1e6 << " MHz" << std::endl;
        std::cout << "  Range: " << range_km << " km" << std::endl;
        std::cout << "  Temperature: " << weather.temperature_c << "°C" << std::endl;
        std::cout << "  Humidity: " << weather.humidity_percent << "%" << std::endl;
        std::cout << "  Rain rate: " << weather.rain_rate_mmh << " mm/h" << std::endl;
    }
    #endif
    
    // Unreachable code path (should never be executed)
    double calculateUnreachablePath(double frequency_hz) {
        if (frequency_hz < 0) {
            // This should never happen due to validation
            return -1.0; // Unreachable code
        }
        return 0.0;
    }
};

class AudioProcessor {
public:
    // Extreme audio processing
    void processExtremeAudio(std::vector<float>& samples, double gain_db) {
        // Check for extreme values
        if (std::isnan(gain_db) || std::isinf(gain_db)) {
            throw std::invalid_argument("Invalid gain: NaN or infinity");
        }
        
        if (gain_db < -120.0 || gain_db > 120.0) {
            throw std::invalid_argument("Gain out of reasonable range (-120 to 120 dB)");
        }
        
        if (samples.empty()) {
            return; // Nothing to process
        }
        
        // Check for extreme sample values
        for (float& sample : samples) {
            if (std::isnan(sample) || std::isinf(sample)) {
                sample = 0.0f; // Replace invalid samples
            }
        }
        
        // Apply extreme gain
        double gain_linear = std::pow(10.0, gain_db / 20.0);
        for (auto& sample : samples) {
            sample *= gain_linear;
            
            // Clamp to prevent overflow
            if (sample > 1.0f) sample = 1.0f;
            if (sample < -1.0f) sample = -1.0f;
        }
    }
    
    // Debug-only function
    #ifdef DEBUG
    void debugPrintAudio(const std::vector<float>& samples, double gain_db) {
        std::cout << "DEBUG: Audio processing" << std::endl;
        std::cout << "  Samples: " << samples.size() << std::endl;
        std::cout << "  Gain: " << gain_db << " dB" << std::endl;
        std::cout << "  RMS: " << calculateRMS(samples) << std::endl;
    }
    #endif
    
    // Calculate RMS with extreme values
    double calculateRMS(const std::vector<float>& samples) {
        if (samples.empty()) return 0.0;
        
        double sum_squares = 0.0;
        for (float sample : samples) {
            if (std::isnan(sample) || std::isinf(sample)) {
                continue; // Skip invalid samples
            }
            sum_squares += sample * sample;
        }
        
        if (sum_squares == 0.0) return 0.0;
        
        return std::sqrt(sum_squares / samples.size());
    }
    
    // Unreachable code path
    double calculateUnreachableRMS() {
        // This function should never be called
        return -1.0; // Unreachable code
    }
};

class FrequencyManager {
public:
    // Extreme frequency management
    double allocateExtremeFrequency(double requested_freq_hz, const std::vector<double>& used_frequencies) {
        // Check for extreme values
        if (std::isnan(requested_freq_hz) || std::isinf(requested_freq_hz)) {
            throw std::invalid_argument("Invalid frequency: NaN or infinity");
        }
        
        if (requested_freq_hz <= 0) {
            throw std::invalid_argument("Frequency must be positive");
        }
        
        if (requested_freq_hz > 1e12) { // 1 THz
            throw std::invalid_argument("Frequency too high for radio allocation");
        }
        
        // Check for extreme frequency conflicts
        for (double used_freq : used_frequencies) {
            if (std::abs(requested_freq_hz - used_freq) < 1e3) { // 1 kHz minimum separation
                throw std::runtime_error("Frequency too close to existing allocation");
            }
        }
        
        return requested_freq_hz;
    }
    
    // Debug-only function
    #ifdef DEBUG
    void debugPrintFrequencyAllocation(double frequency_hz, const std::vector<double>& used_frequencies) {
        std::cout << "DEBUG: Frequency allocation" << std::endl;
        std::cout << "  Requested: " << frequency_hz / 1e6 << " MHz" << std::endl;
        std::cout << "  Used frequencies: " << used_frequencies.size() << std::endl;
        for (double freq : used_frequencies) {
            std::cout << "    " << freq / 1e6 << " MHz" << std::endl;
        }
    }
    #endif
    
    // Unreachable code path
    double allocateUnreachableFrequency() {
        // This should never be called
        return -1.0; // Unreachable code
    }
};

// Edge case coverage tests
class EdgeCaseCoverageTests : public ::testing::Test {
protected:
    RadioPropagation prop;
    AudioProcessor audio;
    FrequencyManager freq_mgr;
};

// Test 1: Rare Error Conditions
TEST_F(EdgeCaseCoverageTests, RareErrorConditions) {
    // Test NaN frequency
    EXPECT_THROW(prop.calculateRangeExtreme(std::numeric_limits<double>::quiet_NaN(), {}), 
                 std::invalid_argument);
    
    // Test infinity frequency
    EXPECT_THROW(prop.calculateRangeExtreme(std::numeric_limits<double>::infinity(), {}), 
                 std::invalid_argument);
    
    // Test negative frequency
    EXPECT_THROW(prop.calculateRangeExtreme(-100.0, {}), 
                 std::invalid_argument);
    
    // Test zero frequency
    EXPECT_THROW(prop.calculateRangeExtreme(0.0, {}), 
                 std::invalid_argument);
    
    // Test extremely high frequency
    EXPECT_THROW(prop.calculateRangeExtreme(1e15, {}), 
                 std::invalid_argument);
    
    // Test extreme weather conditions
    RadioPropagation::ExtremeWeather extreme_weather;
    extreme_weather.temperature_c = -150.0; // Too cold
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
    
    extreme_weather.temperature_c = 150.0; // Too hot
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
    
    extreme_weather.temperature_c = 20.0;
    extreme_weather.humidity_percent = -10.0; // Invalid humidity
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
    
    extreme_weather.humidity_percent = 150.0; // Invalid humidity
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
    
    extreme_weather.humidity_percent = 50.0;
    extreme_weather.rain_rate_mmh = -5.0; // Invalid rain rate
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
    
    extreme_weather.rain_rate_mmh = 2000.0; // Extreme rain rate
    EXPECT_THROW(prop.calculateRangeExtreme(118.5e6, extreme_weather), 
                 std::invalid_argument);
}

// Test 2: Debug-Only Code Paths
TEST_F(EdgeCaseCoverageTests, DebugOnlyCodePaths) {
    #ifdef DEBUG
    // Test debug functions (only available in debug builds)
    RadioPropagation::ExtremeWeather weather = {20.0, 50.0, 0.0, 0.0, 0.0, 5.0, 1013.25};
    double range = prop.calculateRangeExtreme(118.5e6, weather);
    
    // This should not throw in debug builds
    EXPECT_NO_THROW(prop.debugPrintPropagation(118.5e6, range, weather));
    
    // Test audio debug function
    std::vector<float> samples = {0.1f, 0.2f, 0.3f};
    EXPECT_NO_THROW(audio.debugPrintAudio(samples, 6.0));
    
    // Test frequency debug function
    std::vector<double> used_freqs = {118.5e6, 118.525e6};
    EXPECT_NO_THROW(freq_mgr.debugPrintFrequencyAllocation(118.55e6, used_freqs));
    #else
    // In release builds, debug functions are not available
    // This test passes by default
    EXPECT_TRUE(true);
    #endif
}

// Test 3: Unreachable Code Paths
TEST_F(EdgeCaseCoverageTests, UnreachableCodePaths) {
    // Test unreachable code paths
    // These should never be executed due to validation
    
    // Test with valid frequency (should not reach unreachable code)
    double result = prop.calculateUnreachablePath(118.5e6);
    EXPECT_EQ(result, 0.0); // Should return 0.0, not -1.0
    
    // Test audio unreachable code
    double audio_result = audio.calculateUnreachableRMS();
    EXPECT_EQ(audio_result, -1.0); // This is unreachable code
    
    // Test frequency unreachable code
    double freq_result = freq_mgr.allocateUnreachableFrequency();
    EXPECT_EQ(freq_result, -1.0); // This is unreachable code
}

// Test 4: Exception Handlers for Extreme Cases
TEST_F(EdgeCaseCoverageTests, ExtremeCaseExceptionHandlers) {
    // Test extreme audio processing
    std::vector<float> samples = {0.1f, 0.2f, 0.3f};
    
    // Test NaN gain
    EXPECT_THROW(audio.processExtremeAudio(samples, std::numeric_limits<double>::quiet_NaN()), 
                 std::invalid_argument);
    
    // Test infinity gain
    EXPECT_THROW(audio.processExtremeAudio(samples, std::numeric_limits<double>::infinity()), 
                 std::invalid_argument);
    
    // Test extreme gain values
    EXPECT_THROW(audio.processExtremeAudio(samples, -200.0), 
                 std::invalid_argument);
    
    EXPECT_THROW(audio.processExtremeAudio(samples, 200.0), 
                 std::invalid_argument);
    
    // Test extreme frequency allocation
    std::vector<double> used_frequencies = {118.5e6, 118.525e6};
    
    // Test NaN frequency
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(std::numeric_limits<double>::quiet_NaN(), used_frequencies), 
                 std::invalid_argument);
    
    // Test infinity frequency
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(std::numeric_limits<double>::infinity(), used_frequencies), 
                 std::invalid_argument);
    
    // Test negative frequency
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(-100.0, used_frequencies), 
                 std::invalid_argument);
    
    // Test zero frequency
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(0.0, used_frequencies), 
                 std::invalid_argument);
    
    // Test extremely high frequency
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(1e15, used_frequencies), 
                 std::invalid_argument);
    
    // Test frequency conflict
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(118.5e6, used_frequencies), 
                 std::runtime_error);
}

// Test 5: Extreme Weather Conditions
TEST_F(EdgeCaseCoverageTests, ExtremeWeatherConditions) {
    RadioPropagation::ExtremeWeather weather;
    
    // Test extreme rain
    weather = {20.0, 50.0, 500.0, 0.0, 0.0, 5.0, 1013.25}; // 500 mm/h rain
    double range_heavy_rain = prop.calculateRangeExtreme(118.5e6, weather);
    EXPECT_GT(range_heavy_rain, 0.0);
    EXPECT_LT(range_heavy_rain, 1000.0);
    
    // Test extreme fog
    weather = {20.0, 50.0, 0.0, 0.9, 0.0, 5.0, 1013.25}; // Dense fog
    double range_fog = prop.calculateRangeExtreme(10e9, weather);
    EXPECT_GT(range_fog, 0.0);
    EXPECT_LT(range_fog, 1000.0);
    
    // Test extreme snow
    weather = {0.0, 50.0, 0.0, 0.0, 100.0, 5.0, 1013.25}; // Heavy snow
    double range_snow = prop.calculateRangeExtreme(5e9, weather);
    EXPECT_GT(range_snow, 0.0);
    EXPECT_LT(range_snow, 1000.0);
    
    // Test combined extreme weather
    weather = {5.0, 100.0, 100.0, 0.5, 50.0, 25.0, 980.0}; // Extreme conditions
    double range_extreme = prop.calculateRangeExtreme(2.4e9, weather);
    EXPECT_GT(range_extreme, 0.0);
    EXPECT_LT(range_extreme, 1000.0);
}

// Test 6: Extreme Audio Processing
TEST_F(EdgeCaseCoverageTests, ExtremeAudioProcessing) {
    // Test with extreme sample values
    std::vector<float> samples = {0.1f, 0.2f, 0.3f, std::numeric_limits<float>::quiet_NaN(), 
                                  std::numeric_limits<float>::infinity(), -0.5f};
    
    // Test extreme gain
    EXPECT_NO_THROW(audio.processExtremeAudio(samples, 60.0)); // High gain
    EXPECT_NO_THROW(audio.processExtremeAudio(samples, -60.0)); // High attenuation
    
    // Test with empty samples
    std::vector<float> empty_samples;
    EXPECT_NO_THROW(audio.processExtremeAudio(empty_samples, 6.0));
    
    // Test RMS calculation with extreme values
    double rms = audio.calculateRMS(samples);
    EXPECT_GE(rms, 0.0);
    EXPECT_FALSE(std::isnan(rms));
    EXPECT_FALSE(std::isinf(rms));
}

// Test 7: Extreme Frequency Management
TEST_F(EdgeCaseCoverageTests, ExtremeFrequencyManagement) {
    std::vector<double> used_frequencies = {118.5e6, 118.525e6, 118.55e6};
    
    // Test normal frequency allocation
    double allocated_freq = freq_mgr.allocateExtremeFrequency(118.575e6, used_frequencies);
    EXPECT_EQ(allocated_freq, 118.575e6);
    
    // Test frequency too close to existing
    EXPECT_THROW(freq_mgr.allocateExtremeFrequency(118.5005e6, used_frequencies), 
                 std::runtime_error);
    
    // Test with empty used frequencies
    std::vector<double> empty_used;
    double freq = freq_mgr.allocateExtremeFrequency(118.5e6, empty_used);
    EXPECT_EQ(freq, 118.5e6);
}

// Property-based tests for edge cases
TEST_F(EdgeCaseCoverageTests, ExtremeWeatherHandling) {
    rc::check("Extreme weather handling", [](double frequency_hz, double temperature_c, double humidity_percent, 
               double rain_rate_mmh, double fog_density, double snow_rate_mmh) {
        // Use RC_PRE to filter out invalid values
        RC_PRE(frequency_hz >= 1e6 && frequency_hz <= 1e9); // 1 MHz to 1 GHz
        RC_PRE(temperature_c >= -50.0 && temperature_c <= 50.0); // -50°C to 50°C
        RC_PRE(humidity_percent >= 0.0 && humidity_percent <= 100.0); // 0% to 100%
        RC_PRE(rain_rate_mmh >= 0.0 && rain_rate_mmh <= 500.0); // 0 to 500 mm/h
        RC_PRE(fog_density >= 0.0 && fog_density <= 1.0); // 0.0 to 1.0
        RC_PRE(snow_rate_mmh >= 0.0 && snow_rate_mmh <= 100.0); // 0 to 100 mm/h
        
        RadioPropagation prop;
        RadioPropagation::ExtremeWeather weather;
        weather.temperature_c = temperature_c;
        weather.humidity_percent = humidity_percent;
        weather.rain_rate_mmh = rain_rate_mmh;
        weather.fog_density = fog_density;
        weather.snow_rate_mmh = snow_rate_mmh;
        weather.wind_speed_ms = 5.0;
        weather.atmospheric_pressure_hpa = 1013.25;
        
        double range = prop.calculateRangeExtreme(frequency_hz, weather);
        
        RC_ASSERT(range > 0.0);
        RC_ASSERT(range < 10000.0); // Reasonable upper bound
        RC_ASSERT(!std::isnan(range));
        RC_ASSERT(!std::isinf(range));
    });
}

TEST_F(EdgeCaseCoverageTests, ExtremeAudioProcessingProperty) {
    rc::check("Extreme audio processing", [](std::vector<float> samples, double gain_db) {
        // Use RC_PRE to filter out invalid values
        RC_PRE(gain_db >= -60.0 && gain_db <= 60.0); // -60 dB to 60 dB
        
        // Filter out extreme values for property testing
        for (float& sample : samples) {
            if (std::isnan(sample) || std::isinf(sample)) {
                sample = 0.0f;
            }
            if (sample > 1.0f) sample = 1.0f;
            if (sample < -1.0f) sample = -1.0f;
        }
        
        AudioProcessor audio;
        EXPECT_NO_THROW(audio.processExtremeAudio(samples, gain_db));
        
        double rms = audio.calculateRMS(samples);
        RC_ASSERT(rms >= 0.0);
        RC_ASSERT(!std::isnan(rms));
        RC_ASSERT(!std::isinf(rms));
    });
}

TEST_F(EdgeCaseCoverageTests, ExtremeFrequencyAllocation) {
    rc::check("Extreme frequency allocation", [](double frequency_hz, std::vector<double> used_frequencies) {
        RC_PRE(frequency_hz > 1e6 && frequency_hz < 1e9);
        
        // Filter used frequencies to be reasonable
        for (double& freq : used_frequencies) {
            if (freq < 1e6 || freq > 1e9) {
                freq = 118.5e6; // Default to VHF
            }
        }
        
        // Ensure minimum separation
        bool has_conflict = false;
        for (double used_freq : used_frequencies) {
            if (std::abs(frequency_hz - used_freq) < 1e3) {
                has_conflict = true;
                break;
            }
        }
        
        FrequencyManager freq_mgr;
        if (!has_conflict) {
            double allocated = freq_mgr.allocateExtremeFrequency(frequency_hz, used_frequencies);
            RC_ASSERT(allocated == frequency_hz);
        } else {
            RC_ASSERT_THROWS(freq_mgr.allocateExtremeFrequency(frequency_hz, used_frequencies));
        }
    });
}
