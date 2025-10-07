#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <limits>

// Include the actual AGC/Squelch implementation
#include "../../client/mumble-plugin/lib/agc_squelch.h"

// Thread-safe test utilities
class ThreadSafeTestUtils {
public:
    // Removed unused validateFloatValue function
    
    static void validatePositiveFloat(float value, const std::string& param_name) {
        if (std::isnan(value) || std::isinf(value) || value <= 0.0f) {
            throw std::invalid_argument(param_name + " must be a positive finite number");
        }
    }
    
    static void validateNonNegativeFloat(float value, const std::string& param_name) {
        if (std::isnan(value) || std::isinf(value) || value < 0.0f) {
            throw std::invalid_argument(param_name + " must be a non-negative finite number");
        }
    }
};

// Test fixtures and utilities with proper error handling
class AGC_Squelch_Test : public ::testing::Test {
protected:
    void SetUp() override {
        try {
            // Reset AGC state for test isolation using comprehensive reset method
            FGCom_AGC_Squelch& agc = FGCom_AGC_Squelch::getInstance();
            agc.resetToDefaultState();  // Complete reset to default state
        } catch (const std::exception& e) {
            // Log but don't fail setup
            std::cerr << "Warning: Exception during setup: " << e.what() << std::endl;
        }
    }
    
    // TearDown removed - not needed as tests are self-contained
    
    // Helper functions for test data generation with proper validation
    std::vector<float> generateSineWave(float frequency, float sample_rate, size_t samples, float amplitude = 1.0f) {
        // Validate inputs
        ThreadSafeTestUtils::validatePositiveFloat(frequency, "frequency");
        ThreadSafeTestUtils::validatePositiveFloat(sample_rate, "sample_rate");
        ThreadSafeTestUtils::validateNonNegativeFloat(amplitude, "amplitude");
        
        if (samples == 0) {
            throw std::invalid_argument("samples must be greater than 0");
        }
        
        std::vector<float> wave;
        wave.reserve(samples); // Pre-allocate to avoid reallocations
        
        for (size_t i = 0; i < samples; ++i) {
            float sample = amplitude * std::sin(2.0f * M_PI * frequency * i / sample_rate);
            // Clamp to prevent overflow
            sample = std::max(-1.0f, std::min(1.0f, sample));
            wave.push_back(sample);
        }
        return wave;
    }
    
    // generateNoise function removed - not used
    
    std::vector<float> generateSilence(size_t samples) {
        if (samples == 0) {
            throw std::invalid_argument("samples must be greater than 0");
        }
        return std::vector<float>(samples, 0.0f);
    }
    
    // measureTime function removed - not used
};

// Thread-safe test suite base class
class ThreadSafeTestSuite : public AGC_Squelch_Test {
protected:
    void SetUp() override {
        AGC_Squelch_Test::SetUp();
        // Get instance safely with error handling
        try {
            agc_instance = &FGCom_AGC_Squelch::getInstance();
            if (agc_instance == nullptr) {
                throw std::runtime_error("Failed to get AGC/Squelch instance");
            }
        } catch (const std::exception& e) {
            FAIL() << "Failed to initialize AGC/Squelch instance: " << e.what();
        }
    }
    
    // Thread-safe access to AGC instance
    FGCom_AGC_Squelch& getAGC() {
        if (agc_instance == nullptr) {
            throw std::runtime_error("AGC instance not initialized");
        }
        return *agc_instance;
    }
    
    // Validate AGC instance is valid
    bool isAGCValid() const {
        return agc_instance != nullptr;
    }
    
private:
    FGCom_AGC_Squelch* agc_instance = nullptr;
};

// Test suite for singleton pattern
class SingletonTest : public AGC_Squelch_Test {
protected:
    void SetUp() override {
        AGC_Squelch_Test::SetUp();
    }
};

// Test suite for AGC configuration
class AGCConfigTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for Squelch configuration  
class SquelchConfigTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for audio processing
class AudioProcessingTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for mathematical functions
class MathFunctionTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for thread safety
class ThreadSafetyTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for JSON API
class JSONAPITest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Test suite for memory and performance
class MemoryPerformanceTest : public ThreadSafeTestSuite {
protected:
    void SetUp() override {
        ThreadSafeTestSuite::SetUp();
    }
};

// Main function moved to separate main.cpp file to avoid multiple definitions
