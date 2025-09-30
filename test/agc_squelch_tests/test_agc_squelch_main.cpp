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
    static void validateFloatValue(float value, float min_val, float max_val, const std::string& param_name) {
        if (std::isnan(value) || std::isinf(value)) {
            throw std::invalid_argument(param_name + " cannot be NaN or infinity");
        }
        if (value < min_val || value > max_val) {
            throw std::out_of_range(param_name + " must be between " + std::to_string(min_val) + " and " + std::to_string(max_val));
        }
    }
    
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
            // Clean up any existing instance safely
            FGCom_AGC_Squelch::destroyInstance();
        } catch (const std::exception& e) {
            // Log but don't fail setup for destroy operations
            std::cerr << "Warning: Exception during cleanup in SetUp: " << e.what() << std::endl;
        }
    }
    
    void TearDown() override {
        try {
            // Clean up after each test safely
            FGCom_AGC_Squelch::destroyInstance();
        } catch (const std::exception& e) {
            // Log but don't fail teardown
            std::cerr << "Warning: Exception during cleanup in TearDown: " << e.what() << std::endl;
        }
    }
    
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
    
    std::vector<float> generateNoise(size_t samples, float amplitude = 0.1f) {
        // Validate inputs
        ThreadSafeTestUtils::validateNonNegativeFloat(amplitude, "amplitude");
        
        if (samples == 0) {
            throw std::invalid_argument("samples must be greater than 0");
        }
        
        std::vector<float> noise;
        noise.reserve(samples); // Pre-allocate to avoid reallocations
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<float> dis(0.0f, amplitude);
        
        for (size_t i = 0; i < samples; ++i) {
            float sample = dis(gen);
            // Clamp to prevent extreme values
            sample = std::max(-1.0f, std::min(1.0f, sample));
            noise.push_back(sample);
        }
        return noise;
    }
    
    std::vector<float> generateSilence(size_t samples) {
        if (samples == 0) {
            throw std::invalid_argument("samples must be greater than 0");
        }
        return std::vector<float>(samples, 0.0f);
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
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
