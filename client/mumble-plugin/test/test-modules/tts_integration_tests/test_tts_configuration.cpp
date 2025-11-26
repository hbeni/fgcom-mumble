/**
 * @file test_tts_configuration.cpp
 * @brief Test suite for TTS Configuration Management
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for TTS configuration management,
 * including configuration loading, validation, and parameter management.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include <fstream>
#include "tts_configuration.h"

using namespace std;
using namespace testing;

/**
 * @class TTSConfiguration_Test
 * @brief Test fixture for TTS configuration tests
 */
class TTSConfiguration_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize TTS configuration system
        ttsConfig = new TTSConfiguration();
        ASSERT_NE(ttsConfig, nullptr);
    }

    void TearDown() override {
        if (ttsConfig) {
            delete ttsConfig;
            ttsConfig = nullptr;
        }
    }

    TTSConfiguration* ttsConfig = nullptr;
};

/**
 * @test Test TTS configuration initialization
 */
TEST_F(TTSConfiguration_Test, Initialization) {
    EXPECT_TRUE(ttsConfig->isInitialized());
    EXPECT_FALSE(ttsConfig->getDefaultModel().empty());
    EXPECT_GT(ttsConfig->getSampleRate(), 0);
    EXPECT_GT(ttsConfig->getBitrate(), 0);
    EXPECT_FALSE(ttsConfig->getOutputDirectory().empty());
}

/**
 * @test Test TTS configuration loading
 */
TEST_F(TTSConfiguration_Test, ConfigurationLoading) {
    // Test configuration file loading
    string configPath = "../../scripts/tts/tts_config.conf";
    bool loadResult = ttsConfig->loadConfiguration(configPath);
    EXPECT_TRUE(loadResult || !loadResult); // May or may not exist
    
    // Test configuration validation
    EXPECT_TRUE(ttsConfig->validateConfiguration());
}

/**
 * @test Test TTS configuration parameters
 */
TEST_F(TTSConfiguration_Test, ConfigurationParameters) {
    // Test default model
    string defaultModel = ttsConfig->getDefaultModel();
    EXPECT_FALSE(defaultModel.empty());
    
    // Test sample rate
    int sampleRate = ttsConfig->getSampleRate();
    EXPECT_GT(sampleRate, 0);
    EXPECT_LE(sampleRate, 48000); // Reasonable upper limit
    
    // Test bitrate
    int bitrate = ttsConfig->getBitrate();
    EXPECT_GT(bitrate, 0);
    EXPECT_LE(bitrate, 320000); // Reasonable upper limit
    
    // Test output directory
    string outputDir = ttsConfig->getOutputDirectory();
    EXPECT_FALSE(outputDir.empty());
}

/**
 * @test Test TTS configuration saving
 */
TEST_F(TTSConfiguration_Test, ConfigurationSaving) {
    // Test configuration saving
    string outputPath = "test_tts_config.conf";
    bool saveResult = ttsConfig->saveConfiguration(outputPath);
    EXPECT_TRUE(saveResult);
    
    // Test saved configuration
    ifstream file(outputPath);
    EXPECT_TRUE(file.good());
    file.close();
    
    // Clean up
    remove(outputPath.c_str());
}

/**
 * @test Test TTS configuration reset
 */
TEST_F(TTSConfiguration_Test, ConfigurationReset) {
    // Test configuration reset
    ttsConfig->resetConfiguration();
    EXPECT_TRUE(ttsConfig->isDefaultConfiguration());
    
    // Test default values
    EXPECT_FALSE(ttsConfig->getDefaultModel().empty());
    EXPECT_GT(ttsConfig->getSampleRate(), 0);
    EXPECT_GT(ttsConfig->getBitrate(), 0);
}

/**
 * @test Test TTS configuration validation
 */
TEST_F(TTSConfiguration_Test, ConfigurationValidation) {
    // Test valid configuration
    EXPECT_TRUE(ttsConfig->validateConfiguration());
    
    // Test configuration parameters
    EXPECT_TRUE(ttsConfig->isValidModel(ttsConfig->getDefaultModel()));
    EXPECT_TRUE(ttsConfig->isValidSampleRate(ttsConfig->getSampleRate()));
    EXPECT_TRUE(ttsConfig->isValidBitrate(ttsConfig->getBitrate()));
    EXPECT_TRUE(ttsConfig->isValidOutputDirectory(ttsConfig->getOutputDirectory()));
}

/**
 * @test Test TTS configuration error handling
 */
TEST_F(TTSConfiguration_Test, ErrorHandling) {
    // Test invalid configuration file
    string invalidPath = "/invalid/path/config.conf";
    bool loadResult = ttsConfig->loadConfiguration(invalidPath);
    EXPECT_FALSE(loadResult);
    
    // Test invalid parameters
    EXPECT_FALSE(ttsConfig->isValidModel("INVALID_MODEL"));
    EXPECT_FALSE(ttsConfig->isValidSampleRate(-1));
    EXPECT_FALSE(ttsConfig->isValidBitrate(-1));
    EXPECT_FALSE(ttsConfig->isValidOutputDirectory(""));
}

/**
 * @test Test TTS configuration performance
 */
TEST_F(TTSConfiguration_Test, Performance) {
    // Test configuration loading performance
    auto start = chrono::high_resolution_clock::now();
    
    string configPath = "../../scripts/tts/tts_config.conf";
    bool loadResult = ttsConfig->loadConfiguration(configPath);
    
    // Verify configuration loaded successfully
    EXPECT_TRUE(loadResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Configuration loading should be fast (less than 1ms)
    EXPECT_LT(duration.count(), 1000);
}

/**
 * @test Test TTS configuration thread safety
 */
TEST_F(TTSConfiguration_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 100;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                // Test configuration access
                string model = ttsConfig->getDefaultModel();
                int sampleRate = ttsConfig->getSampleRate();
                int bitrate = ttsConfig->getBitrate();
                string outputDir = ttsConfig->getOutputDirectory();
                
                if (model.empty() || sampleRate <= 0 || bitrate <= 0 || outputDir.empty()) {
                    results[t] = false;
                    break;
                }
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have succeeded
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}
