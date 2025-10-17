/**
 * @file test_granit.cpp
 * @brief Test suite for Granit Soviet Time-Scrambling Voice Encryption System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the Granit Soviet time-scrambling
 * voice encryption system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - Time-domain segment scrambling and descrambling
 * - Pilot signal synchronization
 * - Temporal distortion effects
 * - Key management and validation
 * - Audio processing and filtering
 * - Soviet audio characteristics (segmented, time-jumped sound)
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see granit.h
 * @see docs/GRANIT_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../systems/granit/include/granit.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom::granit;

/**
 * @brief Test suite for Granit system
 * 
 * @details
 * This test suite provides comprehensive testing of the Granit
 * Soviet time-scrambling voice encryption system.
 */
using namespace testing;

class GranitTest : public ::testing::Test {
protected:
    void SetUp() override {
        granit = std::make_unique<Granit>();
    }
    
    void TearDown() override {
        granit.reset();
    }
    
    std::unique_ptr<Granit> granit;
};

/**
 * @brief Test Granit initialization
 * 
 * @details
 * Tests the initialization of the Granit system with various
 * audio parameters and configurations.
 */
TEST_F(GranitTest, Initialization) {
    // Test successful initialization
    EXPECT_TRUE(granit->initialize(44100.0f, 1));
    EXPECT_TRUE(granit->isInitialized());
    
    // Test invalid parameters
    EXPECT_FALSE(granit->initialize(0.0f, 1));
    EXPECT_FALSE(granit->initialize(44100.0f, 0));
    
    // Test re-initialization
    EXPECT_TRUE(granit->initialize(48000.0f, 2));
    EXPECT_TRUE(granit->isInitialized());
}

/**
 * @brief Test time-segment processing
 * 
 * @details
 * Tests the time-segment processing functionality including
 * segmentation, scrambling, and reconstruction.
 */
TEST_F(GranitTest, TimeSegmentProcessing) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test time segmentation
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    std::vector<std::vector<float>> segments = GranitUtils::generateTimeSegments(
        input_audio, 882, 0.5f); // 20 ms segments with 50% overlap
    
    EXPECT_FALSE(segments.empty());
    EXPECT_GT(segments.size(), 1);
    
    // Test segment reconstruction
    std::vector<float> reconstructed_audio = GranitUtils::reconstructFromSegments(segments, 0.5f);
    
    EXPECT_FALSE(reconstructed_audio.empty());
    EXPECT_GT(reconstructed_audio.size(), 0);
}

/**
 * @brief Test scrambling sequence generation
 * 
 * @details
 * Tests the scrambling sequence generation and application
 * for time-domain scrambling.
 */
TEST_F(GranitTest, ScramblingSequence) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test scrambling sequence generation
    std::vector<uint32_t> sequence = GranitUtils::generateScramblingSequence(64, 8);
    
    EXPECT_FALSE(sequence.empty());
    EXPECT_EQ(sequence.size(), 8);
    
    // Test sequence uniqueness
    std::set<uint32_t> unique_values(sequence.begin(), sequence.end());
    EXPECT_EQ(unique_values.size(), sequence.size());
    
    // Test scrambling parameters
    EXPECT_TRUE(granit->setScramblingParameters(882, 8, 1500.0f));
    EXPECT_TRUE(granit->isScramblingActive());
}

/**
 * @brief Test time scrambling functionality
 * 
 * @details
 * Tests the time-domain scrambling and descrambling
 * functionality.
 */
TEST_F(GranitTest, TimeScrambling) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Generate test segments
    std::vector<std::vector<float>> segments;
    for (int i = 0; i < 8; ++i) {
        std::vector<float> segment(882, static_cast<float>(i));
        segments.push_back(segment);
    }
    
    // Generate scrambling sequence
    std::vector<uint32_t> scrambling_sequence = {7, 3, 1, 5, 2, 6, 0, 4};
    
    // Test time scrambling
    std::vector<std::vector<float>> scrambled_segments = GranitUtils::applyTimeScrambling(
        segments, scrambling_sequence);
    
    EXPECT_FALSE(scrambled_segments.empty());
    EXPECT_EQ(scrambled_segments.size(), segments.size());
    
    // Test time descrambling
    std::vector<std::vector<float>> descrambled_segments = GranitUtils::applyTimeDescrambling(
        scrambled_segments, scrambling_sequence);
    
    EXPECT_FALSE(descrambled_segments.empty());
    EXPECT_EQ(descrambled_segments.size(), segments.size());
}

/**
 * @brief Test pilot signal functionality
 * 
 * @details
 * Tests the pilot signal generation and synchronization
 * functionality.
 */
TEST_F(GranitTest, PilotSignal) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test pilot signal generation
    std::vector<float> pilot_signal = GranitUtils::generatePilotSignal(
        1500.0f, 0.1f, 44100.0f, 1.0f);
    
    EXPECT_FALSE(pilot_signal.empty());
    EXPECT_EQ(pilot_signal.size(), 44100);
    
    // Test pilot signal properties
    for (float sample : pilot_signal) {
        EXPECT_GE(sample, -0.1f);
        EXPECT_LE(sample, 0.1f);
    }
    
    // Test pilot signal configuration
    granit->setPilotSignal(1500.0f, 0.1f);
    EXPECT_TRUE(granit->isPilotActive());
}

/**
 * @brief Test temporal distortion effects
 * 
 * @details
 * Tests the temporal distortion effects characteristic
 * of the Granit system.
 */
TEST_F(GranitTest, TemporalDistortion) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test temporal distortion configuration
    granit->setTemporalDistortion(0.8f);
    
    // Generate test audio
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test temporal distortion application
    std::vector<float> distorted_audio = input_audio;
    GranitUtils::applyTemporalDistortion(distorted_audio, 0.8f);
    
    EXPECT_FALSE(distorted_audio.empty());
    EXPECT_EQ(distorted_audio.size(), input_audio.size());
    
    // Test distortion effects
    float input_rms = 0.0f;
    float distorted_rms = 0.0f;
    
    for (size_t i = 0; i < input_audio.size(); ++i) {
        input_rms += input_audio[i] * input_audio[i];
        distorted_rms += distorted_audio[i] * distorted_audio[i];
    }
    
    input_rms = std::sqrt(input_rms / input_audio.size());
    distorted_rms = std::sqrt(distorted_rms / distorted_audio.size());
    
    // Distorted audio should have different RMS
    EXPECT_NE(input_rms, distorted_rms);
}

/**
 * @brief Test audio encryption and decryption
 * 
 * @details
 * Tests the complete audio encryption and decryption process
 * using the Granit system.
 */
TEST_F(GranitTest, AudioEncryptionDecryption) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Set up scrambling
    granit->setScramblingParameters(882, 8, 1500.0f);
    granit->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate test audio
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test encryption
    std::vector<float> encrypted_audio = granit->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test decryption
    std::vector<float> decrypted_audio = granit->decrypt(encrypted_audio);
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), input_audio.size());
    
    // Test audio integrity (simplified)
    float input_rms = 0.0f;
    float decrypted_rms = 0.0f;
    
    for (size_t i = 0; i < input_audio.size(); ++i) {
        input_rms += input_audio[i] * input_audio[i];
        decrypted_rms += decrypted_audio[i] * decrypted_audio[i];
    }
    
    input_rms = std::sqrt(input_rms / input_audio.size());
    decrypted_rms = std::sqrt(decrypted_rms / decrypted_audio.size());
    
    // Allow for some difference due to processing
    EXPECT_NEAR(input_rms, decrypted_rms, 0.1f);
}

/**
 * @brief Test Soviet audio effects
 * 
 * @details
 * Tests the distinctive Soviet audio effects including temporal
 * distortion and segment scrambling.
 */
TEST_F(GranitTest, SovietAudioEffects) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test temporal distortion
    std::vector<float> temporal_audio = input_audio;
    GranitUtils::applyTemporalDistortion(temporal_audio, 0.8f);
    
    EXPECT_FALSE(temporal_audio.empty());
    EXPECT_EQ(temporal_audio.size(), input_audio.size());
    
    // Test segment scrambling
    std::vector<float> scrambled_audio = input_audio;
    std::vector<uint32_t> scrambling_sequence = {7, 3, 1, 5, 2, 6, 0, 4};
    GranitUtils::applySegmentScrambling(scrambled_audio, 882, scrambling_sequence);
    
    EXPECT_FALSE(scrambled_audio.empty());
    EXPECT_EQ(scrambled_audio.size(), input_audio.size());
    
    // Test Soviet effects
    std::vector<float> soviet_audio = input_audio;
    GranitUtils::applySovietEffects(soviet_audio);
    
    EXPECT_FALSE(soviet_audio.empty());
    EXPECT_EQ(soviet_audio.size(), input_audio.size());
}

/**
 * @brief Test key management functionality
 * 
 * @details
 * Tests the key management system including key loading,
 * saving, and validation.
 */
TEST_F(GranitTest, KeyManagement) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test key setting
    std::string key_data = "01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(granit->setKey(12345, key_data));
    EXPECT_TRUE(granit->isScramblingActive());
    
    // Test key validation
    EXPECT_TRUE(granit->validateKey(key_data));
    
    // Test invalid key
    std::string invalid_key = "invalid key data";
    EXPECT_FALSE(granit->validateKey(invalid_key));
    
    // Test key info
    std::string key_info = granit->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test audio processing functionality
 * 
 * @details
 * Tests the audio processing capabilities including filtering,
 * window functions, and effects.
 */
TEST_F(GranitTest, AudioProcessing) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test frequency response filtering
    std::vector<float> filtered_audio = input_audio;
    GranitUtils::applyFrequencyResponse(filtered_audio, 44100.0f, 300.0f, 3400.0f);
    
    EXPECT_FALSE(filtered_audio.empty());
    EXPECT_EQ(filtered_audio.size(), input_audio.size());
    
    // Test window function
    std::vector<float> window = GranitUtils::generateWindowFunction("hanning", 1024);
    EXPECT_FALSE(window.empty());
    EXPECT_EQ(window.size(), 1024);
    
    // Test window application
    std::vector<float> windowed_audio = input_audio;
    GranitUtils::applyWindowFunction(windowed_audio, window);
    
    EXPECT_FALSE(windowed_audio.empty());
    EXPECT_EQ(windowed_audio.size(), input_audio.size());
}

/**
 * @brief Test system status and diagnostics
 * 
 * @details
 * Tests the system status reporting and diagnostic capabilities.
 */
TEST_F(GranitTest, SystemStatus) {
    // Test uninitialized system
    EXPECT_FALSE(granit->isInitialized());
    EXPECT_FALSE(granit->isScramblingActive());
    EXPECT_FALSE(granit->isPilotActive());
    
    // Test initialized system
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    EXPECT_TRUE(granit->isInitialized());
    EXPECT_FALSE(granit->isScramblingActive());
    EXPECT_FALSE(granit->isPilotActive());
    
    // Test system with key
    granit->setKey(12345, "01 23 45 67 89 AB CD EF");
    EXPECT_TRUE(granit->isInitialized());
    EXPECT_TRUE(granit->isScramblingActive());
    
    // Test system with pilot signal
    granit->setPilotSignal(1500.0f, 0.1f);
    EXPECT_TRUE(granit->isPilotActive());
    
    // Test status reporting
    std::string status = granit->getStatus();
    EXPECT_FALSE(status.empty());
    EXPECT_NE(status.find("Granit"), std::string::npos);
    
    // Test key info
    std::string key_info = granit->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test error handling and edge cases
 * 
 * @details
 * Tests the system's error handling capabilities and edge cases.
 */
TEST_F(GranitTest, ErrorHandling) {
    // Test initialization with invalid parameters
    EXPECT_FALSE(granit->initialize(0.0f, 1));
    EXPECT_FALSE(granit->initialize(44100.0f, 0));
    
    // Test operations on uninitialized system
    EXPECT_FALSE(granit->setKey(12345, "test_key"));
    EXPECT_FALSE(granit->setScramblingParameters(882, 8, 1500.0f));
    EXPECT_FALSE(granit->validateKey("test_key"));
    
    // Test encryption/decryption on uninitialized system
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> result = granit->encrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    result = granit->decrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    // Test with empty audio
    std::vector<float> empty_audio;
    result = granit->encrypt(empty_audio);
    EXPECT_TRUE(result.empty());
    
    result = granit->decrypt(empty_audio);
    EXPECT_TRUE(result.empty());
}

/**
 * @brief Test utility functions
 * 
 * @details
 * Tests the utility functions for the Granit system.
 */
TEST_F(GranitTest, UtilityFunctions) {
    // Test test tone generation
    std::vector<float> tone = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(tone.empty());
    EXPECT_EQ(tone.size(), 44100);
    
    // Test noise generation
    std::vector<float> noise = GranitUtils::generateNoise(44100.0f, 1.0f);
    EXPECT_FALSE(noise.empty());
    EXPECT_EQ(noise.size(), 44100);
    
    // Test chirp generation
    std::vector<float> chirp = GranitUtils::generateChirp(100.0f, 1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(chirp.empty());
    EXPECT_EQ(chirp.size(), 44100);
    
    // Test key data parsing
    std::string key_data = "01 23 45 67 89 AB CD EF";
    std::vector<uint8_t> key_bytes = GranitUtils::parseKeyData(key_data);
    EXPECT_FALSE(key_bytes.empty());
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key data generation
    std::string generated_key = GranitUtils::generateKeyData(key_bytes);
    EXPECT_FALSE(generated_key.empty());
    EXPECT_EQ(generated_key, key_data);
    
    // Test key format validation
    EXPECT_TRUE(GranitUtils::validateKeyFormat(key_data));
    EXPECT_FALSE(GranitUtils::validateKeyFormat("invalid key"));
    
    // Test window function generation
    std::vector<float> hanning_window = GranitUtils::generateWindowFunction("hanning", 1024);
    EXPECT_FALSE(hanning_window.empty());
    EXPECT_EQ(hanning_window.size(), 1024);
    
    std::vector<float> hamming_window = GranitUtils::generateWindowFunction("hamming", 1024);
    EXPECT_FALSE(hamming_window.empty());
    EXPECT_EQ(hamming_window.size(), 1024);
    
    std::vector<float> blackman_window = GranitUtils::generateWindowFunction("blackman", 1024);
    EXPECT_FALSE(blackman_window.empty());
    EXPECT_EQ(blackman_window.size(), 1024);
}

/**
 * @brief Test performance characteristics
 * 
 * @details
 * Tests the performance characteristics of the Granit system
 * including processing speed and memory usage.
 */
TEST_F(GranitTest, PerformanceCharacteristics) {
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    granit->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate large audio buffer
    std::vector<float> large_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 10.0f);
    
    // Test encryption performance
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> encrypted_audio = granit->encrypt(large_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), large_audio.size());
    EXPECT_LT(duration.count(), 2000); // Should complete within 2 seconds
    
    // Test decryption performance
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = granit->decrypt(encrypted_audio);
    end_time = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), encrypted_audio.size());
    EXPECT_LT(duration.count(), 2000); // Should complete within 2 seconds
}

/**
 * @brief Test integration with voice encryption module
 * 
 * @details
 * Tests the integration of the Granit system with the
 * broader voice encryption module.
 */
TEST_F(GranitTest, ModuleIntegration) {
    // Test system initialization
    ASSERT_TRUE(granit->initialize(44100.0f, 1));
    
    // Test scrambling setup
    granit->setScramblingParameters(882, 8, 1500.0f);
    granit->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Test audio processing pipeline
    std::vector<float> input_audio = GranitUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test complete encryption pipeline
    std::vector<float> encrypted_audio = granit->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test complete decryption pipeline
    std::vector<float> decrypted_audio = granit->decrypt(encrypted_audio);
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), input_audio.size());
    
    // Test system status
    EXPECT_TRUE(granit->isInitialized());
    EXPECT_TRUE(granit->isScramblingActive());
    
    // Test status reporting
    std::string status = granit->getStatus();
    EXPECT_FALSE(status.empty());
    
    std::string key_info = granit->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
}

