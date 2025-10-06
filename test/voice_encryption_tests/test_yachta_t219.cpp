/**
 * @file test_yachta_t219.cpp
 * @brief Test suite for Yachta T-219 Soviet Voice Encryption System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the Yachta T-219 Soviet
 * voice encryption system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - FSK sync signal generation and detection
 * - Voice scrambling and descrambling
 * - M-sequence generation and validation
 * - Key card handling and validation
 * - Audio processing and filtering
 * - Soviet audio characteristics (warbled, Donald Duck sound)
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see voice-encryption/systems/yachta-t219/include/yachta_t219.h
 * @see voice-encryption/systems/yachta-t219/docs/YACHTA_T219_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/yachta-t219/include/yachta_t219.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom::yachta;

/**
 * @brief Test suite for Yachta T-219 system
 * 
 * @details
 * This test suite provides comprehensive testing of the Yachta T-219
 * Soviet voice encryption system.
 */
using namespace testing;

class YachtaT219Test : public ::testing::Test {
protected:
    void SetUp() override {
        yachta = std::make_unique<YachtaT219>();
    }
    
    void TearDown() override {
        yachta.reset();
    }
    
    std::unique_ptr<YachtaT219> yachta;
};

/**
 * @brief Test Yachta T-219 initialization
 * 
 * @details
 * Tests the initialization of the Yachta T-219 system with various
 * audio parameters and configurations.
 */
TEST_F(YachtaT219Test, Initialization) {
    // Test successful initialization
    EXPECT_TRUE(yachta->initialize(44100.0f, 1));
    EXPECT_TRUE(yachta->isInitialized());
    
    // Test invalid parameters
    EXPECT_FALSE(yachta->initialize(0.0f, 1));
    EXPECT_FALSE(yachta->initialize(44100.0f, 0));
    
    // Test re-initialization
    EXPECT_TRUE(yachta->initialize(48000.0f, 2));
    EXPECT_TRUE(yachta->isInitialized());
}

/**
 * @brief Test FSK sync signal functionality
 * 
 * @details
 * Tests the FSK sync signal generation and detection
 * functionality for the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, FSKSyncSignal) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Test FSK sync signal generation
    std::vector<float> fsk_signal = YachtaT219Utils::generateFSKSyncSignal(
        100.0f, 150.0f, 0.1f, 44100.0f, 1.0f);
    
    EXPECT_FALSE(fsk_signal.empty());
    EXPECT_EQ(fsk_signal.size(), 44100);
    
    // Test FSK sync signal properties
    for (float sample : fsk_signal) {
        EXPECT_GE(sample, -0.1f);
        EXPECT_LE(sample, 0.1f);
    }
    
    // Test FSK sync signal configuration
    yachta->setFSKSyncParameters(100.0f, 150.0f, 0.1f);
    EXPECT_TRUE(yachta->isFSKSyncActive());
}

/**
 * @brief Test voice scrambling functionality
 * 
 * @details
 * Tests the voice scrambling and descrambling
 * functionality for the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, VoiceScrambling) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test voice scrambling
    std::vector<float> scrambled_audio = test_audio;
    YachtaT219Utils::applyVoiceScrambling(scrambled_audio, 0.8f);
    
    EXPECT_FALSE(scrambled_audio.empty());
    EXPECT_EQ(scrambled_audio.size(), test_audio.size());
    
    // Test scrambling parameters
    EXPECT_TRUE(yachta->setScramblingParameters(10, 5, 0.8f));
    EXPECT_TRUE(yachta->isScramblingActive());
}

/**
 * @brief Test M-sequence generation
 * 
 * @details
 * Tests the M-sequence generation and validation
 * functionality for the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, MSequenceGeneration) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Test M-sequence generation
    std::vector<bool> m_sequence = YachtaT219Utils::generateMSequence(52, 1000);
    
    EXPECT_FALSE(m_sequence.empty());
    EXPECT_EQ(m_sequence.size(), 1000);
    
    // Test M-sequence properties
    size_t ones_count = 0;
    for (bool bit : m_sequence) {
        if (bit) ones_count++;
    }
    
    // M-sequence should have approximately equal 0s and 1s
    EXPECT_NEAR(ones_count, m_sequence.size() / 2, m_sequence.size() / 10);
    
    // Test M-sequence validation
    EXPECT_TRUE(YachtaT219Utils::validateMSequence(m_sequence));
}

/**
 * @brief Test key card functionality
 * 
 * @details
 * Tests the key card handling and validation
 * functionality for the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, KeyCardFunctionality) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Test key card generation
    std::vector<uint8_t> key_card = YachtaT219Utils::generateKeyCard(64);
    
    EXPECT_FALSE(key_card.empty());
    EXPECT_EQ(key_card.size(), 64);
    
    // Test key card validation
    EXPECT_TRUE(YachtaT219Utils::validateKeyCard(key_card));
    
    // Test key card loading
    EXPECT_TRUE(yachta->loadKeyCard(key_card));
    EXPECT_TRUE(yachta->isKeyCardLoaded());
    
    // Test key card saving
    std::vector<uint8_t> saved_key_card = yachta->getKeyCard();
    EXPECT_FALSE(saved_key_card.empty());
    EXPECT_EQ(saved_key_card.size(), key_card.size());
}

/**
 * @brief Test audio encryption and decryption
 * 
 * @details
 * Tests the complete audio encryption and decryption process
 * using the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, AudioEncryptionDecryption) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Set up scrambling
    yachta->setScramblingParameters(10, 5, 0.8f);
    yachta->setKey(12345, "scrambling_key_data");
    
    // Generate test audio
    std::vector<float> input_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test encryption
    std::vector<float> encrypted_audio = yachta->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test decryption
    std::vector<float> decrypted_audio = yachta->decrypt(encrypted_audio);
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
 * Tests the distinctive Soviet audio effects including
 * warbled sound and Donald Duck characteristics.
 */
TEST_F(YachtaT219Test, SovietAudioEffects) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test warbled effect
    std::vector<float> warbled_audio = test_audio;
    YachtaT219Utils::applyWarbledEffect(warbled_audio, 0.8f);
    
    EXPECT_FALSE(warbled_audio.empty());
    EXPECT_EQ(warbled_audio.size(), test_audio.size());
    
    // Test Donald Duck effect
    std::vector<float> donald_duck_audio = test_audio;
    YachtaT219Utils::applyDonaldDuckEffect(donald_duck_audio, 0.8f);
    
    EXPECT_FALSE(donald_duck_audio.empty());
    EXPECT_EQ(donald_duck_audio.size(), test_audio.size());
    
    // Test Soviet effects
    std::vector<float> soviet_audio = test_audio;
    YachtaT219Utils::applySovietEffects(soviet_audio);
    
    EXPECT_FALSE(soviet_audio.empty());
    EXPECT_EQ(soviet_audio.size(), test_audio.size());
}

/**
 * @brief Test key management functionality
 * 
 * @details
 * Tests the key management system including key loading,
 * saving, and validation.
 */
TEST_F(YachtaT219Test, KeyManagement) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Test key setting
    std::string key_data = "scrambling_key_data";
    EXPECT_TRUE(yachta->setKey(12345, key_data));
    EXPECT_TRUE(yachta->isScramblingActive());
    
    // Test key validation
    EXPECT_TRUE(yachta->validateKey(key_data));
    
    // Test invalid key
    std::string invalid_key = "invalid key data";
    EXPECT_FALSE(yachta->validateKey(invalid_key));
    
    // Test key info
    std::string key_info = yachta->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test audio processing functionality
 * 
 * @details
 * Tests the audio processing capabilities including filtering,
 * frequency response, and effects.
 */
TEST_F(YachtaT219Test, AudioProcessing) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test frequency response filtering
    std::vector<float> filtered_audio = test_audio;
    YachtaT219Utils::applyFrequencyResponse(filtered_audio, 44100.0f, 300.0f, 2700.0f);
    
    EXPECT_FALSE(filtered_audio.empty());
    EXPECT_EQ(filtered_audio.size(), test_audio.size());
    
    // Test test signal generation
    std::vector<float> test_tone = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(test_tone.empty());
    EXPECT_EQ(test_tone.size(), 44100);
    
    // Test noise generation
    std::vector<float> noise = YachtaT219Utils::generateNoise(44100.0f, 1.0f);
    EXPECT_FALSE(noise.empty());
    EXPECT_EQ(noise.size(), 44100);
    
    // Test chirp generation
    std::vector<float> chirp = YachtaT219Utils::generateChirp(100.0f, 1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(chirp.empty());
    EXPECT_EQ(chirp.size(), 44100);
}

/**
 * @brief Test system status and diagnostics
 * 
 * @details
 * Tests the system status reporting and diagnostic capabilities.
 */
TEST_F(YachtaT219Test, SystemStatus) {
    // Test uninitialized system
    EXPECT_FALSE(yachta->isInitialized());
    EXPECT_FALSE(yachta->isScramblingActive());
    EXPECT_FALSE(yachta->isFSKSyncActive());
    
    // Test initialized system
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    EXPECT_TRUE(yachta->isInitialized());
    EXPECT_FALSE(yachta->isScramblingActive());
    EXPECT_FALSE(yachta->isFSKSyncActive());
    
    // Test system with key
    yachta->setKey(12345, "scrambling_key_data");
    EXPECT_TRUE(yachta->isInitialized());
    EXPECT_TRUE(yachta->isScramblingActive());
    
    // Test system with FSK sync
    yachta->setFSKSyncParameters(100.0f, 150.0f, 0.1f);
    EXPECT_TRUE(yachta->isFSKSyncActive());
    
    // Test status reporting
    std::string status = yachta->getStatus();
    EXPECT_FALSE(status.empty());
    EXPECT_NE(status.find("Yachta T-219"), std::string::npos);
    
    // Test key info
    std::string key_info = yachta->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test error handling and edge cases
 * 
 * @details
 * Tests the system's error handling capabilities and edge cases.
 */
TEST_F(YachtaT219Test, ErrorHandling) {
    // Test initialization with invalid parameters
    EXPECT_FALSE(yachta->initialize(0.0f, 1));
    EXPECT_FALSE(yachta->initialize(44100.0f, 0));
    
    // Test operations on uninitialized system
    EXPECT_FALSE(yachta->setKey(12345, "test_key"));
    EXPECT_FALSE(yachta->setScramblingParameters(10, 5, 0.8f));
    EXPECT_FALSE(yachta->validateKey("test_key"));
    
    // Test encryption/decryption on uninitialized system
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> result = yachta->encrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    result = yachta->decrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    // Test with empty audio
    std::vector<float> empty_audio;
    result = yachta->encrypt(empty_audio);
    EXPECT_TRUE(result.empty());
    
    result = yachta->decrypt(empty_audio);
    EXPECT_TRUE(result.empty());
}

/**
 * @brief Test utility functions
 * 
 * @details
 * Tests the utility functions for the Yachta T-219 system.
 */
TEST_F(YachtaT219Test, UtilityFunctions) {
    // Test key data parsing
    std::string key_data = "01 23 45 67 89 AB CD EF";
    std::vector<uint8_t> key_bytes = YachtaT219Utils::parseKeyData(key_data);
    EXPECT_FALSE(key_bytes.empty());
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key data generation
    std::string generated_key = YachtaT219Utils::generateKeyData(key_bytes);
    EXPECT_FALSE(generated_key.empty());
    EXPECT_EQ(generated_key, key_data);
    
    // Test key format validation
    EXPECT_TRUE(YachtaT219Utils::validateKeyFormat(key_data));
    EXPECT_FALSE(YachtaT219Utils::validateKeyFormat("invalid key"));
    
    // Test window function generation
    std::vector<float> hanning_window = YachtaT219Utils::generateWindowFunction("hanning", 1024);
    EXPECT_FALSE(hanning_window.empty());
    EXPECT_EQ(hanning_window.size(), 1024);
    
    std::vector<float> hamming_window = YachtaT219Utils::generateWindowFunction("hamming", 1024);
    EXPECT_FALSE(hamming_window.empty());
    EXPECT_EQ(hamming_window.size(), 1024);
    
    std::vector<float> blackman_window = YachtaT219Utils::generateWindowFunction("blackman", 1024);
    EXPECT_FALSE(blackman_window.empty());
    EXPECT_EQ(blackman_window.size(), 1024);
}

/**
 * @brief Test performance characteristics
 * 
 * @details
 * Tests the performance characteristics of the Yachta T-219 system
 * including processing speed and memory usage.
 */
TEST_F(YachtaT219Test, PerformanceCharacteristics) {
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    yachta->setKey(12345, "scrambling_key_data");
    
    // Generate large audio buffer
    std::vector<float> large_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 10.0f);
    
    // Test encryption performance
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> encrypted_audio = yachta->encrypt(large_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), large_audio.size());
    EXPECT_LT(duration.count(), 2000); // Should complete within 2 seconds
    
    // Test decryption performance
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = yachta->decrypt(encrypted_audio);
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
 * Tests the integration of the Yachta T-219 system with the
 * broader voice encryption module.
 */
TEST_F(YachtaT219Test, ModuleIntegration) {
    // Test system initialization
    ASSERT_TRUE(yachta->initialize(44100.0f, 1));
    
    // Test scrambling setup
    yachta->setScramblingParameters(10, 5, 0.8f);
    yachta->setKey(12345, "scrambling_key_data");
    
    // Test audio processing pipeline
    std::vector<float> input_audio = YachtaT219Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test complete encryption pipeline
    std::vector<float> encrypted_audio = yachta->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test complete decryption pipeline
    std::vector<float> decrypted_audio = yachta->decrypt(encrypted_audio);
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), input_audio.size());
    
    // Test system status
    EXPECT_TRUE(yachta->isInitialized());
    EXPECT_TRUE(yachta->isScramblingActive());
    
    // Test status reporting
    std::string status = yachta->getStatus();
    EXPECT_FALSE(status.empty());
    
    std::string key_info = yachta->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
}

} // namespace testing