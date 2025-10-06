/**
 * @file test_vinson_ky57.cpp
 * @brief Test suite for VINSON KY-57/KY-58 NATO Secure Voice System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the VINSON KY-57 NATO secure
 * voice system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - CVSD vocoder encoding and decoding
 * - FSK modulation and demodulation
 * - Type 1 encryption and decryption
 * - Key management and validation
 * - Audio processing and filtering
 * - NATO audio characteristics (robotic, buzzy sound)
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see vinson_ky57.h
 * @see docs/VINSON_KY57_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../systems/vinson-ky57/include/vinson_ky57.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom::vinson;

/**
 * @brief Test suite for VINSON KY-57 system
 * 
 * @details
 * This test suite provides comprehensive testing of the VINSON KY-57
 * NATO secure voice system.
 */
using namespace testing;

class VinsonKY57Test : public ::testing::Test {
protected:
    void SetUp() override {
        vinson = std::make_unique<VinsonKY57>();
    }
    
    void TearDown() override {
        vinson.reset();
    }
    
    std::unique_ptr<VinsonKY57> vinson;
};

/**
 * @brief Test VINSON KY-57 initialization
 * 
 * @details
 * Tests the initialization of the VINSON KY-57 system with various
 * audio parameters and configurations.
 */
TEST_F(VinsonKY57Test, Initialization) {
    // Test successful initialization
    EXPECT_TRUE(vinson->initialize(44100.0f, 1));
    EXPECT_TRUE(vinson->isInitialized());
    
    // Test invalid parameters
    EXPECT_FALSE(vinson->initialize(0.0f, 1));
    EXPECT_FALSE(vinson->initialize(44100.0f, 0));
    
    // Test re-initialization
    EXPECT_TRUE(vinson->initialize(48000.0f, 2));
    EXPECT_TRUE(vinson->isInitialized());
}

/**
 * @brief Test CVSD vocoder functionality
 * 
 * @details
 * Tests the CVSD (Continuously Variable Slope Delta) vocoder
 * encoding and decoding functionality.
 */
TEST_F(VinsonKY57Test, CVSDVocoder) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test CVSD parameters
    vinson->setCVSDParameters(16000, 0.1f, 0.01f);
    
    // Generate test audio
    std::vector<float> input_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test CVSD encoding
    std::vector<bool> bitstream = VinsonUtils::generateCVSDBitstream(
        input_audio, 16000, 0.1f, 0.01f);
    
    EXPECT_FALSE(bitstream.empty());
    EXPECT_EQ(bitstream.size(), input_audio.size());
    
    // Test CVSD decoding
    std::vector<float> decoded_audio = VinsonUtils::decodeCVSDBitstream(
        bitstream, 44100.0f, 0.1f, 0.01f);
    
    EXPECT_FALSE(decoded_audio.empty());
    EXPECT_EQ(decoded_audio.size(), bitstream.size());
}

/**
 * @brief Test FSK modulation functionality
 * 
 * @details
 * Tests the FSK (Frequency Shift Keying) modulation and demodulation
 * functionality.
 */
TEST_F(VinsonKY57Test, FSKModulation) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test FSK parameters
    vinson->setFSKParameters(1200, 1700.0f);
    
    // Generate test data
    std::vector<bool> test_data = {true, false, true, false, true, false, true, false};
    
    // Test FSK signal generation
    std::vector<float> fsk_signal = VinsonUtils::generateFSKSignal(
        test_data, 44100.0f, 1200, 1700.0f);
    
    EXPECT_FALSE(fsk_signal.empty());
    EXPECT_GT(fsk_signal.size(), test_data.size());
    
    // Test FSK signal properties
    for (float sample : fsk_signal) {
        EXPECT_GE(sample, -1.0f);
        EXPECT_LE(sample, 1.0f);
    }
}

/**
 * @brief Test Type 1 encryption functionality
 * 
 * @details
 * Tests the Type 1 encryption and decryption functionality
 * for secure communications.
 */
TEST_F(VinsonKY57Test, Type1Encryption) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test encryption parameters
    vinson->setEncryptionParameters("Type1", true);
    
    // Test key generation
    EXPECT_TRUE(vinson->generateKey(256));
    EXPECT_TRUE(vinson->isKeyLoaded());
    EXPECT_TRUE(vinson->isEncryptionActive());
    
    // Test key validation
    std::string key_data = "01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(vinson->validateKey(key_data));
    
    // Test invalid key
    std::string invalid_key = "invalid key data";
    EXPECT_FALSE(vinson->validateKey(invalid_key));
}

/**
 * @brief Test audio encryption and decryption
 * 
 * @details
 * Tests the complete audio encryption and decryption process
 * using the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, AudioEncryptionDecryption) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Set up encryption
    vinson->setEncryptionParameters("Type1", true);
    vinson->generateKey(256);
    
    // Generate test audio
    std::vector<float> input_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test encryption
    std::vector<float> encrypted_audio = vinson->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test decryption
    std::vector<float> decrypted_audio = vinson->decrypt(encrypted_audio);
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
 * @brief Test NATO audio effects
 * 
 * @details
 * Tests the distinctive NATO audio effects including robotic
 * and buzzy characteristics.
 */
TEST_F(VinsonKY57Test, NATOAudioEffects) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test audio effects configuration
    vinson->setAudioEffects(true, true, 0.7f, 0.6f);
    
    // Generate test audio
    std::vector<float> input_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test robotic effect
    std::vector<float> robotic_audio = input_audio;
    VinsonUtils::applyRoboticEffect(robotic_audio, 0.7f);
    
    EXPECT_FALSE(robotic_audio.empty());
    EXPECT_EQ(robotic_audio.size(), input_audio.size());
    
    // Test buzzy effect
    std::vector<float> buzzy_audio = input_audio;
    VinsonUtils::applyBuzzyEffect(buzzy_audio, 0.6f);
    
    EXPECT_FALSE(buzzy_audio.empty());
    EXPECT_EQ(buzzy_audio.size(), input_audio.size());
    
    // Test NATO effects
    std::vector<float> nato_audio = input_audio;
    VinsonUtils::applyNATOEffects(nato_audio);
    
    EXPECT_FALSE(nato_audio.empty());
    EXPECT_EQ(nato_audio.size(), input_audio.size());
}

/**
 * @brief Test key management functionality
 * 
 * @details
 * Tests the key management system including key loading,
 * saving, and validation.
 */
TEST_F(VinsonKY57Test, KeyManagement) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test key generation
    EXPECT_TRUE(vinson->generateKey(256));
    EXPECT_TRUE(vinson->isKeyLoaded());
    
    // Test key loading
    std::string key_data = "01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(vinson->loadKey(key_data));
    EXPECT_TRUE(vinson->isKeyLoaded());
    
    // Test key validation
    EXPECT_TRUE(vinson->validateKey(key_data));
    
    // Test invalid key
    std::string invalid_key = "invalid key data";
    EXPECT_FALSE(vinson->validateKey(invalid_key));
    
    // Test key info
    std::string key_info = vinson->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test audio processing functionality
 * 
 * @details
 * Tests the audio processing capabilities including filtering,
 * compression, and effects.
 */
TEST_F(VinsonKY57Test, AudioProcessing) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> input_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test frequency response filtering
    std::vector<float> filtered_audio = input_audio;
    VinsonUtils::applyFrequencyResponse(filtered_audio, 44100.0f, 300.0f, 2700.0f);
    
    EXPECT_FALSE(filtered_audio.empty());
    EXPECT_EQ(filtered_audio.size(), input_audio.size());
    
    // Test audio effects
    std::vector<float> effects_audio = input_audio;
    VinsonUtils::applyNATOEffects(effects_audio);
    
    EXPECT_FALSE(effects_audio.empty());
    EXPECT_EQ(effects_audio.size(), input_audio.size());
}

/**
 * @brief Test system status and diagnostics
 * 
 * @details
 * Tests the system status reporting and diagnostic capabilities.
 */
TEST_F(VinsonKY57Test, SystemStatus) {
    // Test uninitialized system
    EXPECT_FALSE(vinson->isInitialized());
    EXPECT_FALSE(vinson->isEncryptionActive());
    EXPECT_FALSE(vinson->isKeyLoaded());
    
    // Test initialized system
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    EXPECT_TRUE(vinson->isInitialized());
    EXPECT_FALSE(vinson->isEncryptionActive());
    EXPECT_FALSE(vinson->isKeyLoaded());
    
    // Test system with key
    vinson->generateKey(256);
    EXPECT_TRUE(vinson->isInitialized());
    EXPECT_TRUE(vinson->isEncryptionActive());
    EXPECT_TRUE(vinson->isKeyLoaded());
    
    // Test status reporting
    std::string status = vinson->getStatus();
    EXPECT_FALSE(status.empty());
    EXPECT_NE(status.find("VINSON KY-57"), std::string::npos);
    
    // Test key info
    std::string key_info = vinson->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test error handling and edge cases
 * 
 * @details
 * Tests the system's error handling capabilities and edge cases.
 */
TEST_F(VinsonKY57Test, ErrorHandling) {
    // Test initialization with invalid parameters
    EXPECT_FALSE(vinson->initialize(0.0f, 1));
    EXPECT_FALSE(vinson->initialize(44100.0f, 0));
    
    // Test operations on uninitialized system
    EXPECT_FALSE(vinson->setKey(12345, "test_key"));
    EXPECT_FALSE(vinson->loadKey("test_key"));
    EXPECT_FALSE(vinson->generateKey(256));
    EXPECT_FALSE(vinson->validateKey("test_key"));
    
    // Test encryption/decryption on uninitialized system
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> result = vinson->encrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    result = vinson->decrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    // Test with empty audio
    std::vector<float> empty_audio;
    result = vinson->encrypt(empty_audio);
    EXPECT_TRUE(result.empty());
    
    result = vinson->decrypt(empty_audio);
    EXPECT_TRUE(result.empty());
}

/**
 * @brief Test utility functions
 * 
 * @details
 * Tests the utility functions for the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, UtilityFunctions) {
    // Test test tone generation
    std::vector<float> tone = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(tone.empty());
    EXPECT_EQ(tone.size(), 44100);
    
    // Test noise generation
    std::vector<float> noise = VinsonUtils::generateNoise(44100.0f, 1.0f);
    EXPECT_FALSE(noise.empty());
    EXPECT_EQ(noise.size(), 44100);
    
    // Test chirp generation
    std::vector<float> chirp = VinsonUtils::generateChirp(100.0f, 1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(chirp.empty());
    EXPECT_EQ(chirp.size(), 44100);
    
    // Test key data parsing
    std::string key_data = "01 23 45 67 89 AB CD EF";
    std::vector<uint8_t> key_bytes = VinsonUtils::parseKeyData(key_data);
    EXPECT_FALSE(key_bytes.empty());
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key data generation
    std::string generated_key = VinsonUtils::generateKeyData(key_bytes);
    EXPECT_FALSE(generated_key.empty());
    EXPECT_EQ(generated_key, key_data);
    
    // Test key format validation
    EXPECT_TRUE(VinsonUtils::validateKeyFormat(key_data));
    EXPECT_FALSE(VinsonUtils::validateKeyFormat("invalid key"));
    
    // Test Type 1 key generation
    std::vector<uint8_t> type1_key = VinsonUtils::generateType1Key(256);
    EXPECT_FALSE(type1_key.empty());
    EXPECT_EQ(type1_key.size(), 32); // 256 bits = 32 bytes
    
    // Test Type 1 key validation
    EXPECT_TRUE(VinsonUtils::validateType1Key(type1_key));
    EXPECT_FALSE(VinsonUtils::validateType1Key(std::vector<uint8_t>()));
}

/**
 * @brief Test performance characteristics
 * 
 * @details
 * Tests the performance characteristics of the VINSON KY-57 system
 * including processing speed and memory usage.
 */
TEST_F(VinsonKY57Test, PerformanceCharacteristics) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    vinson->generateKey(256);
    
    // Generate large audio buffer
    std::vector<float> large_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 10.0f);
    
    // Test encryption performance
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> encrypted_audio = vinson->encrypt(large_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), large_audio.size());
    EXPECT_LT(duration.count(), 1000); // Should complete within 1 second
    
    // Test decryption performance
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = vinson->decrypt(encrypted_audio);
    end_time = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), encrypted_audio.size());
    EXPECT_LT(duration.count(), 1000); // Should complete within 1 second
}

/**
 * @brief Test integration with voice encryption module
 * 
 * @details
 * Tests the integration of the VINSON KY-57 system with the
 * broader voice encryption module.
 */
TEST_F(VinsonKY57Test, ModuleIntegration) {
    // Test system initialization
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test encryption setup
    vinson->setEncryptionParameters("Type1", true);
    vinson->generateKey(256);
    
    // Test audio processing pipeline
    std::vector<float> input_audio = VinsonUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test complete encryption pipeline
    std::vector<float> encrypted_audio = vinson->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test complete decryption pipeline
    std::vector<float> decrypted_audio = vinson->decrypt(encrypted_audio);
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), input_audio.size());
    
    // Test system status
    EXPECT_TRUE(vinson->isInitialized());
    EXPECT_TRUE(vinson->isEncryptionActive());
    EXPECT_TRUE(vinson->isKeyLoaded());
    
    // Test status reporting
    std::string status = vinson->getStatus();
    EXPECT_FALSE(status.empty());
    
    std::string key_info = vinson->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
}

} // namespace testing
