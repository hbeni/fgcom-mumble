/**
 * @file test_vinson_ky57.cpp
 * @brief Test suite for VINSON KY-57 NATO Secure Voice System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the VINSON KY-57 NATO
 * secure voice system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - CVSD digital vocoder encoding and decoding
 * - FSK modulation and demodulation
 * - Type 1 encryption and decryption
 * - Electronic key loading and management
 * - Audio processing and filtering
 * - NATO digital voice characteristics (robotic, buzzy sound)
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see voice-encryption/systems/vinson-ky57/include/vinson_ky57.h
 * @see voice-encryption/systems/vinson-ky57/docs/VINSON_KY57_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/vinson-ky57/include/vinson_ky57.h"
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
 * Tests the CVSD vocoder encoding and decoding
 * functionality for the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, CVSDVocoder) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test CVSD encoding
    std::vector<bool> cvsd_encoded = VinsonKY57Utils::applyCVSDEncoding(test_audio, 16000.0f);
    
    EXPECT_FALSE(cvsd_encoded.empty());
    EXPECT_GT(cvsd_encoded.size(), 0);
    
    // Test CVSD decoding
    std::vector<float> cvsd_decoded = VinsonKY57Utils::applyCVSDDecoding(cvsd_encoded, 16000.0f);
    
    EXPECT_FALSE(cvsd_decoded.empty());
    EXPECT_EQ(cvsd_decoded.size(), test_audio.size());
    
    // Test CVSD parameters
    vinson->setCVSDParameters(16000.0f, 0.8f);
    EXPECT_TRUE(vinson->isCVSDActive());
}

/**
 * @brief Test FSK modulation functionality
 * 
 * @details
 * Tests the FSK modulation and demodulation
 * functionality for the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, FSKModulation) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test FSK modulation
    std::vector<bool> test_bits = {true, false, true, true, false, false};
    std::vector<float> fsk_modulated = VinsonKY57Utils::applyFSKModulation(test_bits, 1200.0f, 1800.0f, 44100.0f);
    
    EXPECT_FALSE(fsk_modulated.empty());
    EXPECT_GT(fsk_modulated.size(), 0);
    
    // Test FSK demodulation
    std::vector<bool> fsk_demodulated = VinsonKY57Utils::applyFSKDemodulation(fsk_modulated, 1200.0f, 1800.0f, 44100.0f);
    
    EXPECT_FALSE(fsk_demodulated.empty());
    EXPECT_EQ(fsk_demodulated.size(), test_bits.size());
    
    // Test FSK parameters
    vinson->setFSKParameters(1200.0f, 1800.0f);
    EXPECT_TRUE(vinson->isFSKActive());
}

/**
 * @brief Test Type 1 encryption functionality
 * 
 * @details
 * Tests the Type 1 encryption and decryption
 * functionality for the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, Type1Encryption) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test encryption key setting
    std::string encryption_key = "01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(vinson->setEncryptionKey(12345, encryption_key));
    EXPECT_TRUE(vinson->isEncryptionActive());
    
    // Test encryption
    std::vector<uint8_t> test_data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::vector<uint8_t> encrypted_data = VinsonKY57Utils::applyType1Encryption(test_data, encryption_key);
    
    EXPECT_FALSE(encrypted_data.empty());
    EXPECT_EQ(encrypted_data.size(), test_data.size());
    
    // Test decryption
    std::vector<uint8_t> decrypted_data = VinsonKY57Utils::applyType1Decryption(encrypted_data, encryption_key);
    
    EXPECT_FALSE(decrypted_data.empty());
    EXPECT_EQ(decrypted_data.size(), test_data.size());
    
    // Test data integrity
    EXPECT_EQ(decrypted_data, test_data);
}

/**
 * @brief Test electronic key loading
 * 
 * @details
 * Tests the electronic key loading and management
 * functionality for the VINSON KY-57 system.
 */
TEST_F(VinsonKY57Test, ElectronicKeyLoading) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test key loading
    std::vector<uint8_t> key_data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    EXPECT_TRUE(vinson->loadKey(key_data));
    EXPECT_TRUE(vinson->isKeyLoaded());
    
    // Test key validation
    EXPECT_TRUE(vinson->validateKey(key_data));
    
    // Test key saving
    std::vector<uint8_t> saved_key = vinson->getKey();
    EXPECT_FALSE(saved_key.empty());
    EXPECT_EQ(saved_key.size(), key_data.size());
    
    // Test key management
    vinson->setKeyManagementMode("electronic");
    EXPECT_TRUE(vinson->isKeyManagementActive());
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
    vinson->setCVSDParameters(16000.0f, 0.8f);
    vinson->setEncryptionKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate test audio
    std::vector<float> input_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
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
 * @brief Test NATO digital voice effects
 * 
 * @details
 * Tests the distinctive NATO digital voice effects including
 * robotic and buzzy sound characteristics.
 */
TEST_F(VinsonKY57Test, NATODigitalVoiceEffects) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test robotic effect
    std::vector<float> robotic_audio = test_audio;
    VinsonKY57Utils::applyRoboticEffect(robotic_audio, 0.8f);
    
    EXPECT_FALSE(robotic_audio.empty());
    EXPECT_EQ(robotic_audio.size(), test_audio.size());
    
    // Test buzzy effect
    std::vector<float> buzzy_audio = test_audio;
    VinsonKY57Utils::applyBuzzyEffect(buzzy_audio, 0.8f);
    
    EXPECT_FALSE(buzzy_audio.empty());
    EXPECT_EQ(buzzy_audio.size(), test_audio.size());
    
    // Test NATO effects
    std::vector<float> nato_audio = test_audio;
    VinsonKY57Utils::applyNATODigitalEffects(nato_audio);
    
    EXPECT_FALSE(nato_audio.empty());
    EXPECT_EQ(nato_audio.size(), test_audio.size());
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
    
    // Test key setting
    std::string key_data = "01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(vinson->setEncryptionKey(12345, key_data));
    EXPECT_TRUE(vinson->isEncryptionActive());
    
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
 * frequency response, and effects.
 */
TEST_F(VinsonKY57Test, AudioProcessing) {
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test frequency response filtering
    std::vector<float> filtered_audio = test_audio;
    VinsonKY57Utils::applyFrequencyResponse(filtered_audio, 44100.0f, 300.0f, 3400.0f);
    
    EXPECT_FALSE(filtered_audio.empty());
    EXPECT_EQ(filtered_audio.size(), test_audio.size());
    
    // Test test signal generation
    std::vector<float> test_tone = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(test_tone.empty());
    EXPECT_EQ(test_tone.size(), 44100);
    
    // Test noise generation
    std::vector<float> noise = VinsonKY57Utils::generateNoise(44100.0f, 1.0f);
    EXPECT_FALSE(noise.empty());
    EXPECT_EQ(noise.size(), 44100);
    
    // Test chirp generation
    std::vector<float> chirp = VinsonKY57Utils::generateChirp(100.0f, 1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(chirp.empty());
    EXPECT_EQ(chirp.size(), 44100);
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
    EXPECT_FALSE(vinson->isCVSDActive());
    
    // Test initialized system
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    EXPECT_TRUE(vinson->isInitialized());
    EXPECT_FALSE(vinson->isEncryptionActive());
    EXPECT_FALSE(vinson->isCVSDActive());
    
    // Test system with key
    vinson->setEncryptionKey(12345, "01 23 45 67 89 AB CD EF");
    EXPECT_TRUE(vinson->isInitialized());
    EXPECT_TRUE(vinson->isEncryptionActive());
    
    // Test system with CVSD
    vinson->setCVSDParameters(16000.0f, 0.8f);
    EXPECT_TRUE(vinson->isCVSDActive());
    
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
    EXPECT_FALSE(vinson->setEncryptionKey(12345, "test_key"));
    EXPECT_FALSE(vinson->setCVSDParameters(16000.0f, 0.8f));
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
    // Test key data parsing
    std::string key_data = "01 23 45 67 89 AB CD EF";
    std::vector<uint8_t> key_bytes = VinsonKY57Utils::parseKeyData(key_data);
    EXPECT_FALSE(key_bytes.empty());
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key data generation
    std::string generated_key = VinsonKY57Utils::generateKeyData(key_bytes);
    EXPECT_FALSE(generated_key.empty());
    EXPECT_EQ(generated_key, key_data);
    
    // Test key format validation
    EXPECT_TRUE(VinsonKY57Utils::validateKeyFormat(key_data));
    EXPECT_FALSE(VinsonKY57Utils::validateKeyFormat("invalid key"));
    
    // Test encryption key generation
    std::vector<uint8_t> encryption_key = VinsonKY57Utils::generateEncryptionKey(128);
    EXPECT_FALSE(encryption_key.empty());
    EXPECT_EQ(encryption_key.size(), 16); // 128 bits / 8 bits per byte
    
    // Test encryption key validation
    EXPECT_TRUE(VinsonKY57Utils::validateEncryptionKey(encryption_key));
    
    // Test invalid encryption key
    std::vector<uint8_t> invalid_key = {0x01, 0x02}; // Too short
    EXPECT_FALSE(VinsonKY57Utils::validateEncryptionKey(invalid_key));
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
    vinson->setEncryptionKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate large audio buffer
    std::vector<float> large_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 10.0f);
    
    // Test encryption performance
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> encrypted_audio = vinson->encrypt(large_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), large_audio.size());
    EXPECT_LT(duration.count(), 2000); // Should complete within 2 seconds
    
    // Test decryption performance
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = vinson->decrypt(encrypted_audio);
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
 * Tests the integration of the VINSON KY-57 system with the
 * broader voice encryption module.
 */
TEST_F(VinsonKY57Test, ModuleIntegration) {
    // Test system initialization
    ASSERT_TRUE(vinson->initialize(44100.0f, 1));
    
    // Test encryption setup
    vinson->setCVSDParameters(16000.0f, 0.8f);
    vinson->setEncryptionKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Test audio processing pipeline
    std::vector<float> input_audio = VinsonKY57Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
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
    
    // Test status reporting
    std::string status = vinson->getStatus();
    EXPECT_FALSE(status.empty());
    
    std::string key_info = vinson->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
}

} // namespace testing