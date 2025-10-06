/**
 * @file test_stanag_4197.cpp
 * @brief Test suite for STANAG 4197 NATO QPSK OFDM Voice Encryption System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the STANAG 4197 NATO QPSK OFDM
 * voice encryption system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - QPSK OFDM modulation and demodulation
 * - Linear predictive coding (LPC) voice encoding
 * - Preamble and header generation
 * - Digital voice encryption and decryption
 * - Key management and validation
 * - Audio processing and filtering
 * - NATO digital voice characteristics
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see voice-encryption/systems/stanag-4197/include/stanag_4197.h
 * @see voice-encryption/systems/stanag-4197/docs/STANAG_4197_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/stanag-4197/include/stanag_4197.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom::stanag4197;

/**
 * @brief Test suite for STANAG 4197 system
 * 
 * @details
 * This test suite provides comprehensive testing of the STANAG 4197
 * NATO QPSK OFDM voice encryption system.
 */
using namespace testing;

class Stanag4197Test : public ::testing::Test {
protected:
    void SetUp() override {
        stanag = std::make_unique<Stanag4197>();
    }
    
    void TearDown() override {
        stanag.reset();
    }
    
    std::unique_ptr<Stanag4197> stanag;
};

/**
 * @brief Test STANAG 4197 initialization
 * 
 * @details
 * Tests the initialization of the STANAG 4197 system with various
 * audio parameters and configurations.
 */
TEST_F(Stanag4197Test, Initialization) {
    // Test successful initialization
    EXPECT_TRUE(stanag->initialize(44100.0f, 1));
    EXPECT_TRUE(stanag->isInitialized());
    
    // Test invalid parameters
    EXPECT_FALSE(stanag->initialize(0.0f, 1));
    EXPECT_FALSE(stanag->initialize(44100.0f, 0));
    
    // Test re-initialization
    EXPECT_TRUE(stanag->initialize(48000.0f, 2));
    EXPECT_TRUE(stanag->isInitialized());
}

/**
 * @brief Test QPSK modulation and demodulation
 * 
 * @details
 * Tests the QPSK modulation and demodulation functionality
 * for the STANAG 4197 system.
 */
TEST_F(Stanag4197Test, QPSKModulation) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Test QPSK constellation generation
    std::vector<std::complex<float>> constellation = Stanag4197Utils::generateQPSKConstellation();
    
    EXPECT_FALSE(constellation.empty());
    EXPECT_EQ(constellation.size(), 4);
    
    // Test QPSK modulation
    std::vector<bool> test_bits = {true, false, true, true, false, false};
    std::vector<std::complex<float>> modulated_symbols = Stanag4197Utils::applyQPSKModulation(test_bits);
    
    EXPECT_FALSE(modulated_symbols.empty());
    EXPECT_EQ(modulated_symbols.size(), 3); // 6 bits -> 3 symbols
    
    // Test QPSK demodulation
    std::vector<bool> demodulated_bits = Stanag4197Utils::applyQPSKDemodulation(modulated_symbols);
    
    EXPECT_FALSE(demodulated_bits.empty());
    EXPECT_EQ(demodulated_bits.size(), 6); // 3 symbols -> 6 bits
    
    // Test bit integrity
    EXPECT_EQ(demodulated_bits, test_bits);
}

/**
 * @brief Test OFDM symbol generation
 * 
 * @details
 * Tests the OFDM symbol generation and processing
 * functionality.
 */
TEST_F(Stanag4197Test, OFDMSymbolGeneration) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Test OFDM symbol generation
    std::vector<bool> test_data = {true, false, true, true, false, false, true, false};
    std::vector<std::complex<float>> ofdm_symbols = Stanag4197Utils::generateOFDMSymbols(
        test_data, 39, 64);
    
    EXPECT_FALSE(ofdm_symbols.empty());
    EXPECT_EQ(ofdm_symbols.size(), 4); // 8 bits -> 4 symbols
    
    // Test OFDM parameters
    EXPECT_TRUE(stanag->setOFDMParameters(2400, 39, 16));
    EXPECT_TRUE(stanag->isOFDMProcessingActive());
}

/**
 * @brief Test preamble sequence generation
 * 
 * @details
 * Tests the preamble sequence generation for STANAG 4197
 * system synchronization.
 */
TEST_F(Stanag4197Test, PreambleSequence) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Test STANAG 4197 preamble generation
    std::vector<std::complex<float>> preamble = Stanag4197Utils::generatePreambleSequence(
        "4197", 16, 39);
    
    EXPECT_FALSE(preamble.empty());
    EXPECT_EQ(preamble.size(), 55); // 16 header + 39 data tones
    
    // Test preamble parameters
    stanag->setPreambleParameters("4197", false);
    EXPECT_TRUE(stanag->isInitialized());
    
    // Test MIL-STD-188-110A/B preamble
    std::vector<std::complex<float>> preamble_110a = Stanag4197Utils::generatePreambleSequence(
        "110A", 16, 39);
    
    EXPECT_FALSE(preamble_110a.empty());
    EXPECT_EQ(preamble_110a.size(), 55);
}

/**
 * @brief Test LPC encoding and decoding
 * 
 * @details
 * Tests the linear predictive coding functionality
 * for digital voice encoding.
 */
TEST_F(Stanag4197Test, LPCEncoding) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test LPC encoding
    auto lpc_result = Stanag4197Utils::applyLPCEncoding(test_audio, 10);
    std::vector<float> lpc_coefficients = lpc_result.first;
    std::vector<float> lpc_residual = lpc_result.second;
    
    EXPECT_FALSE(lpc_coefficients.empty());
    EXPECT_EQ(lpc_coefficients.size(), 10);
    EXPECT_FALSE(lpc_residual.empty());
    EXPECT_EQ(lpc_residual.size(), test_audio.size());
    
    // Test LPC decoding
    std::vector<float> decoded_audio = Stanag4197Utils::applyLPCDecoding(
        lpc_coefficients, lpc_residual, 10);
    
    EXPECT_FALSE(decoded_audio.empty());
    EXPECT_EQ(decoded_audio.size(), test_audio.size());
    
    // Test digital voice parameters
    stanag->setDigitalVoiceParameters("autocorrelation", 0.8f);
    EXPECT_TRUE(stanag->isInitialized());
}

/**
 * @brief Test digital voice effects
 * 
 * @details
 * Tests the digital voice effects characteristic
 * of the STANAG 4197 system.
 */
TEST_F(Stanag4197Test, DigitalVoiceEffects) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test digital voice effect
    std::vector<float> digital_audio = test_audio;
    Stanag4197Utils::applyDigitalVoiceEffect(digital_audio, 0.8f);
    
    EXPECT_FALSE(digital_audio.empty());
    EXPECT_EQ(digital_audio.size(), test_audio.size());
    
    // Test digital voice effect application
    stanag->applyDigitalVoiceEffect(digital_audio, 0.8f);
    EXPECT_FALSE(digital_audio.empty());
    
    // Test NATO digital effects
    std::vector<float> nato_audio = test_audio;
    Stanag4197Utils::applyNATODigitalEffects(nato_audio);
    
    EXPECT_FALSE(nato_audio.empty());
    EXPECT_EQ(nato_audio.size(), test_audio.size());
}

/**
 * @brief Test audio encryption and decryption
 * 
 * @details
 * Tests the complete audio encryption and decryption process
 * using the STANAG 4197 system.
 */
TEST_F(Stanag4197Test, AudioEncryptionDecryption) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Set up encryption
    stanag->setOFDMParameters(2400, 39, 16);
    stanag->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate test audio
    std::vector<float> input_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test encryption
    std::vector<float> encrypted_audio = stanag->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test decryption
    std::vector<float> decrypted_audio = stanag->decrypt(encrypted_audio);
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
 * @brief Test OFDM modulation
 * 
 * @details
 * Tests the OFDM modulation functionality
 * for the STANAG 4197 system.
 */
TEST_F(Stanag4197Test, OFDMModulation) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test OFDM modulation
    std::vector<float> ofdm_audio = test_audio;
    Stanag4197Utils::applyOFDMModulation(ofdm_audio, 39, 64);
    
    EXPECT_FALSE(ofdm_audio.empty());
    EXPECT_EQ(ofdm_audio.size(), test_audio.size());
    
    // Test OFDM modulation application
    stanag->applyOFDMModulation(ofdm_audio);
    EXPECT_FALSE(ofdm_audio.empty());
}

/**
 * @brief Test preamble sequence application
 * 
 * @details
 * Tests the preamble sequence application
 * for synchronization.
 */
TEST_F(Stanag4197Test, PreambleSequenceApplication) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Generate preamble sequence
    std::vector<std::complex<float>> preamble = Stanag4197Utils::generatePreambleSequence(
        "4197", 16, 39);
    
    // Test preamble sequence application
    std::vector<float> preamble_audio = test_audio;
    Stanag4197Utils::applyPreambleSequence(preamble_audio, preamble);
    
    EXPECT_FALSE(preamble_audio.empty());
    EXPECT_EQ(preamble_audio.size(), test_audio.size());
    
    // Test preamble sequence application
    stanag->applyPreambleSequence(preamble_audio);
    EXPECT_FALSE(preamble_audio.empty());
}

/**
 * @brief Test key management functionality
 * 
 * @details
 * Tests the key management system including key loading,
 * saving, and validation.
 */
TEST_F(Stanag4197Test, KeyManagement) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Test key setting
    std::string key_data = "01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(stanag->setKey(12345, key_data));
    EXPECT_TRUE(stanag->isEncryptionActive());
    
    // Test key validation
    EXPECT_TRUE(stanag->validateKey(key_data));
    
    // Test invalid key
    std::string invalid_key = "invalid key data";
    EXPECT_FALSE(stanag->validateKey(invalid_key));
    
    // Test key generation
    EXPECT_TRUE(stanag->generateKey(128));
    EXPECT_TRUE(stanag->isEncryptionActive());
    
    // Test key info
    std::string key_info = stanag->getKeyInfo();
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
TEST_F(Stanag4197Test, AudioProcessing) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Generate test audio
    std::vector<float> test_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test frequency response filtering
    std::vector<float> filtered_audio = test_audio;
    Stanag4197Utils::applyFrequencyResponse(filtered_audio, 44100.0f, 300.0f, 3400.0f);
    
    EXPECT_FALSE(filtered_audio.empty());
    EXPECT_EQ(filtered_audio.size(), test_audio.size());
    
    // Test test signal generation
    std::vector<float> test_tone = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(test_tone.empty());
    EXPECT_EQ(test_tone.size(), 44100);
    
    // Test noise generation
    std::vector<float> noise = Stanag4197Utils::generateNoise(44100.0f, 1.0f);
    EXPECT_FALSE(noise.empty());
    EXPECT_EQ(noise.size(), 44100);
    
    // Test chirp generation
    std::vector<float> chirp = Stanag4197Utils::generateChirp(100.0f, 1000.0f, 44100.0f, 1.0f);
    EXPECT_FALSE(chirp.empty());
    EXPECT_EQ(chirp.size(), 44100);
}

/**
 * @brief Test system status and diagnostics
 * 
 * @details
 * Tests the system status reporting and diagnostic capabilities.
 */
TEST_F(Stanag4197Test, SystemStatus) {
    // Test uninitialized system
    EXPECT_FALSE(stanag->isInitialized());
    EXPECT_FALSE(stanag->isEncryptionActive());
    EXPECT_FALSE(stanag->isOFDMProcessingActive());
    
    // Test initialized system
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    EXPECT_TRUE(stanag->isInitialized());
    EXPECT_FALSE(stanag->isEncryptionActive());
    EXPECT_FALSE(stanag->isOFDMProcessingActive());
    
    // Test system with key
    stanag->setKey(12345, "01 23 45 67 89 AB CD EF");
    EXPECT_TRUE(stanag->isInitialized());
    EXPECT_TRUE(stanag->isEncryptionActive());
    
    // Test system with OFDM
    stanag->setOFDMParameters(2400, 39, 16);
    EXPECT_TRUE(stanag->isOFDMProcessingActive());
    
    // Test status reporting
    std::string status = stanag->getStatus();
    EXPECT_FALSE(status.empty());
    EXPECT_NE(status.find("STANAG 4197"), std::string::npos);
    
    // Test key info
    std::string key_info = stanag->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
    EXPECT_NE(key_info, "No key loaded");
}

/**
 * @brief Test error handling and edge cases
 * 
 * @details
 * Tests the system's error handling capabilities and edge cases.
 */
TEST_F(Stanag4197Test, ErrorHandling) {
    // Test initialization with invalid parameters
    EXPECT_FALSE(stanag->initialize(0.0f, 1));
    EXPECT_FALSE(stanag->initialize(44100.0f, 0));
    
    // Test operations on uninitialized system
    EXPECT_FALSE(stanag->setKey(12345, "test_key"));
    EXPECT_FALSE(stanag->setOFDMParameters(2400, 39, 16));
    EXPECT_FALSE(stanag->validateKey("test_key"));
    
    // Test encryption/decryption on uninitialized system
    std::vector<float> test_audio = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    std::vector<float> result = stanag->encrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    result = stanag->decrypt(test_audio);
    EXPECT_EQ(result, test_audio); // Should return original audio
    
    // Test with empty audio
    std::vector<float> empty_audio;
    result = stanag->encrypt(empty_audio);
    EXPECT_TRUE(result.empty());
    
    result = stanag->decrypt(empty_audio);
    EXPECT_TRUE(result.empty());
}

/**
 * @brief Test utility functions
 * 
 * @details
 * Tests the utility functions for the STANAG 4197 system.
 */
TEST_F(Stanag4197Test, UtilityFunctions) {
    // Test key data parsing
    std::string key_data = "01 23 45 67 89 AB CD EF";
    std::vector<uint8_t> key_bytes = Stanag4197Utils::parseKeyData(key_data);
    EXPECT_FALSE(key_bytes.empty());
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key data generation
    std::string generated_key = Stanag4197Utils::generateKeyData(key_bytes);
    EXPECT_FALSE(generated_key.empty());
    EXPECT_EQ(generated_key, key_data);
    
    // Test key format validation
    EXPECT_TRUE(Stanag4197Utils::validateKeyFormat(key_data));
    EXPECT_FALSE(Stanag4197Utils::validateKeyFormat("invalid key"));
    
    // Test encryption key generation
    std::vector<uint8_t> encryption_key = Stanag4197Utils::generateEncryptionKey(128);
    EXPECT_FALSE(encryption_key.empty());
    EXPECT_EQ(encryption_key.size(), 16); // 128 bits / 8 bits per byte
    
    // Test encryption key validation
    EXPECT_TRUE(Stanag4197Utils::validateEncryptionKey(encryption_key));
    
    // Test invalid encryption key
    std::vector<uint8_t> invalid_key = {0x01, 0x02}; // Too short
    EXPECT_FALSE(Stanag4197Utils::validateEncryptionKey(invalid_key));
}

/**
 * @brief Test performance characteristics
 * 
 * @details
 * Tests the performance characteristics of the STANAG 4197 system
 * including processing speed and memory usage.
 */
TEST_F(Stanag4197Test, PerformanceCharacteristics) {
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    stanag->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Generate large audio buffer
    std::vector<float> large_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 10.0f);
    
    // Test encryption performance
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> encrypted_audio = stanag->encrypt(large_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), large_audio.size());
    EXPECT_LT(duration.count(), 2000); // Should complete within 2 seconds
    
    // Test decryption performance
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<float> decrypted_audio = stanag->decrypt(encrypted_audio);
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
 * Tests the integration of the STANAG 4197 system with the
 * broader voice encryption module.
 */
TEST_F(Stanag4197Test, ModuleIntegration) {
    // Test system initialization
    ASSERT_TRUE(stanag->initialize(44100.0f, 1));
    
    // Test OFDM setup
    stanag->setOFDMParameters(2400, 39, 16);
    stanag->setKey(12345, "01 23 45 67 89 AB CD EF");
    
    // Test audio processing pipeline
    std::vector<float> input_audio = Stanag4197Utils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    
    // Test complete encryption pipeline
    std::vector<float> encrypted_audio = stanag->encrypt(input_audio);
    EXPECT_FALSE(encrypted_audio.empty());
    EXPECT_EQ(encrypted_audio.size(), input_audio.size());
    
    // Test complete decryption pipeline
    std::vector<float> decrypted_audio = stanag->decrypt(encrypted_audio);
    EXPECT_FALSE(decrypted_audio.empty());
    EXPECT_EQ(decrypted_audio.size(), input_audio.size());
    
    // Test system status
    EXPECT_TRUE(stanag->isInitialized());
    EXPECT_TRUE(stanag->isEncryptionActive());
    EXPECT_TRUE(stanag->isOFDMProcessingActive());
    
    // Test status reporting
    std::string status = stanag->getStatus();
    EXPECT_FALSE(status.empty());
    
    std::string key_info = stanag->getKeyInfo();
    EXPECT_FALSE(key_info.empty());
}

} // namespace testing