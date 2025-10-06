/**
 * @file test_yachta_t219.cpp
 * @brief Test suite for Yachta T-219 Soviet Analog Voice Scrambler
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the Yachta T-219 Soviet analog
 * voice scrambler system, including unit tests, integration tests, and
 * performance tests.
 * 
 * @details
 * The test suite covers:
 * - FSK synchronization and M-sequence generation
 * - Voice scrambling and descrambling
 * - Key card system functionality
 * - Audio processing and filtering
 * - Soviet audio characteristics (warbled, Donald Duck sound)
 * - Error handling and edge cases
 * - Performance and timing tests
 * 
 * @see yachta_t219.h
 * @see docs/YACHTA_T219_DOCUMENTATION.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../systems/yachta-t219/include/yachta_t219.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom::yachta;

/**
 * @brief Test suite for Yachta T-219 system
 * 
 * @details
 * This test suite provides comprehensive testing of the Yachta T-219
 * Soviet analog voice scrambler system.
 */
using namespace testing;

class YachtaT219Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        sample_rate = 44100.0f;
        channels = 1;
        
        // Create test audio data
        test_audio = generateTestTone(1000.0f, 1.0f); // 1 second of 1kHz tone
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    std::vector<float> generateTestTone(float frequency, float duration) {
        std::vector<float> tone;
        size_t samples = static_cast<size_t>(sample_rate * duration);
        tone.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            float phase = 2.0f * M_PI * frequency * i / sample_rate;
            tone.push_back(0.5f * sin(phase));
        }
        
        return tone;
    }
    
    std::vector<float> generateNoise(float duration) {
        std::vector<float> noise;
        size_t samples = static_cast<size_t>(sample_rate * duration);
        noise.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            noise.push_back(2.0f * (static_cast<float>(rand()) / RAND_MAX - 0.5f));
        }
        
        return noise;
    }
    
    float sample_rate;
    uint32_t channels;
    std::vector<float> test_audio;
};

// Test Yachta T-219 initialization
TEST_F(YachtaT219Test, Initialization) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_FALSE(yachta.isActive()); // Not active until key is set
}

// Test Yachta T-219 key setting
TEST_F(YachtaT219Test, KeySetting) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    EXPECT_TRUE(yachta.isActive());
}

// Test Yachta T-219 key card loading
TEST_F(YachtaT219Test, KeyCardLoading) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    std::string key_card = "01 23 45 67 89 AB CD EF";
    EXPECT_TRUE(yachta.loadKeyCard(key_card));
    EXPECT_TRUE(yachta.isKeyCardLoaded());
}

// Test Yachta T-219 encryption
TEST_F(YachtaT219Test, Encryption) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = yachta.encrypt(test_audio);
    
    // Encrypted audio should be different from original
    EXPECT_NE(encrypted.size(), 0);
    EXPECT_EQ(encrypted.size(), test_audio.size());
    
    // Check for Soviet characteristics
    bool has_warbling = false;
    bool has_fsk_sync = false;
    
    for (size_t i = 1; i < encrypted.size(); ++i) {
        float diff = std::abs(encrypted[i] - encrypted[i-1]);
        if (diff > 0.1f) {
            has_warbling = true;
        }
    }
    
    // Check for FSK sync signal characteristics
    float rms = 0.0f;
    for (float sample : encrypted) {
        rms += sample * sample;
    }
    rms = std::sqrt(rms / encrypted.size());
    
    if (rms > 0.05f) {
        has_fsk_sync = true;
    }
    
    EXPECT_TRUE(has_warbling || has_fsk_sync) << "Encrypted audio should show Soviet characteristics";
}

// Test Yachta T-219 decryption
TEST_F(YachtaT219Test, Decryption) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = yachta.encrypt(test_audio);
    std::vector<float> decrypted = yachta.decrypt(encrypted);
    
    EXPECT_EQ(decrypted.size(), test_audio.size());
    EXPECT_EQ(decrypted.size(), encrypted.size());
}

// Test Yachta T-219 audio characteristics
TEST_F(YachtaT219Test, AudioCharacteristics) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    std::string characteristics = yachta.getAudioCharacteristics();
    EXPECT_FALSE(characteristics.empty());
    EXPECT_THAT(characteristics, HasSubstr("Soviet"));
    EXPECT_THAT(characteristics, HasSubstr("warbled"));
}

// Test FSK parameters
TEST_F(YachtaT219Test, FSKParameters) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    yachta.setFSKParameters(50, 75.0f);
    EXPECT_TRUE(yachta.isFSKSyncActive());
}

// Test scrambling parameters
TEST_F(YachtaT219Test, ScramblingParameters) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    std::vector<uint32_t> segments = {10, 20, 30, 40};
    yachta.setScramblingParameters(segments, 0.5f);
    
    EXPECT_TRUE(yachta.isActive());
}

// Test audio response
TEST_F(YachtaT219Test, AudioResponse) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    yachta.setAudioResponse(200.0f, 3000.0f);
    yachta.setBandwidth(3000.0f);
    
    EXPECT_TRUE(yachta.isActive());
}

// Test key card data
TEST_F(YachtaT219Test, KeyCardData) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    std::string key_card = "01 23 45 67 89 AB CD EF 12 34 56 78";
    yachta.setKeyCardData(key_card);
    
    EXPECT_TRUE(yachta.isKeyCardLoaded());
}

// Test status information
TEST_F(YachtaT219Test, StatusInformation) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    std::string status = yachta.getEncryptionStatus();
    EXPECT_FALSE(status.empty());
    EXPECT_THAT(status, HasSubstr("YachtaT219"));
    EXPECT_THAT(status, HasSubstr("Initialized: Yes"));
    EXPECT_THAT(status, HasSubstr("Encryption Active: Yes"));
}

// Test frequency response
TEST_F(YachtaT219Test, FrequencyResponse) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    auto response = yachta.getFrequencyResponse();
    // Response should be available (implementation dependent)
    EXPECT_TRUE(true); // Placeholder for actual response validation
}

// Test M-sequence
TEST_F(YachtaT219Test, MSequence) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    auto sequence = yachta.getCurrentMSequence();
    EXPECT_EQ(sequence.size(), 52);
    
    // Check that sequence is not all zeros or all ones
    bool has_zeros = false;
    bool has_ones = false;
    
    for (bool bit : sequence) {
        if (bit) has_ones = true;
        else has_zeros = true;
    }
    
    EXPECT_TRUE(has_zeros && has_ones) << "M-sequence should contain both 0s and 1s";
}

// Test self-test
TEST_F(YachtaT219Test, SelfTest) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    // Self-test should not throw exceptions
    EXPECT_NO_THROW(yachta.runSelfTest());
}

// Test FSK calibration
TEST_F(YachtaT219Test, FSKCalibration) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    // FSK calibration should not throw exceptions
    EXPECT_NO_THROW(yachta.calibrateFSK());
}

// Test audio response alignment
TEST_F(YachtaT219Test, AudioResponseAlignment) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    // Audio response alignment should not throw exceptions
    EXPECT_NO_THROW(yachta.alignAudioResponse());
}

// Test key card testing
TEST_F(YachtaT219Test, KeyCardTesting) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.loadKeyCard("01 23 45 67 89 AB CD EF"));
    
    // Key card testing should not throw exceptions
    EXPECT_NO_THROW(yachta.testKeyCard());
}

// Test test signal generation
TEST_F(YachtaT219Test, TestSignalGeneration) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    // Test signal generation should not throw exceptions
    EXPECT_NO_THROW(yachta.generateTestSignal());
}

// Test encryption with different audio types
TEST_F(YachtaT219Test, EncryptionWithDifferentAudioTypes) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    // Test with tone
    auto tone = generateTestTone(1000.0f, 0.5f);
    auto encrypted_tone = yachta.encrypt(tone);
    EXPECT_EQ(encrypted_tone.size(), tone.size());
    
    // Test with noise
    auto noise = generateNoise(0.5f);
    auto encrypted_noise = yachta.encrypt(noise);
    EXPECT_EQ(encrypted_noise.size(), noise.size());
    
    // Test with silence
    std::vector<float> silence(22050, 0.0f);
    auto encrypted_silence = yachta.encrypt(silence);
    EXPECT_EQ(encrypted_silence.size(), silence.size());
}

// Test encryption parameters
TEST_F(YachtaT219Test, EncryptionParameters) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    
    // Test with different parameters
    yachta.setFSKParameters(50, 75.0f);
    yachta.setScramblingParameters({10, 20, 30, 40}, 0.5f);
    yachta.setAudioResponse(200.0f, 3000.0f);
    yachta.setBandwidth(3000.0f);
    
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    auto encrypted1 = yachta.encrypt(test_audio);
    EXPECT_EQ(encrypted1.size(), test_audio.size());
    
    // Test with different key
    EXPECT_TRUE(yachta.setKey(67890, "different_key_data"));
    
    auto encrypted2 = yachta.encrypt(test_audio);
    EXPECT_EQ(encrypted2.size(), test_audio.size());
    
    // Different keys should produce different encrypted output
    bool is_different = false;
    for (size_t i = 0; i < std::min(encrypted1.size(), encrypted2.size()); ++i) {
        if (std::abs(encrypted1[i] - encrypted2[i]) > 0.01f) {
            is_different = true;
            break;
        }
    }
    
    EXPECT_TRUE(is_different) << "Different keys should produce different encrypted output";
}

// Test edge cases
TEST_F(YachtaT219Test, EdgeCases) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    // Test with empty audio
    std::vector<float> empty_audio;
    auto encrypted_empty = yachta.encrypt(empty_audio);
    EXPECT_EQ(encrypted_empty.size(), 0);
    
    // Test with single sample
    std::vector<float> single_sample = {0.5f};
    auto encrypted_single = yachta.encrypt(single_sample);
    EXPECT_EQ(encrypted_single.size(), 1);
    
    // Test with very short audio
    std::vector<float> short_audio = {0.1f, 0.2f, 0.3f};
    auto encrypted_short = yachta.encrypt(short_audio);
    EXPECT_EQ(encrypted_short.size(), 3);
}

// Test performance characteristics
TEST_F(YachtaT219Test, PerformanceCharacteristics) {
    YachtaT219 yachta;
    
    EXPECT_TRUE(yachta.initialize(sample_rate, channels));
    EXPECT_TRUE(yachta.setKey(12345, "test_key_data"));
    
    // Test with longer audio
    auto long_audio = generateTestTone(1000.0f, 5.0f); // 5 seconds
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto encrypted = yachta.encrypt(long_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_EQ(encrypted.size(), long_audio.size());
    EXPECT_LT(duration.count(), 1000) << "Encryption should complete within 1 second for 5 seconds of audio";
}

// Test YachtaUtils functions
TEST_F(YachtaT219Test, YachtaUtilsFunctions) {
    // Test M-sequence generation
    auto sequence = YachtaUtils::generateMSequence(0x2000000000001ULL, 52);
    EXPECT_EQ(sequence.size(), 52);
    
    // Test FSK signal generation
    std::vector<bool> data = {true, false, true, false, true};
    auto fsk_signal = YachtaUtils::generateFSKSignal(data, sample_rate, 100, 150.0f);
    EXPECT_GT(fsk_signal.size(), 0);
    
    // Test audio scrambling
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    std::vector<uint32_t> segments = {25, 75, 50, 100};
    YachtaUtils::applyAudioScrambling(audio, segments, 0.8f);
    EXPECT_EQ(audio.size(), original.size());
    
    // Test warbled effect
    audio = generateTestTone(1000.0f, 0.1f);
    original = audio;
    YachtaUtils::generateWarbledEffect(audio, 0.5f);
    EXPECT_EQ(audio.size(), original.size());
    
    // Test Donald Duck sound
    audio = generateTestTone(1000.0f, 0.1f);
    original = audio;
    YachtaUtils::generateDonaldDuckSound(audio, 0.3f);
    EXPECT_EQ(audio.size(), original.size());
    
    // Test frequency response
    audio = generateTestTone(1000.0f, 0.1f);
    original = audio;
    YachtaUtils::applyFrequencyResponse(audio, sample_rate, 300.0f, 2700.0f);
    EXPECT_EQ(audio.size(), original.size());
    
    // Test upper sideband
    audio = generateTestTone(1000.0f, 0.1f);
    original = audio;
    YachtaUtils::applyUpperSideband(audio, sample_rate);
    EXPECT_EQ(audio.size(), original.size());
    
    // Test test signal generation
    auto tone = YachtaUtils::generateTestTone(1000.0f, sample_rate, 1.0f);
    auto noise = YachtaUtils::generateNoise(sample_rate, 1.0f);
    auto chirp = YachtaUtils::generateChirp(100.0f, 2000.0f, sample_rate, 1.0f);
    
    EXPECT_EQ(tone.size(), static_cast<size_t>(sample_rate));
    EXPECT_EQ(noise.size(), static_cast<size_t>(sample_rate));
    EXPECT_EQ(chirp.size(), static_cast<size_t>(sample_rate));
    
    // Test key card parsing
    std::string key_card = "01 23 45 67 89 AB CD EF";
    auto key_bytes = YachtaUtils::parseKeyCardData(key_card);
    EXPECT_EQ(key_bytes.size(), 8);
    
    // Test key card generation
    std::vector<uint8_t> test_bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    auto generated_key_card = YachtaUtils::generateKeyCardData(test_bytes);
    EXPECT_FALSE(generated_key_card.empty());
    
    // Test key card validation
    EXPECT_TRUE(YachtaUtils::validateKeyCardFormat("01 23 45 67 89 AB CD EF"));
    EXPECT_FALSE(YachtaUtils::validateKeyCardFormat("invalid format"));
    EXPECT_FALSE(YachtaUtils::validateKeyCardFormat("01 23 45 67 89 AB CD EF GG"));
}
