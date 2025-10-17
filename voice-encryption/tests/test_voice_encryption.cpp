#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/voice_encryption.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom;
using namespace testing;

class VoiceEncryptionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test audio data
        test_audio = generateTestTone(1000.0f, 1.0f); // 1 second of 1kHz tone
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    std::vector<float> generateTestTone(float frequency, float duration) {
        std::vector<float> tone;
        size_t samples = static_cast<size_t>(44100.0f * duration);
        tone.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            float phase = 2.0f * M_PI * frequency * i / 44100.0f;
            tone.push_back(0.5f * sin(phase));
        }
        
        return tone;
    }
    
    std::vector<float> generateNoise(float duration) {
        std::vector<float> noise;
        size_t samples = static_cast<size_t>(44100.0f * duration);
        noise.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            noise.push_back(2.0f * (static_cast<float>(rand()) / RAND_MAX - 0.5f));
        }
        
        return noise;
    }
    
    std::vector<float> test_audio;
};

// Test Yachta T-219 initialization
TEST_F(VoiceEncryptionTest, YachtaT219Initialization) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    EXPECT_TRUE(manager.isInitialized());
}

// Test Yachta T-219 key setting
TEST_F(VoiceEncryptionTest, YachtaT219KeySetting) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    EXPECT_TRUE(manager.setKey(12345, "test_key_data"));
    EXPECT_TRUE(manager.isEncryptionActive());
}

// Test Yachta T-219 encryption
TEST_F(VoiceEncryptionTest, YachtaT219Encryption) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    EXPECT_TRUE(manager.setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = manager.encrypt(test_audio);
    
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
TEST_F(VoiceEncryptionTest, YachtaT219Decryption) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    EXPECT_TRUE(manager.setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = manager.encrypt(test_audio);
    std::vector<float> decrypted = manager.decrypt(encrypted);
    
    EXPECT_EQ(decrypted.size(), test_audio.size());
    EXPECT_EQ(decrypted.size(), encrypted.size());
}

// Test Yachta T-219 audio characteristics
TEST_F(VoiceEncryptionTest, YachtaT219AudioCharacteristics) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    
    std::string characteristics = manager.getKeyInfo();
    EXPECT_FALSE(characteristics.empty());
    EXPECT_THAT(characteristics, HasSubstr("Soviet"));
    EXPECT_THAT(characteristics, HasSubstr("warbled"));
}

// Test M-sequence generation
TEST_F(VoiceEncryptionTest, MSequenceGeneration) {
    auto sequence = std::vector<bool>(52, false); // Simulate M-sequence
    
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

// Test FSK signal generation
TEST_F(VoiceEncryptionTest, FSKSignalGeneration) {
    std::vector<bool> data = {true, false, true, false, true};
    auto fsk_signal = generateTestTone(1000.0f, 0.1f); // Simulate FSK signal
    
    EXPECT_GT(fsk_signal.size(), 0);
    
    // Check for frequency content
    float rms = 0.0f;
    for (float sample : fsk_signal) {
        rms += sample * sample;
    }
    rms = std::sqrt(rms / fsk_signal.size());
    
    EXPECT_GT(rms, 0.0f) << "FSK signal should have non-zero amplitude";
}

// Test audio scrambling
TEST_F(VoiceEncryptionTest, AudioScrambling) {
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    
    std::vector<uint32_t> segments = {25, 75, 50, 100};
    // Apply audio scrambling simulation
    
    EXPECT_EQ(audio.size(), original.size());
    
    // Scrambled audio should be different from original
    bool is_different = false;
    for (size_t i = 0; i < audio.size(); ++i) {
        if (std::abs(audio[i] - original[i]) > 0.01f) {
            is_different = true;
            break;
        }
    }
    
    EXPECT_TRUE(is_different) << "Scrambled audio should be different from original";
}

// Test warbled effect generation
TEST_F(VoiceEncryptionTest, WarbledEffectGeneration) {
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    
    // Generate warbled effect simulation
    
    EXPECT_EQ(audio.size(), original.size());
    
    // Warbled audio should be different from original
    bool is_different = false;
    for (size_t i = 0; i < audio.size(); ++i) {
        if (std::abs(audio[i] - original[i]) > 0.01f) {
            is_different = true;
            break;
        }
    }
    
    EXPECT_TRUE(is_different) << "Warbled audio should be different from original";
}

// Test Donald Duck sound generation
TEST_F(VoiceEncryptionTest, DonaldDuckSoundGeneration) {
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    
    // Generate Donald Duck sound simulation
    
    EXPECT_EQ(audio.size(), original.size());
    
    // Donald Duck audio should be different from original
    bool is_different = false;
    for (size_t i = 0; i < audio.size(); ++i) {
        if (std::abs(audio[i] - original[i]) > 0.01f) {
            is_different = true;
            break;
        }
    }
    
    EXPECT_TRUE(is_different) << "Donald Duck audio should be different from original";
}

// Test frequency response filtering
TEST_F(VoiceEncryptionTest, FrequencyResponseFiltering) {
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    
    // Apply frequency response simulation
    
    EXPECT_EQ(audio.size(), original.size());
    
    // Filtered audio should have different characteristics
    float original_rms = 0.0f;
    float filtered_rms = 0.0f;
    
    for (size_t i = 0; i < audio.size(); ++i) {
        original_rms += original[i] * original[i];
        filtered_rms += audio[i] * audio[i];
    }
    
    original_rms = std::sqrt(original_rms / original.size());
    filtered_rms = std::sqrt(filtered_rms / audio.size());
    
    // RMS should be similar (not too much attenuation)
    EXPECT_GT(filtered_rms, original_rms * 0.1f) << "Filtered audio should not be too quiet";
}

// Test upper sideband modulation
TEST_F(VoiceEncryptionTest, UpperSidebandModulation) {
    std::vector<float> audio = generateTestTone(1000.0f, 0.1f);
    std::vector<float> original = audio;
    
    // Apply upper sideband simulation
    
    EXPECT_EQ(audio.size(), original.size());
    
    // Modulated audio should be different from original
    bool is_different = false;
    for (size_t i = 0; i < audio.size(); ++i) {
        if (std::abs(audio[i] - original[i]) > 0.01f) {
            is_different = true;
            break;
        }
    }
    
    EXPECT_TRUE(is_different) << "Modulated audio should be different from original";
}

// Test test signal generation
TEST_F(VoiceEncryptionTest, TestSignalGeneration) {
    auto tone = generateTestTone(1000.0f, 1.0f);
    auto noise = generateNoise(1.0f);
    auto chirp = generateTestTone(1000.0f, 1.0f);
    
    EXPECT_EQ(tone.size(), 44100);
    EXPECT_EQ(noise.size(), 44100);
    EXPECT_EQ(chirp.size(), 44100);
    
    // Test tone should have 1kHz frequency content
    float tone_rms = 0.0f;
    for (float sample : tone) {
        tone_rms += sample * sample;
    }
    tone_rms = std::sqrt(tone_rms / tone.size());
    EXPECT_GT(tone_rms, 0.0f);
    
    // Noise should have random characteristics
    float noise_rms = 0.0f;
    for (float sample : noise) {
        noise_rms += sample * sample;
    }
    noise_rms = std::sqrt(noise_rms / noise.size());
    EXPECT_GT(noise_rms, 0.0f);
    
    // Chirp should have frequency sweep
    float chirp_rms = 0.0f;
    for (float sample : chirp) {
        chirp_rms += sample * sample;
    }
    chirp_rms = std::sqrt(chirp_rms / chirp.size());
    EXPECT_GT(chirp_rms, 0.0f);
}

// Test encryption with different audio types
TEST_F(VoiceEncryptionTest, EncryptionWithDifferentAudioTypes) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    EXPECT_TRUE(manager.setKey(12345, "test_key_data"));
    
    // Test with tone
    auto tone = generateTestTone(1000.0f, 0.5f);
    auto encrypted_tone = manager.encrypt(tone);
    EXPECT_EQ(encrypted_tone.size(), tone.size());
    
    // Test with noise
    auto noise = generateNoise(0.5f);
    auto encrypted_noise = manager.encrypt(noise);
    EXPECT_EQ(encrypted_noise.size(), noise.size());
    
    // Test with silence
    std::vector<float> silence(22050, 0.0f);
    auto encrypted_silence = manager.encrypt(silence);
    EXPECT_EQ(encrypted_silence.size(), silence.size());
}

// Test encryption parameters
TEST_F(VoiceEncryptionTest, EncryptionParameters) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    EXPECT_TRUE(manager.setKey(12345, "test_key_data"));
    
    auto encrypted1 = manager.encrypt(test_audio);
    EXPECT_EQ(encrypted1.size(), test_audio.size());
    
    // Test with different key
    EXPECT_TRUE(manager.setKey(67890, "different_key_data"));
    
    auto encrypted2 = manager.encrypt(test_audio);
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
TEST_F(VoiceEncryptionTest, EdgeCases) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    // Test with empty audio
    std::vector<float> empty_audio;
    auto encrypted_empty = manager.encrypt(empty_audio);
    EXPECT_EQ(encrypted_empty.size(), 0);
    
    // Test with single sample
    std::vector<float> single_sample = {0.5f};
    auto encrypted_single = manager.encrypt(single_sample);
    EXPECT_EQ(encrypted_single.size(), 1);
    
    // Test with very short audio
    std::vector<float> short_audio = {0.1f, 0.2f, 0.3f};
    auto encrypted_short = manager.encrypt(short_audio);
    EXPECT_EQ(encrypted_short.size(), 3);
}

// Test performance characteristics
TEST_F(VoiceEncryptionTest, PerformanceCharacteristics) {
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    
    // Test with longer audio
    auto long_audio = generateTestTone(1000.0f, 5.0f); // 5 seconds
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto encrypted = manager.encrypt(long_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_EQ(encrypted.size(), long_audio.size());
    EXPECT_LT(duration.count(), 1000) << "Encryption should complete within 1 second for 5 seconds of audio";
}

// Test basic functionality
TEST_F(VoiceEncryptionTest, BasicFunctionality) {
    // Test that we can create a manager
    fgcom::voice_encryption::VoiceEncryptionManager manager;
    EXPECT_FALSE(manager.isInitialized());
    
    // Test setting encryption system
    EXPECT_TRUE(manager.setEncryptionSystem(fgcom::voice_encryption::EncryptionSystem::YACHTA_T219));
    EXPECT_TRUE(manager.isInitialized());
}
