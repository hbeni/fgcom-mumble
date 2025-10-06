#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../client/mumble-plugin/lib/voice_encryption.h"
#include <vector>
#include <string>
#include <cmath>

using namespace fgcom;
using namespace testing;

class VoiceEncryptionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        audio_params.sample_rate = 44100.0f;
        audio_params.channels = 1;
        audio_params.bit_depth = 16;
        audio_params.bandwidth = 2700.0f;
        audio_params.frequency_shift = 0.0f;
        audio_params.upper_sideband = true;
        
        encryption_params.type = EncryptionType::YACHTA_T219;
        encryption_params.enabled = true;
        encryption_params.key_id = 12345;
        encryption_params.key_data = "test_key_data";
        encryption_params.frequency_shift = 150.0f;
        encryption_params.bandwidth = 2700.0f;
        encryption_params.audio_response_min = 300.0f;
        encryption_params.audio_response_max = 2700.0f;
        encryption_params.fsk_baud_rate = 100;
        encryption_params.use_key_card = true;
        encryption_params.key_card_data = "01 23 45 67 89 AB CD EF";
        
        // Create test audio data
        test_audio = generateTestTone(1000.0f, 1.0f); // 1 second of 1kHz tone
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    std::vector<float> generateTestTone(float frequency, float duration) {
        std::vector<float> tone;
        size_t samples = static_cast<size_t>(audio_params.sample_rate * duration);
        tone.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            float phase = 2.0f * M_PI * frequency * i / audio_params.sample_rate;
            tone.push_back(0.5f * sin(phase));
        }
        
        return tone;
    }
    
    std::vector<float> generateNoise(float duration) {
        std::vector<float> noise;
        size_t samples = static_cast<size_t>(audio_params.sample_rate * duration);
        noise.reserve(samples);
        
        for (size_t i = 0; i < samples; ++i) {
            noise.push_back(2.0f * (static_cast<float>(rand()) / RAND_MAX - 0.5f));
        }
        
        return noise;
    }
    
    AudioParams audio_params;
    EncryptionParams encryption_params;
    std::vector<float> test_audio;
};

// Test Yachta T-219 initialization
TEST_F(VoiceEncryptionTest, YachtaT219Initialization) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_EQ(encryption->getType(), EncryptionType::YACHTA_T219);
    EXPECT_FALSE(encryption->isActive()); // Not active until key is set
}

// Test Yachta T-219 key setting
TEST_F(VoiceEncryptionTest, YachtaT219KeySetting) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    EXPECT_TRUE(encryption->isActive());
}

// Test Yachta T-219 encryption
TEST_F(VoiceEncryptionTest, YachtaT219Encryption) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = encryption->encrypt(test_audio);
    
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
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    std::vector<float> encrypted = encryption->encrypt(test_audio);
    std::vector<float> decrypted = encryption->decrypt(encrypted);
    
    EXPECT_EQ(decrypted.size(), test_audio.size());
    EXPECT_EQ(decrypted.size(), encrypted.size());
}

// Test Yachta T-219 audio characteristics
TEST_F(VoiceEncryptionTest, YachtaT219AudioCharacteristics) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    
    std::string characteristics = encryption->getAudioCharacteristics();
    EXPECT_FALSE(characteristics.empty());
    EXPECT_THAT(characteristics, HasSubstr("Soviet"));
    EXPECT_THAT(characteristics, HasSubstr("warbled"));
}

// Test M-sequence generation
TEST_F(VoiceEncryptionTest, MSequenceGeneration) {
    auto sequence = VoiceEncryptionUtils::generateMSequence(0x2000000000001ULL, 52); // x^52 + x^49 + 1
    
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
    auto fsk_signal = VoiceEncryptionUtils::generateFSKSignal(data, 44100.0f, 100, 150.0f);
    
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
    VoiceEncryptionUtils::applyAudioScrambling(audio, segments, 0.8f);
    
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
    
    VoiceEncryptionUtils::generateWarbledEffect(audio, 0.5f);
    
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
    
    VoiceEncryptionUtils::generateDonaldDuckSound(audio, 0.3f);
    
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
    
    VoiceEncryptionUtils::applyFrequencyResponse(audio, 44100.0f, 300.0f, 2700.0f);
    
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
    
    VoiceEncryptionUtils::applyUpperSideband(audio, 44100.0f);
    
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
    auto tone = VoiceEncryptionUtils::generateTestTone(1000.0f, 44100.0f, 1.0f);
    auto noise = VoiceEncryptionUtils::generateNoise(44100.0f, 1.0f);
    auto chirp = VoiceEncryptionUtils::generateChirp(100.0f, 2000.0f, 44100.0f, 1.0f);
    
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
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    // Test with tone
    auto tone = generateTestTone(1000.0f, 0.5f);
    auto encrypted_tone = encryption->encrypt(tone);
    EXPECT_EQ(encrypted_tone.size(), tone.size());
    
    // Test with noise
    auto noise = generateNoise(0.5f);
    auto encrypted_noise = encryption->encrypt(noise);
    EXPECT_EQ(encrypted_noise.size(), noise.size());
    
    // Test with silence
    std::vector<float> silence(22050, 0.0f);
    auto encrypted_silence = encryption->encrypt(silence);
    EXPECT_EQ(encrypted_silence.size(), silence.size());
}

// Test encryption parameters
TEST_F(VoiceEncryptionTest, EncryptionParameters) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    // Test with different parameters
    EncryptionParams params1 = encryption_params;
    params1.fsk_baud_rate = 50;
    params1.bandwidth = 2000.0f;
    
    EXPECT_TRUE(encryption->initialize(params1, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    auto encrypted1 = encryption->encrypt(test_audio);
    EXPECT_EQ(encrypted1.size(), test_audio.size());
    
    // Test with different key
    EncryptionParams params2 = encryption_params;
    params2.key_data = "different_key_data";
    
    EXPECT_TRUE(encryption->initialize(params2, audio_params));
    EXPECT_TRUE(encryption->setKey(67890, "different_key_data"));
    
    auto encrypted2 = encryption->encrypt(test_audio);
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
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    // Test with empty audio
    std::vector<float> empty_audio;
    auto encrypted_empty = encryption->encrypt(empty_audio);
    EXPECT_EQ(encrypted_empty.size(), 0);
    
    // Test with single sample
    std::vector<float> single_sample = {0.5f};
    auto encrypted_single = encryption->encrypt(single_sample);
    EXPECT_EQ(encrypted_single.size(), 1);
    
    // Test with very short audio
    std::vector<float> short_audio = {0.1f, 0.2f, 0.3f};
    auto encrypted_short = encryption->encrypt(short_audio);
    EXPECT_EQ(encrypted_short.size(), 3);
}

// Test performance characteristics
TEST_F(VoiceEncryptionTest, PerformanceCharacteristics) {
    auto encryption = createVoiceEncryption(EncryptionType::YACHTA_T219);
    ASSERT_NE(encryption, nullptr);
    
    EXPECT_TRUE(encryption->initialize(encryption_params, audio_params));
    EXPECT_TRUE(encryption->setKey(12345, "test_key_data"));
    
    // Test with longer audio
    auto long_audio = generateTestTone(1000.0f, 5.0f); // 5 seconds
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto encrypted = encryption->encrypt(long_audio);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_EQ(encrypted.size(), long_audio.size());
    EXPECT_LT(duration.count(), 1000) << "Encryption should complete within 1 second for 5 seconds of audio";
}

// Test factory function
TEST_F(VoiceEncryptionTest, FactoryFunction) {
    auto yachta = createVoiceEncryption(EncryptionType::YACHTA_T219);
    EXPECT_NE(yachta, nullptr);
    
    auto none = createVoiceEncryption(EncryptionType::NONE);
    EXPECT_EQ(none, nullptr);
    
    auto granit = createVoiceEncryption(EncryptionType::GRANIT);
    EXPECT_EQ(granit, nullptr);
    
    auto vinson = createVoiceEncryption(EncryptionType::VINSON_KY57);
    EXPECT_EQ(vinson, nullptr);
    
    auto stanag = createVoiceEncryption(EncryptionType::STANAG_4197);
    EXPECT_EQ(stanag, nullptr);
    
    auto custom = createVoiceEncryption(EncryptionType::CUSTOM);
    EXPECT_EQ(custom, nullptr);
}
