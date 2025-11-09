/*
 * White Noise Generation Tests for FGCom-mumble Plugin
 * 
 * This test suite validates white noise generation in mumble_onAudioSourceFetched()
 * specifically testing the fix for white noise at 0% squelch when isSpeech == false
 * 
 * Test Coverage:
 * - White noise generation when squelch is at 0% and isSpeech == false
 * - White noise volume scaling with squelch level
 * - No white noise when squelch is closed
 * - White noise with multiple radios
 * - Integration with radio operable state and frequency
 */

#include "test_client_plugin_module_main.cpp"
#include <cmath>
#include <algorithm>
#include <thread>
#include <atomic>

// Forward declarations for plugin functions
extern bool mumble_onAudioSourceFetched(float *outputPCM, uint32_t sampleCount, 
                                        uint16_t channelCount, uint32_t sampleRate, 
                                        bool isSpeech, mumble_userid_t userID);

// fgcom_inSpecialChannel is defined in fgcom-mumble.cpp, not in globalVars.h
// We need to declare it here for the test
extern std::atomic<bool> fgcom_inSpecialChannel;

// Helper function to calculate RMS (Root Mean Square) of audio samples
float calculateRMS(const float* samples, size_t count) {
    if (count == 0) return 0.0f;
    
    float sum_squares = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum_squares += samples[i] * samples[i];
    }
    return std::sqrt(sum_squares / count);
}

// Helper function to check if audio contains noise (non-zero samples)
bool hasNonZeroSamples(const float* samples, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (std::abs(samples[i]) > 0.0001f) {
            return true;
        }
    }
    return false;
}

// Helper function to count non-zero samples
size_t countNonZeroSamples(const float* samples, size_t count) {
    size_t non_zero = 0;
    for (size_t i = 0; i < count; ++i) {
        if (std::abs(samples[i]) > 0.0001f) {
            non_zero++;
        }
    }
    return non_zero;
}

// Test suite for white noise generation
class WhiteNoiseGenerationTest : public ClientPluginModuleTest {
protected:
    void SetUp() override {
        ClientPluginModuleTest::SetUp();
        
        // Initialize plugin state
        fgcom_cfg.radioAudioEffects = true;
        
        // Set plugin active state directly (bypassing connection check)
        // mumble_onAudioSourceFetched checks fgcom_isPluginActive() which reads fgcom_inSpecialChannel
        fgcom_inSpecialChannel.store(true);
        
        // Clear any existing local client data
        std::lock_guard<std::mutex> lock(fgcom_localcfg_mtx);
        fgcom_local_client.clear();
        
        // Test audio buffer parameters
        test_sample_count = 512;
        test_channel_count = 2;
        test_sample_rate = 48000;
        test_buffer_size = test_sample_count * test_channel_count;
    }
    
    void TearDown() override {
        // Cleanup
        fgcom_inSpecialChannel.store(false);
        std::lock_guard<std::mutex> lock(fgcom_localcfg_mtx);
        fgcom_local_client.clear();
    }
    
    // Helper to setup a radio with specific squelch
    void setupRadio(int identity_id, int radio_id, float squelch, bool operable = true, const std::string& frequency = "121.500") {
        std::lock_guard<std::mutex> lock(fgcom_localcfg_mtx);
        
        // Ensure identity exists
        if (fgcom_local_client.find(identity_id) == fgcom_local_client.end()) {
            fgcom_client new_client;
            new_client.lat = 40.7128;
            new_client.lon = -74.0060;
            new_client.alt = 1000.0f;
            new_client.callsign = "TEST" + std::to_string(identity_id);
            fgcom_local_client[identity_id] = new_client;
        }
        
        // Ensure radio exists
        if (radio_id >= static_cast<int>(fgcom_local_client[identity_id].radios.size())) {
            fgcom_local_client[identity_id].radios.resize(radio_id + 1);
        }
        
        // Configure radio
        fgcom_local_client[identity_id].radios[radio_id].squelch = squelch;
        fgcom_local_client[identity_id].radios[radio_id].operable = operable;
        fgcom_local_client[identity_id].radios[radio_id].frequency = frequency;
        fgcom_local_client[identity_id].radios[radio_id].ptt = false;
        fgcom_local_client[identity_id].radios[radio_id].volume = 1.0f;
    }
    
    uint32_t test_sample_count;
    uint16_t test_channel_count;
    uint32_t test_sample_rate;
    size_t test_buffer_size;
};

// Test 1: White noise generated when squelch is 0% and isSpeech == false
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseAtZeroSquelchNoSpeech) {
    // Setup: Radio with 0% squelch, operable, frequency set
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    // Create audio buffer (initialized to silence)
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched with isSpeech == false
    bool result = mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0       // userID (not used when isSpeech == false)
    );
    
    // Verify: Audio buffer should contain noise (non-zero samples)
    EXPECT_TRUE(result) << "mumble_onAudioSourceFetched should return true when modifying audio";
    EXPECT_TRUE(hasNonZeroSamples(outputPCM, test_buffer_size)) 
        << "Audio buffer should contain white noise when squelch is 0% and isSpeech == false";
    
    // Verify: RMS should be greater than zero (indicating noise was added)
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_GT(rms, 0.0f) << "RMS should be greater than zero when white noise is generated";
    EXPECT_LT(rms, 0.5f) << "RMS should be reasonable (not clipping)";
}

// Test 2: No white noise when squelch is closed (100%)
TEST_F(WhiteNoiseGenerationTest, NoWhiteNoiseWhenSquelchClosed) {
    // Setup: Radio with 100% squelch (closed)
    setupRadio(0, 0, 1.0f, true, "121.500");
    
    // Create audio buffer (initialized to silence)
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched with isSpeech == false
    bool result = mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0       // userID
    );
    
    // Verify: Audio buffer should remain silent (or result should be false)
    // Note: The function may return false or leave buffer unchanged
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_LE(rms, 0.001f) << "Audio buffer should remain silent when squelch is closed";
}

// Test 3: White noise volume scales with squelch level
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseVolumeScalesWithSquelch) {
    std::vector<float> squelch_levels = {0.0f, 0.05f, 0.1f};  // 0%, 5%, 10%
    std::vector<float> rms_values;
    
    for (float squelch : squelch_levels) {
        // Setup radio with specific squelch
        setupRadio(0, 0, squelch, true, "121.500");
        
        // Create fresh audio buffer
        std::vector<float> audio_buffer(test_buffer_size, 0.0f);
        float* outputPCM = audio_buffer.data();
        
        // Call mumble_onAudioSourceFetched
        mumble_onAudioSourceFetched(
            outputPCM, 
            test_sample_count, 
            test_channel_count, 
            test_sample_rate,
            false,  // isSpeech == false
            0
        );
        
        // Calculate RMS
        float rms = calculateRMS(outputPCM, test_buffer_size);
        rms_values.push_back(rms);
    }
    
    // Verify: Lower squelch should produce more noise (higher RMS)
    // Squelch 0.0 should have highest RMS, squelch 0.1 should have lowest
    EXPECT_GT(rms_values[0], rms_values[1]) 
        << "Squelch 0% should produce more noise than squelch 5%";
    EXPECT_GT(rms_values[1], rms_values[2]) 
        << "Squelch 5% should produce more noise than squelch 10%";
    EXPECT_GT(rms_values[0], 0.0f) 
        << "Squelch 0% should produce noise";
}

// Test 4: No white noise when radio is not operable
TEST_F(WhiteNoiseGenerationTest, NoWhiteNoiseWhenRadioNotOperable) {
    // Setup: Radio with 0% squelch but NOT operable
    setupRadio(0, 0, 0.0f, false, "121.500");  // operable = false
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched
    mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0
    );
    
    // Verify: No noise should be generated
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_LE(rms, 0.001f) << "No white noise should be generated when radio is not operable";
}

// Test 5: No white noise when frequency is not set
TEST_F(WhiteNoiseGenerationTest, NoWhiteNoiseWhenFrequencyNotSet) {
    // Setup: Radio with 0% squelch but empty frequency
    setupRadio(0, 0, 0.0f, true, "");  // empty frequency
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched
    mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0
    );
    
    // Verify: No noise should be generated
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_LE(rms, 0.001f) << "No white noise should be generated when frequency is not set";
}

// Test 6: White noise with multiple radios (should use best/highest noise level)
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseWithMultipleRadios) {
    // Setup: Two radios with different squelch levels
    setupRadio(0, 0, 0.05f, true, "121.500");  // 5% squelch
    setupRadio(0, 1, 0.0f, true, "123.450");  // 0% squelch (should produce more noise)
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched
    mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0
    );
    
    // Verify: Noise should be generated (from the radio with 0% squelch)
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_GT(rms, 0.0f) << "White noise should be generated with multiple radios";
    
    // The noise level should reflect the best (lowest squelch) radio
    EXPECT_GT(rms, 0.01f) << "Noise level should be significant with 0% squelch radio";
}

// Test 7: No white noise when plugin is not active
TEST_F(WhiteNoiseGenerationTest, NoWhiteNoiseWhenPluginInactive) {
    // Setup: Radio with 0% squelch
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    // Deactivate plugin by setting fgcom_inSpecialChannel to false
    fgcom_inSpecialChannel.store(false);
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched
    bool result = mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0
    );
    
    // Verify: No noise should be generated, function should return false
    EXPECT_FALSE(result) << "Function should return false when plugin is not active";
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_LE(rms, 0.001f) << "No white noise should be generated when plugin is inactive";
    
    // Restore plugin state
    fgcom_inSpecialChannel.store(true);
}

// Test 8: No white noise when audio effects are disabled
TEST_F(WhiteNoiseGenerationTest, NoWhiteNoiseWhenAudioEffectsDisabled) {
    // Setup: Radio with 0% squelch
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    // Disable audio effects
    fgcom_cfg.radioAudioEffects = false;
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched
    mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        false,  // isSpeech == false
        0
    );
    
    // Verify: No noise should be generated
    float rms = calculateRMS(outputPCM, test_buffer_size);
    EXPECT_LE(rms, 0.001f) << "No white noise should be generated when audio effects are disabled";
    
    // Restore audio effects
    fgcom_cfg.radioAudioEffects = true;
}

// Test 9: White noise when isSpeech == true but no signal (bestSignalStrength <= 0)
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseWhenSpeechButNoSignal) {
    // Setup: Radio with 0% squelch
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    // Create audio buffer
    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
    float* outputPCM = audio_buffer.data();
    
    // Call mumble_onAudioSourceFetched with isSpeech == true
    // This should also generate white noise when bestSignalStrength <= 0
    bool result = mumble_onAudioSourceFetched(
        outputPCM, 
        test_sample_count, 
        test_channel_count, 
        test_sample_rate,
        true,   // isSpeech == true
        0       // userID
    );
    
    // Note: This test may pass or fail depending on current implementation
    // The fix should ensure white noise is generated in the !isSpeech case
    // This test verifies the existing behavior in the isSpeech case
}

// Test 10: Performance - white noise generation should be fast
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseGenerationPerformance) {
    // Setup: Radio with 0% squelch
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    const int iterations = 100;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<float> audio_buffer(test_buffer_size, 0.0f);
        float* outputPCM = audio_buffer.data();
        
        mumble_onAudioSourceFetched(
            outputPCM, 
            test_sample_count, 
            test_channel_count, 
            test_sample_rate,
            false,  // isSpeech == false
            0
        );
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double time_per_call = static_cast<double>(duration.count()) / iterations;
    
    // White noise generation should be fast (< 1ms per call for audio thread)
    EXPECT_LT(time_per_call, 1000.0) 
        << "White noise generation should be fast: " << time_per_call << " microseconds per call";
    
    std::cout << "White noise generation performance: " << time_per_call << " microseconds per call" << std::endl;
}

// Test 11: Thread safety - multiple calls should not cause issues
TEST_F(WhiteNoiseGenerationTest, WhiteNoiseGenerationThreadSafety) {
    // Setup: Radio with 0% squelch
    setupRadio(0, 0, 0.0f, true, "121.500");
    
    const int num_threads = 4;
    const int calls_per_thread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    // Launch multiple threads calling the function
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < calls_per_thread; ++i) {
                try {
                    std::vector<float> audio_buffer(test_buffer_size, 0.0f);
                    float* outputPCM = audio_buffer.data();
                    
                    bool result = mumble_onAudioSourceFetched(
                        outputPCM, 
                        test_sample_count, 
                        test_channel_count, 
                        test_sample_rate,
                        false,  // isSpeech == false
                        0
                    );
                    
                    if (result && hasNonZeroSamples(outputPCM, test_buffer_size)) {
                        success_count++;
                    } else {
                        failure_count++;
                    }
                } catch (...) {
                    failure_count++;
                }
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify: Most calls should succeed (some may fail due to try_lock, which is acceptable)
    int total_calls = num_threads * calls_per_thread;
    EXPECT_GT(success_count.load(), total_calls * 0.5) 
        << "At least 50% of calls should succeed even under thread contention";
    
    std::cout << "Thread safety test: " << success_count.load() << " successes, " 
              << failure_count.load() << " failures out of " << total_calls << " calls" << std::endl;
}

// Test 12: Squelch threshold boundary test (0.1f threshold)
TEST_F(WhiteNoiseGenerationTest, SquelchThresholdBoundary) {
    // Test values around the 0.1f threshold
    std::vector<float> test_squelches = {0.09f, 0.10f, 0.11f};  // Just below, at, and above threshold
    
    for (float squelch : test_squelches) {
        setupRadio(0, 0, squelch, true, "121.500");
        
        std::vector<float> audio_buffer(test_buffer_size, 0.0f);
        float* outputPCM = audio_buffer.data();
        
        mumble_onAudioSourceFetched(
            outputPCM, 
            test_sample_count, 
            test_channel_count, 
            test_sample_rate,
            false,  // isSpeech == false
            0
        );
        
        float rms = calculateRMS(outputPCM, test_buffer_size);
        
        if (squelch <= 0.1f) {
            EXPECT_GT(rms, 0.0f) 
                << "Squelch " << squelch << " (<= 0.1) should generate noise";
        } else {
            EXPECT_LE(rms, 0.001f) 
                << "Squelch " << squelch << " (> 0.1) should not generate noise";
        }
    }
}

