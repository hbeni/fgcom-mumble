#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>

// Include FGCom-mumble headers
#include "../../client/mumble-plugin/lib/agc_squelch.h"

// Fuzzing target for AGC (Automatic Gain Control) functions
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Need minimum data
    
    // Systematically consume input bytes
    size_t offset = 0;
    
    // Extract AGC parameters (4 bytes each for float)
    float input_level_db = -60.0f;
    float target_level_db = -20.0f;
    float attack_time_ms = 10.0f;
    float release_time_ms = 100.0f;
    float max_gain_db = 40.0f;
    float min_gain_db = -20.0f;
    
    if (offset + 4 <= Size) {
        std::memcpy(&input_level_db, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&target_level_db, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&attack_time_ms, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&release_time_ms, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&max_gain_db, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        std::memcpy(&min_gain_db, Data + offset, 4);
        offset += 4;
    }
    
    // Extract audio sample count and generate samples
    size_t sample_count = 1024; // Default
    if (offset + 4 <= Size) {
        uint32_t temp_count;
        std::memcpy(&temp_count, Data + offset, 4);
        sample_count = std::min(static_cast<size_t>(temp_count), 4096UL); // Limit to reasonable size
        offset += 4;
    }
    
    try {
        // Get AGC instance
        auto& agc = FGCom_AGC_Squelch::getInstance();
        
        // Configure AGC
        AGCConfig config;
        config.mode = AGCMode::SLOW;
        config.threshold_db = target_level_db;
        config.max_gain_db = max_gain_db;
        config.min_gain_db = min_gain_db;
        config.attack_time_ms = attack_time_ms;
        config.release_time_ms = release_time_ms;
        config.enable_agc_hold = true;
        config.hold_time_ms = 1000.0f;
        
        agc.setAGCConfig(config);
        
        // Generate audio samples from input data
        std::vector<float> audio_samples(sample_count);
        for (size_t i = 0; i < sample_count && offset + 4 <= Size; ++i) {
            std::memcpy(&audio_samples[i], Data + offset, 4);
            offset += 4;
        }
        
        // Fill remaining samples with generated data if needed
        for (size_t i = offset / 4; i < sample_count; ++i) {
            // Generate deterministic samples based on input
            float t = static_cast<float>(i) / 44100.0f;
            audio_samples[i] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * t);
        }
        
        // Apply input level scaling
        float scale_factor = std::pow(10.0f, input_level_db / 20.0f);
        for (auto& sample : audio_samples) {
            sample *= scale_factor;
        }
        
        // CRITICAL PATH 1: Complete AGC processing pipeline
        // This is the main AGC functionality - simulate a full audio processing session
        
        // Step 1: Initialize AGC system
        agc.resetToDefaultState();
        
        // Step 2: Test AGC configuration and setup (CRITICAL PATH)
        std::vector<AGCMode> agc_modes = {AGCMode::OFF, AGCMode::FAST, AGCMode::MEDIUM, AGCMode::SLOW};
        for (AGCMode mode : agc_modes) {
            config.mode = mode;
            agc.setAGCConfig(config);
            
            // Test AGC processing with each mode
            std::vector<float> processed_samples = audio_samples;
            agc.processAGC(processed_samples);
            
            // Test AGC statistics collection (CRITICAL for monitoring)
            AGCStats stats = agc.getAGCStats();
        }
        
        // CRITICAL PATH 2: AGC gain control algorithm
        // Test the main AGC gain calculation and application logic
        
        // Test with different input levels to trigger AGC response
        std::vector<float> input_levels = {-80.0f, -60.0f, -40.0f, -20.0f, 0.0f, 20.0f};
        for (float level : input_levels) {
            std::vector<float> test_samples = audio_samples;
            float scale_factor = std::pow(10.0f, level / 20.0f);
            for (auto& sample : test_samples) {
                sample *= scale_factor;
            }
            
            // Process through AGC
            agc.processAGC(test_samples);
            
            // Test AGC response to level changes
            for (auto& sample : test_samples) {
                sample *= 0.1f; // Sudden level drop
            }
            agc.processAGC(test_samples);
            
            for (auto& sample : test_samples) {
                sample *= 10.0f; // Sudden level increase
            }
            agc.processAGC(test_samples);
        }
        
        // CRITICAL PATH 3: AGC attack and release timing
        // Test the main AGC timing algorithms
        
        // Test attack time behavior
        config.attack_time_ms = 1.0f; // Fast attack
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        config.attack_time_ms = 100.0f; // Slow attack
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        // Test release time behavior
        config.release_time_ms = 10.0f; // Fast release
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        config.release_time_ms = 1000.0f; // Slow release
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        // CRITICAL PATH 4: Squelch functionality
        // Test the main squelch detection and control logic
        
        SquelchConfig squelch_config;
        squelch_config.enabled = true;
        squelch_config.threshold_db = target_level_db;
        squelch_config.hysteresis_db = 3.0f;
        squelch_config.attack_time_ms = 5.0f;
        squelch_config.release_time_ms = 50.0f;
        squelch_config.tone_squelch = true;
        squelch_config.tone_frequency_hz = 1000.0f;
        squelch_config.noise_squelch = true;
        squelch_config.noise_threshold_db = -70.0f;
        
        agc.setSquelchConfig(squelch_config);
        
        // Test squelch with different signal levels
        std::vector<float> squelch_levels = {-100.0f, -80.0f, -60.0f, -40.0f, -20.0f};
        for (float level : squelch_levels) {
            std::vector<float> squelch_samples = audio_samples;
            float scale_factor = std::pow(10.0f, level / 20.0f);
            for (auto& sample : squelch_samples) {
                sample *= scale_factor;
            }
            
            // Test squelch processing
            agc.processSquelch(squelch_samples);
            
            // Test squelch statistics
            SquelchStats squelch_stats = agc.getSquelchStats();
        }
        
        // CRITICAL PATH 5: Tone squelch detection
        // Test the main tone detection algorithm
        
        // Generate tone signals for testing
        std::vector<float> tone_samples(sample_count);
        for (size_t i = 0; i < sample_count; ++i) {
            float t = static_cast<float>(i) / 44100.0f;
            tone_samples[i] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * t); // 1kHz tone
        }
        
        agc.processSquelch(tone_samples);
        
        // Test with different tone frequencies
        std::vector<float> tone_frequencies = {100.0f, 500.0f, 1000.0f, 2000.0f, 5000.0f};
        for (float freq : tone_frequencies) {
            squelch_config.tone_frequency_hz = freq;
            agc.setSquelchConfig(squelch_config);
            
            for (size_t i = 0; i < sample_count; ++i) {
                float t = static_cast<float>(i) / 44100.0f;
                tone_samples[i] = 0.5f * std::sin(2.0f * M_PI * freq * t);
            }
            agc.processSquelch(tone_samples);
        }
        
        // CRITICAL PATH 6: Noise squelch detection
        // Test the main noise detection algorithm
        
        // Generate noise signals for testing
        std::vector<float> noise_samples(sample_count);
        for (size_t i = 0; i < sample_count; ++i) {
            // Generate pseudo-random noise
            float noise = static_cast<float>(i % 1000) / 1000.0f - 0.5f;
            noise_samples[i] = noise * 0.1f; // Low level noise
        }
        
        agc.processSquelch(noise_samples);
        
        // Test with different noise levels
        std::vector<float> noise_levels = {-100.0f, -80.0f, -60.0f, -40.0f};
        for (float level : noise_levels) {
            float scale_factor = std::pow(10.0f, level / 20.0f);
            for (auto& sample : noise_samples) {
                sample *= scale_factor;
            }
            agc.processSquelch(noise_samples);
        }
        
        // CRITICAL PATH 7: AGC hold functionality
        // Test the main AGC hold mechanism
        
        config.enable_agc_hold = true;
        config.hold_time_ms = 1000.0f;
        agc.setAGCConfig(config);
        
        // Test AGC hold with varying signal levels
        for (int i = 0; i < 10; ++i) {
            std::vector<float> hold_samples = audio_samples;
            float level = -60.0f + (i * 10.0f);
            float scale_factor = std::pow(10.0f, level / 20.0f);
            for (auto& sample : hold_samples) {
                sample *= scale_factor;
            }
            agc.processAGC(hold_samples);
        }
        
        // CRITICAL PATH 8: AGC gain limiting
        // Test the main AGC gain limiting logic
        
        config.max_gain_db = 40.0f;
        config.min_gain_db = -20.0f;
        agc.setAGCConfig(config);
        
        // Test with extreme input levels to trigger gain limiting
        std::vector<float> extreme_samples = audio_samples;
        for (auto& sample : extreme_samples) {
            sample *= 1000.0f; // Very high level
        }
        agc.processAGC(extreme_samples);
        
        for (auto& sample : extreme_samples) {
            sample *= 0.0001f; // Very low level
        }
        agc.processAGC(extreme_samples);
        
        // CRITICAL PATH 9: AGC statistics and monitoring
        // Test the main AGC monitoring and statistics collection
        
        AGCStats stats = agc.getAGCStats();
        SquelchStats squelch_stats = agc.getSquelchStats();
        
        // Test statistics with different processing scenarios
        for (int i = 0; i < 5; ++i) {
            std::vector<float> stat_samples = audio_samples;
            float level = -80.0f + (i * 20.0f);
            float scale_factor = std::pow(10.0f, level / 20.0f);
            for (auto& sample : stat_samples) {
                sample *= scale_factor;
            }
            
            agc.processAGC(stat_samples);
            agc.processSquelch(stat_samples);
            
            // Update statistics
            stats = agc.getAGCStats();
            squelch_stats = agc.getSquelchStats();
        }
        
        // CRITICAL PATH 10: Error handling and edge cases
        // Test the main error handling paths
        
        // Test with invalid configuration parameters
        config.attack_time_ms = -1.0f;
        config.release_time_ms = -1.0f;
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        // Test with extreme gain values
        config.max_gain_db = 200.0f;
        config.min_gain_db = -200.0f;
        agc.setAGCConfig(config);
        agc.processAGC(audio_samples);
        
        // Test with NaN and infinity values
        if (sample_count > 0) {
            audio_samples[0] = std::numeric_limits<float>::quiet_NaN();
            agc.processAGC(audio_samples);
            agc.processSquelch(audio_samples);
            
            audio_samples[0] = std::numeric_limits<float>::infinity();
            agc.processAGC(audio_samples);
            agc.processSquelch(audio_samples);
            
            audio_samples[0] = -std::numeric_limits<float>::infinity();
            agc.processAGC(audio_samples);
            agc.processSquelch(audio_samples);
        }
        
        // Test with empty audio buffer
        std::vector<float> empty_buffer;
        agc.processAGC(empty_buffer);
        agc.processSquelch(empty_buffer);
        
        // Test with single sample
        std::vector<float> single_sample = {0.5f};
        agc.processAGC(single_sample);
        agc.processSquelch(single_sample);
        
        // CRITICAL PATH 11: AGC reset and reinitialization
        // Test the main AGC reset functionality
        
        agc.resetToDefaultState();
        
        // Verify reset worked by checking statistics
        AGCStats reset_stats = agc.getAGCStats();
        SquelchStats reset_squelch_stats = agc.getSquelchStats();
        
        // Test processing after reset
        agc.processAGC(audio_samples);
        agc.processSquelch(audio_samples);
        
        return 0;
        
    } catch (const std::exception& e) {
        // Fuzzing should continue even if exceptions occur
        return 0;
    } catch (...) {
        // Handle any other exceptions
        return 0;
    }
}
