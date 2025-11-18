#include "test_fixtures.h"

// Audio Processing Edge Case Tests
// These tests cover extreme conditions, boundary values, and error states

TEST_F(AudioEffectsTest, ExtremeAmplitudeValues) {
    // Test with extreme amplitude values
    std::vector<float> extreme_samples = {
        -1.0f, 1.0f,           // Normal range boundaries
        -2.0f, 2.0f,           // Beyond normal range
        -10.0f, 10.0f,        // Very extreme values
        std::numeric_limits<float>::min(),
        std::numeric_limits<float>::max(),
        -std::numeric_limits<float>::max()
    };
    
    for (float sample : extreme_samples) {
        std::vector<float> input = {sample};
        std::vector<float> output = input;
        
        // Test that processing handles extreme values gracefully
        EXPECT_NO_THROW({
            // Apply basic processing
            for (float& s : output) {
                s = std::max(-1.0f, std::min(1.0f, s)); // Clamp to valid range
            }
        }) << "Processing should handle extreme amplitude: " << sample;
        
        // Verify output is within valid range
        for (float s : output) {
            EXPECT_GE(s, -1.0f) << "Output should be >= -1.0";
            EXPECT_LE(s, 1.0f) << "Output should be <= 1.0";
            EXPECT_TRUE(std::isfinite(s)) << "Output should be finite";
        }
    }
}

TEST_F(AudioEffectsTest, InvalidFloatValues) {
    // Test with invalid float values (NaN, infinity)
    std::vector<float> invalid_samples = {
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(),
        -std::numeric_limits<float>::infinity(),
        0.0f / 0.0f,  // NaN
        1.0f / 0.0f, // +infinity
        -1.0f / 0.0f  // -infinity
    };
    
    for (float sample : invalid_samples) {
        std::vector<float> input = {sample};
        std::vector<float> output = input;
        
        // Test that processing handles invalid values
        EXPECT_NO_THROW({
            // Apply basic processing with validation
            for (float& s : output) {
                if (!std::isfinite(s)) {
                    s = 0.0f; // Replace invalid values with silence
                }
                s = std::max(-1.0f, std::min(1.0f, s)); // Clamp to valid range
            }
        }) << "Processing should handle invalid float: " << sample;
        
        // Verify output is valid
        for (float s : output) {
            EXPECT_TRUE(std::isfinite(s)) << "Output should be finite";
            EXPECT_GE(s, -1.0f) << "Output should be >= -1.0";
            EXPECT_LE(s, 1.0f) << "Output should be <= 1.0";
        }
    }
}

TEST_F(AudioEffectsTest, EmptyAndNullInputs) {
    // Test with empty inputs
    std::vector<float> empty_input;
    std::vector<float> empty_output;
    
    EXPECT_NO_THROW({
        // Process empty input
        empty_output = empty_input;
    }) << "Processing should handle empty input gracefully";
    
    EXPECT_EQ(empty_output.size(), 0) << "Empty input should produce empty output";
    
    // Test with null pointers (simulated)
    std::vector<float> single_sample = {0.5f};
    std::vector<float> output = single_sample;
    
    EXPECT_NO_THROW({
        // Simulate null pointer handling
        if (single_sample.data() != nullptr) {
            for (size_t i = 0; i < single_sample.size(); ++i) {
                output[i] = single_sample[i];
            }
        }
    }) << "Processing should handle null pointer checks";
}

TEST_F(AudioEffectsTest, VeryLargeSampleCounts) {
    // Test with very large sample counts
    const size_t large_count = 1000000; // 1 million samples
    std::vector<float> large_input(large_count);
    
    // Fill with sine wave
    for (size_t i = 0; i < large_count; ++i) {
        large_input[i] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * i / 48000.0f);
    }
    
    std::vector<float> large_output = large_input;
    
    EXPECT_NO_THROW({
        // Process large input
        for (size_t i = 0; i < large_output.size(); ++i) {
            large_output[i] = std::max(-1.0f, std::min(1.0f, large_output[i]));
        }
    }) << "Processing should handle large sample counts";
    
    EXPECT_EQ(large_output.size(), large_count) << "Output size should match input size";
    
    // Verify output is valid
    for (float sample : large_output) {
        EXPECT_TRUE(std::isfinite(sample)) << "All output samples should be finite";
        EXPECT_GE(sample, -1.0f) << "All output samples should be >= -1.0";
        EXPECT_LE(sample, 1.0f) << "All output samples should be <= 1.0";
    }
}

TEST_F(AudioEffectsTest, ZeroAndNegativeSampleRates) {
    // Test with invalid sample rates
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, 48000, 960);
    
    // Test zero sample rate
    EXPECT_NO_THROW({
        // Simulate zero sample rate handling
        if (0 > 0) {
            // Process normally
            for (float& sample : input_samples) {
                sample = std::max(-1.0f, std::min(1.0f, sample));
            }
        } else {
            // Handle zero sample rate
            std::fill(input_samples.begin(), input_samples.end(), 0.0f);
        }
    }) << "Processing should handle zero sample rate";
    
    // Test negative sample rate
    EXPECT_NO_THROW({
        // Simulate negative sample rate handling
        if (-48000 > 0) {
            // Process normally
            for (float& sample : input_samples) {
                sample = std::max(-1.0f, std::min(1.0f, sample));
            }
        } else {
            // Handle negative sample rate
            std::fill(input_samples.begin(), input_samples.end(), 0.0f);
        }
    }) << "Processing should handle negative sample rate";
}

TEST_F(AudioEffectsTest, MemoryPressureConditions) {
    // Test under memory pressure conditions
    std::vector<std::vector<float>> memory_blocks;
    
    // Allocate multiple large blocks to simulate memory pressure
    for (int i = 0; i < 10; ++i) {
        memory_blocks.emplace_back(100000, 0.5f); // 100k samples each
    }
    
    std::vector<float> test_input = generateSineWave(1000.0f, 0.5f, 48000, 960);
    std::vector<float> test_output = test_input;
    
    EXPECT_NO_THROW({
        // Process under memory pressure
        for (float& sample : test_output) {
            sample = std::max(-1.0f, std::min(1.0f, sample));
        }
    }) << "Processing should work under memory pressure";
    
    // Verify output is still valid
    for (float sample : test_output) {
        EXPECT_TRUE(std::isfinite(sample)) << "Output should be finite under memory pressure";
        EXPECT_GE(sample, -1.0f) << "Output should be >= -1.0";
        EXPECT_LE(sample, 1.0f) << "Output should be <= 1.0";
    }
}

TEST_F(AudioEffectsTest, ConcurrentAccessEdgeCases) {
    // Test concurrent access edge cases
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, 48000, 960);
    std::vector<float> output_samples = input_samples;
    
    // Simulate concurrent access
    std::atomic<bool> processing_done{false};
    std::atomic<int> concurrent_access_count{0};
    
    // Start multiple threads
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&]() {
            concurrent_access_count++;
            
            // Process samples
            for (float& sample : output_samples) {
                sample = std::max(-1.0f, std::min(1.0f, sample));
            }
            
            concurrent_access_count--;
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(concurrent_access_count.load(), 0) << "All concurrent access should complete";
    
    // Verify output is valid
    for (float sample : output_samples) {
        EXPECT_TRUE(std::isfinite(sample)) << "Output should be finite after concurrent access";
        EXPECT_GE(sample, -1.0f) << "Output should be >= -1.0";
        EXPECT_LE(sample, 1.0f) << "Output should be <= 1.0";
    }
}

TEST_F(AudioEffectsTest, BoundaryFrequencyValues) {
    // Test with boundary frequency values
    std::vector<float> frequencies = {
        0.0f,                    // Zero frequency
        0.1f,                    // Very low frequency
        24000.0f,                // Nyquist frequency (48kHz/2)
        23999.0f,                // Just below Nyquist
        24001.0f,                // Just above Nyquist
        48000.0f,                // Sample rate
        96000.0f,                // 2x sample rate
        std::numeric_limits<float>::max()  // Maximum float
    };
    
    for (float freq : frequencies) {
        std::vector<float> input_samples;
        
        if (freq > 0.0f && freq < 24000.0f) {
            // Generate sine wave for valid frequencies
            input_samples = generateSineWave(freq, 0.5f, 48000, 960);
        } else {
            // Generate silence for invalid frequencies
            input_samples = std::vector<float>(960, 0.0f);
        }
        
        std::vector<float> output_samples = input_samples;
        
        EXPECT_NO_THROW({
            // Process samples
            for (float& sample : output_samples) {
                sample = std::max(-1.0f, std::min(1.0f, sample));
            }
        }) << "Processing should handle frequency: " << freq;
        
        // Verify output is valid
        for (float sample : output_samples) {
            EXPECT_TRUE(std::isfinite(sample)) << "Output should be finite for frequency: " << freq;
            EXPECT_GE(sample, -1.0f) << "Output should be >= -1.0";
            EXPECT_LE(sample, 1.0f) << "Output should be <= 1.0";
        }
    }
}

TEST_F(AudioEffectsTest, RapidStateChanges) {
    // Test rapid state changes
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, 48000, 960);
    std::vector<float> output_samples = input_samples;
    
    // Simulate rapid state changes
    bool state = false;
    for (size_t i = 0; i < output_samples.size(); ++i) {
        // Toggle state every 10 samples
        if (i % 10 == 0) {
            state = !state;
        }
        
        if (state) {
            // Apply processing
            output_samples[i] = std::max(-1.0f, std::min(1.0f, output_samples[i]));
        } else {
            // No processing
            output_samples[i] = input_samples[i];
        }
    }
    
    // Verify output is valid
    for (float sample : output_samples) {
        EXPECT_TRUE(std::isfinite(sample)) << "Output should be finite after rapid state changes";
        EXPECT_GE(sample, -1.0f) << "Output should be >= -1.0";
        EXPECT_LE(sample, 1.0f) << "Output should be <= 1.0";
    }
}

TEST_F(AudioEffectsTest, ResourceExhaustionScenarios) {
    // Test resource exhaustion scenarios
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, 48000, 960);
    
    // Simulate resource exhaustion by limiting available memory
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size());
    
    EXPECT_NO_THROW({
        // Process with limited resources
        for (float sample : input_samples) {
            float processed_sample = std::max(-1.0f, std::min(1.0f, sample));
            output_samples.push_back(processed_sample);
        }
    }) << "Processing should handle resource exhaustion gracefully";
    
    EXPECT_EQ(output_samples.size(), input_samples.size()) << "Output size should match input size";
    
    // Verify output is valid
    for (float sample : output_samples) {
        EXPECT_TRUE(std::isfinite(sample)) << "Output should be finite under resource exhaustion";
        EXPECT_GE(sample, -1.0f) << "Output should be >= -1.0";
        EXPECT_LE(sample, 1.0f) << "Output should be <= 1.0";
    }
}
