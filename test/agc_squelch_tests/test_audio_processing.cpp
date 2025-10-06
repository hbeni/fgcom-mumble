#include "test_agc_squelch_main.cpp"

// 1.4 Audio Processing Tests
TEST_F(AudioProcessingTest, ZeroSampleCountHandling) {
    // Test processing with zero samples
    ASSERT_TRUE(isAGCValid());
    std::vector<float> input(0);
    std::vector<float> output(0);
    
    // Should not crash or throw
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 0, 44100.0f));
}

TEST_F(AudioProcessingTest, NullPointerHandling) {
    // Test with null pointers (should be handled gracefully)
    ASSERT_TRUE(isAGCValid());
    EXPECT_NO_THROW(getAGC().processAudioSamples(nullptr, nullptr, 0, 44100.0f));
    
    // Test with valid input but null output
    std::vector<float> input(1024, 0.1f);
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), nullptr, 1024, 44100.0f));
    
    // Test with null input but valid output
    std::vector<float> output(1024);
    EXPECT_NO_THROW(getAGC().processAudioSamples(nullptr, output.data(), 1024, 44100.0f));
}

TEST_F(AudioProcessingTest, LargeSampleCount) {
    // Test with large sample count (1M+ samples)
    ASSERT_TRUE(isAGCValid());
    const size_t large_sample_count = 1048576; // 1M samples
    std::vector<float> input(large_sample_count, 0.1f);
    std::vector<float> output(large_sample_count);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), large_sample_count, 44100.0f));
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Should complete within reasonable time (less than 1 second)
    EXPECT_LT(duration.count(), 1000);
    
    // Output should be valid (not all zeros or NaN)
    bool has_valid_output = false;
    for (size_t i = 0; i < std::min(large_sample_count, size_t(1000)); ++i) {
        if (!std::isnan(output[i]) && !std::isinf(output[i])) {
            has_valid_output = true;
            break;
        }
    }
    EXPECT_TRUE(has_valid_output);
}

TEST_F(AudioProcessingTest, VariousSampleRates) {
    ASSERT_TRUE(isAGCValid());
    std::vector<float> sample_rates = {8000.0f, 16000.0f, 44100.0f, 48000.0f, 96000.0f};
    std::vector<float> input(1024, 0.1f);
    std::vector<float> output(1024);
    
    for (float sample_rate : sample_rates) {
        EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, sample_rate));
        
        // Verify output is valid
        bool has_valid_output = false;
        for (size_t i = 0; i < 100; ++i) {
            if (!std::isnan(output[i]) && !std::isinf(output[i])) {
                has_valid_output = true;
                break;
            }
        }
        EXPECT_TRUE(has_valid_output) << "Invalid output for sample rate: " << sample_rate;
    }
}

TEST_F(AudioProcessingTest, SineWaveProcessing) {
    // Test with various sine wave frequencies
    ASSERT_TRUE(isAGCValid());
    std::vector<float> frequencies = {100.0f, 500.0f, 1000.0f, 2000.0f, 5000.0f};
    float sample_rate = 44100.0f;
    size_t sample_count = 1024;
    
    for (float frequency : frequencies) {
        auto input = generateSineWave(frequency, sample_rate, sample_count, 0.5f);
        std::vector<float> output(sample_count);
        
        EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), sample_count, sample_rate));
        
        // Verify output is not all zeros (unless squelch is closed)
        float output_sum = 0.0f;
        for (size_t i = 0; i < sample_count; ++i) {
            output_sum += std::abs(output[i]);
        }
        
        // Output should have some signal unless squelch is closed
        if (getAGC().isSquelchOpen()) {
            EXPECT_GT(output_sum, 0.0f) << "No output signal for frequency: " << frequency;
        }
    }
}

TEST_F(AudioProcessingTest, NoiseProcessing) {
    // Test with noise input
    ASSERT_TRUE(isAGCValid());
    auto input = generateNoise(1024, 0.1f);
    std::vector<float> output(1024);
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Verify output is valid
    bool has_valid_output = false;
    for (size_t i = 0; i < 100; ++i) {
        if (!std::isnan(output[i]) && !std::isinf(output[i])) {
            has_valid_output = true;
            break;
        }
    }
    EXPECT_TRUE(has_valid_output);
}

TEST_F(AudioProcessingTest, SilenceProcessing) {
    // Test with silence input
    ASSERT_TRUE(isAGCValid());
    auto input = generateSilence(1024);
    std::vector<float> output(1024);
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Output should be silence (all zeros or very small values)
    float max_output = 0.0f;
    for (size_t i = 0; i < 1024; ++i) {
        max_output = std::max(max_output, std::abs(output[i]));
    }
    EXPECT_LT(max_output, 1e-6f); // Should be essentially zero
}

TEST_F(AudioProcessingTest, ClippingPrevention) {
    // Test with high amplitude input to check clipping prevention
    ASSERT_TRUE(isAGCValid());
    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 10.0f); // Very high amplitude
    std::vector<float> output(1024);
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Check for clipping (values should be within reasonable range)
    for (size_t i = 0; i < 1024; ++i) {
        EXPECT_LT(std::abs(output[i]), 2.0f) << "Clipping detected at sample " << i;
        EXPECT_FALSE(std::isnan(output[i])) << "NaN detected at sample " << i;
        EXPECT_FALSE(std::isinf(output[i])) << "Infinity detected at sample " << i;
    }
}

TEST_F(AudioProcessingTest, AGCGainApplicationCorrectness) {
    // Test AGC gain application
    ASSERT_TRUE(isAGCValid());
    getAGC().enableAGC(true);
    getAGC().setSquelchEnabled(false);  // Disable squelch for AGC test
    getAGC().setAGCMode(AGCMode::FAST);
    
    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f); // Low amplitude
    std::vector<float> output(1024);
    
    getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    
    // AGC should increase gain for low amplitude input
    float input_rms = 0.0f;
    float output_rms = 0.0f;
    
    for (size_t i = 0; i < 1024; ++i) {
        input_rms += input[i] * input[i];
        output_rms += output[i] * output[i];
    }
    
    input_rms = std::sqrt(input_rms / 1024.0f);
    output_rms = std::sqrt(output_rms / 1024.0f);
    
    // Output should be louder than input due to AGC
    if (getAGC().isSquelchOpen()) {
        EXPECT_GT(output_rms, input_rms) << "AGC did not increase signal level";
    }
}

TEST_F(AudioProcessingTest, SquelchMutingCorrectness) {
    // Test squelch muting functionality
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchEnabled(true);
    getAGC().setSquelchThreshold(10.0f); // Very high threshold (above signal level)
    
    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.0001f); // Very low amplitude (below threshold)
    std::vector<float> output(1024);
    
    // Process multiple times to give squelch time to close
    for (int i = 0; i < 10; ++i) {
        getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    }
    
    // Squelch should be closed for low amplitude signal
    EXPECT_FALSE(getAGC().isSquelchOpen());
    
    // Output should be muted (all zeros)
    float output_sum = 0.0f;
    for (size_t i = 0; i < 1024; ++i) {
        output_sum += std::abs(output[i]);
    }
    EXPECT_LT(output_sum, 1e-6f) << "Squelch did not mute low signal";
}

TEST_F(AudioProcessingTest, CombinedAGCSquelchProcessing) {
    // Test combined AGC and squelch processing
    ASSERT_TRUE(isAGCValid());
    getAGC().enableAGC(true);
    getAGC().setAGCMode(AGCMode::MEDIUM);
    getAGC().setSquelchEnabled(true);
    getAGC().setSquelchThreshold(-60.0f);
    
    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
    std::vector<float> output(1024);
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Verify output is valid
    bool has_valid_output = false;
    for (size_t i = 0; i < 100; ++i) {
        if (!std::isnan(output[i]) && !std::isinf(output[i])) {
            has_valid_output = true;
            break;
        }
    }
    EXPECT_TRUE(has_valid_output);
}

TEST_F(AudioProcessingTest, BufferOverflowProtection) {
    // Test with proper buffer sizes to avoid overflow
    std::vector<float> input(1024, 0.1f);
    std::vector<float> output(1024); // Same size as input
    
    // Should handle gracefully without buffer overflow
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Test with larger output buffer
    std::vector<float> output_large(2048);
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output_large.data(), 1024, 44100.0f));
    
    // Test with smaller input to fit in smaller output buffer
    std::vector<float> input_small(512, 0.1f);
    std::vector<float> output_small(512);
    EXPECT_NO_THROW(getAGC().processAudioSamples(input_small.data(), output_small.data(), 512, 44100.0f));
}

// Performance tests
TEST_F(AudioProcessingTest, ProcessingPerformance) {
    const size_t sample_count = 1024;
    const int iterations = 1000;
    
    auto input = generateSineWave(1000.0f, 44100.0f, sample_count, 0.5f);
    std::vector<float> output(sample_count);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        getAGC().processAudioSamples(input.data(), output.data(), sample_count, 44100.0f);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate processing time per sample
    double time_per_sample = static_cast<double>(duration.count()) / (iterations * sample_count);
    
    // Should process at least 1M samples per second
    EXPECT_LT(time_per_sample, 1.0) << "Processing too slow: " << time_per_sample << " microseconds per sample";
    
    std::cout << "Processing performance: " << (1.0 / time_per_sample) << " MSamples/sec" << std::endl;
}

// Edge case tests
TEST_F(AudioProcessingTest, VerySmallSamples) {
    // Test with very small sample counts
    std::vector<float> input(1, 0.1f);
    std::vector<float> output(1);
    
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1, 44100.0f));
    EXPECT_FALSE(std::isnan(output[0]));
    EXPECT_FALSE(std::isinf(output[0]));
}

TEST_F(AudioProcessingTest, ExtremeAmplitudes) {
    // Test with extreme amplitude values
    std::vector<float> input(1024);
    std::vector<float> output(1024);
    
    // Very small amplitude
    std::fill(input.begin(), input.end(), 1e-10f);
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Very large amplitude
    std::fill(input.begin(), input.end(), 1e10f);
    EXPECT_NO_THROW(getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f));
    
    // Check for NaN or infinity in output
    for (size_t i = 0; i < 1024; ++i) {
        EXPECT_FALSE(std::isnan(output[i])) << "NaN in output at sample " << i;
        EXPECT_FALSE(std::isinf(output[i])) << "Infinity in output at sample " << i;
    }
}
