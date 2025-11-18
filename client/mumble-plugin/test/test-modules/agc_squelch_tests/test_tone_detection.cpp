#include "test_agc_squelch_main.cpp"

// 1.6 Tone Detection Tests (Goertzel Algorithm)
TEST_F(AudioProcessingTest, SingleToneDetectionAccuracy) {
    // Test single tone detection with known frequencies
    std::vector<float> test_frequencies = {100.0f, 500.0f, 1000.0f, 2000.0f};
    
    for (float frequency : test_frequencies) {
        // Enable tone squelch
        agc->setToneSquelch(true, frequency);
        agc->setSquelchEnabled(true);
        
        // Generate tone at exact frequency
        auto input = generateSineWave(frequency, 44100.0f, 1024, 0.5f);
        std::vector<float> output(1024);
        
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        // Tone should be detected and squelch should open
        EXPECT_TRUE(agc->isSquelchOpen()) << "Tone not detected at frequency " << frequency;
    }
}

TEST_F(AudioProcessingTest, MultipleFrequenciesTested) {
    // Test tone detection with multiple frequencies
    std::vector<float> frequencies = {100.0f, 500.0f, 1000.0f, 2000.0f};
    
    for (float frequency : frequencies) {
        agc->setToneSquelch(true, frequency);
        
        // Generate tone at target frequency
        auto input = generateSineWave(frequency, 44100.0f, 1024, 0.3f);
        std::vector<float> output(1024);
        
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        // Should detect the tone
        EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone at " << frequency << " Hz";
        
        // Test with slightly off frequency (should still detect within tolerance)
        auto input_off = generateSineWave(frequency + 2.0f, 44100.0f, 1024, 0.3f);
        agc->processAudioSamples(input_off.data(), output.data(), 1024, 44100.0f);
        EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone with small frequency offset";
    }
}

TEST_F(AudioProcessingTest, NoiseRejection) {
    // Test that tone detector rejects noise
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    // Generate noise instead of tone
    auto noise = generateNoise(1024, 0.3f);
    std::vector<float> output(1024);
    
    agc->processAudioSamples(noise.data(), output.data(), 1024, 44100.0f);
    
    // Should not detect tone in noise
    EXPECT_FALSE(agc->isSquelchOpen()) << "False tone detection in noise";
}

TEST_F(AudioProcessingTest, FalsePositiveRate) {
    // Test false positive rate with various non-tone signals
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    std::vector<float> test_frequencies = {500.0f, 1500.0f, 3000.0f, 5000.0f};
    int false_positives = 0;
    int total_tests = test_frequencies.size();
    
    for (float frequency : test_frequencies) {
        auto input = generateSineWave(frequency, 44100.0f, 1024, 0.3f);
        std::vector<float> output(1024);
        
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        if (agc->isSquelchOpen()) {
            false_positives++;
        }
    }
    
    // False positive rate should be low
    float false_positive_rate = static_cast<float>(false_positives) / total_tests;
    EXPECT_LT(false_positive_rate, 0.1f) << "High false positive rate: " << false_positive_rate;
}

TEST_F(AudioProcessingTest, AmplitudeThresholdTesting) {
    // Test tone detection with different amplitudes
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    std::vector<float> amplitudes = {0.01f, 0.1f, 0.3f, 0.5f, 1.0f};
    
    for (float amplitude : amplitudes) {
        auto input = generateSineWave(1000.0f, 44100.0f, 1024, amplitude);
        std::vector<float> output(1024);
        
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        if (amplitude >= 0.1f) {
            // Strong signals should be detected
            EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone with amplitude " << amplitude;
        } else {
            // Weak signals might not be detected
            // This is acceptable behavior
        }
    }
}

TEST_F(AudioProcessingTest, PhaseAccuracy) {
    // Test tone detection with different phases
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    std::vector<float> phases = {0.0f, M_PI/4, M_PI/2, M_PI, 3*M_PI/2};
    
    for (float phase : phases) {
        // Generate sine wave with specific phase
        std::vector<float> input(1024);
        for (size_t i = 0; i < 1024; ++i) {
            input[i] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * i / 44100.0f + phase);
        }
        
        std::vector<float> output(1024);
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        // Should detect tone regardless of phase
        EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone with phase " << phase;
    }
}

// Additional tone detection tests
TEST_F(AudioProcessingTest, ToneDetectionWithNoise) {
    // Test tone detection in presence of noise
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    // Generate tone with added noise
    auto tone = generateSineWave(1000.0f, 44100.0f, 1024, 0.3f);
    auto noise = generateNoise(1024, 0.1f);
    
    std::vector<float> input(1024);
    for (size_t i = 0; i < 1024; ++i) {
        input[i] = tone[i] + noise[i];
    }
    
    std::vector<float> output(1024);
    agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    
    // Should still detect tone despite noise
    EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone in presence of noise";
}

TEST_F(AudioProcessingTest, ToneDetectionFrequencyTolerance) {
    // Test frequency tolerance of tone detection
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    std::vector<float> frequency_offsets = {-10.0f, -5.0f, -2.0f, 0.0f, 2.0f, 5.0f, 10.0f};
    
    for (float offset : frequency_offsets) {
        float test_frequency = 1000.0f + offset;
        auto input = generateSineWave(test_frequency, 44100.0f, 1024, 0.3f);
        std::vector<float> output(1024);
        
        agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
        
        if (std::abs(offset) <= 5.0f) {
            // Small offsets should still be detected
            EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect tone with offset " << offset;
        } else {
            // Large offsets might not be detected
            // This is acceptable behavior
        }
    }
}

TEST_F(AudioProcessingTest, MultipleToneDetection) {
    // Test detection of multiple tones (if supported)
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    // Generate signal with multiple tones
    auto tone1 = generateSineWave(1000.0f, 44100.0f, 1024, 0.2f);
    auto tone2 = generateSineWave(2000.0f, 44100.0f, 1024, 0.2f);
    
    std::vector<float> input(1024);
    for (size_t i = 0; i < 1024; ++i) {
        input[i] = tone1[i] + tone2[i];
    }
    
    std::vector<float> output(1024);
    agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    
    // Should detect the target tone (1000 Hz)
    EXPECT_TRUE(agc->isSquelchOpen()) << "Failed to detect target tone in multi-tone signal";
}

TEST_F(AudioProcessingTest, ToneDetectionLatency) {
    // Test tone detection latency
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.3f);
    std::vector<float> output(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Tone detection should be fast
    EXPECT_LT(duration.count(), 1000) << "Tone detection too slow: " << duration.count() << " microseconds";
    
    // Should detect tone
    EXPECT_TRUE(agc->isSquelchOpen()) << "Tone detection failed";
}

TEST_F(AudioProcessingTest, ToneDetectionRobustness) {
    // Test robustness of tone detection with various signal conditions
    agc->setToneSquelch(true, 1000.0f);
    agc->setSquelchEnabled(true);
    
    std::vector<float> test_amplitudes = {0.05f, 0.1f, 0.2f, 0.5f, 1.0f};
    std::vector<float> test_frequencies = {995.0f, 998.0f, 1000.0f, 1002.0f, 1005.0f};
    
    int successful_detections = 0;
    int total_tests = test_amplitudes.size() * test_frequencies.size();
    
    for (float amplitude : test_amplitudes) {
        for (float frequency : test_frequencies) {
            auto input = generateSineWave(frequency, 44100.0f, 1024, amplitude);
            std::vector<float> output(1024);
            
            agc->processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
            
            if (agc->isSquelchOpen()) {
                successful_detections++;
            }
        }
    }
    
    // Should have high detection rate for valid signals
    float detection_rate = static_cast<float>(successful_detections) / total_tests;
    EXPECT_GT(detection_rate, 0.8f) << "Low tone detection rate: " << detection_rate;
}

