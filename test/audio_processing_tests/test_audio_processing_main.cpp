#include "test_fixtures.h"

// Basic audio processing tests
TEST_F(Audio_Processing_Test, BasicAudioProcessing) {
    // Test basic audio processing functionality
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms_48k);
    
    // Test AGC processing
    FGCom_AGC_Squelch& agc = FGCom_AGC_Squelch::getInstance();
    agc.setAGCMode(AGCMode::FAST);
    agc.setSquelchEnabled(false);
    
    // Process audio samples
    std::vector<float> output_samples = input_samples;
    agc.processAudioSamples(input_samples.data(), output_samples.data(), output_samples.size(), test_sample_rate_48k);
    
    // Verify output is not empty
    EXPECT_FALSE(output_samples.empty());
    
    // Verify output has reasonable values
    for (float sample : output_samples) {
        EXPECT_TRUE(std::isfinite(sample));
        EXPECT_GE(sample, -1.0f);
        EXPECT_LE(sample, 1.0f);
    }
}

TEST_F(Audio_Processing_Test, AudioProcessingPerformance) {
    // Test audio processing performance
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms_48k);
    
    FGCom_AGC_Squelch& agc = FGCom_AGC_Squelch::getInstance();
    agc.setAGCMode(AGCMode::FAST);
    agc.setSquelchEnabled(false);
    
    // Measure processing time
    double processing_time = measureTime([&]() {
        for (int i = 0; i < 100; i++) {
            std::vector<float> output_samples = input_samples;
            agc.processAudioSamples(input_samples.data(), output_samples.data(), output_samples.size(), test_sample_rate_48k);
        }
    });
    
    // Verify processing time is reasonable (less than 10ms for 100 iterations)
    EXPECT_LT(processing_time, 10.0);
}

TEST_F(Audio_Processing_Test, AudioProcessingQuality) {
    // Test audio processing quality
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms_48k);
    
    FGCom_AGC_Squelch& agc = FGCom_AGC_Squelch::getInstance();
    agc.setAGCMode(AGCMode::FAST);
    agc.setSquelchEnabled(false);
    
    // Process audio samples
    std::vector<float> output_samples = input_samples;
    agc.processAudioSamples(input_samples.data(), output_samples.data(), output_samples.size(), test_sample_rate_48k);
    
    // Calculate input and output RMS
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    // Verify output RMS is reasonable (not zero, not too high)
    EXPECT_GT(output_rms, 0.0f);
    EXPECT_LT(output_rms, 1.0f);
    
    // Verify processing doesn't completely destroy the signal
    EXPECT_GT(output_rms, input_rms * 0.1f);
}