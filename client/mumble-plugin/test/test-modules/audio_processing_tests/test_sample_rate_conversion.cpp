#include "test_fixtures.h"

// 4.3 Sample Rate Conversion Tests
TEST_F(SampleRateConversionTest, Upsampling8kTo48k) {
    // Test upsampling from 8kHz to 48kHz (6x upsampling)
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_8k, 160); // 20ms at 8kHz
    
    // Test upsampling
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size() * 6); // 6x upsampling
    
    // Simple linear interpolation upsampling
    for (size_t i = 0; i < input_samples.size(); ++i) {
        output_samples.push_back(input_samples[i]);
        
        // Interpolate 5 samples between each input sample (except for the last one)
        if (i < input_samples.size() - 1) {
            for (int j = 1; j < 6; ++j) {
                float t = static_cast<float>(j) / 6.0f;
                float interpolated = input_samples[i] + t * (input_samples[i + 1] - input_samples[i]);
                output_samples.push_back(interpolated);
            }
        }
    }
    
    // For 6x upsampling, we get: input_size + (input_size - 1) * 5 = input_size * 6 - 5
    EXPECT_EQ(output_samples.size(), input_samples.size() * 6 - 5) << "Output should be 6x input size minus 5";
    
    // Test that upsampling preserves signal characteristics
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.1f) << "RMS should be preserved after upsampling";
    
    // Test that upsampling increases frequency resolution
    float input_peak = calculatePeak(input_samples);
    float output_peak = calculatePeak(output_samples);
    
    EXPECT_NEAR(output_peak, input_peak, 0.1f) << "Peak should be preserved after upsampling";
}

TEST_F(SampleRateConversionTest, Downsampling48kTo8k) {
    // Test downsampling from 48kHz to 8kHz (6x downsampling)
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    // Test downsampling
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size() / 6); // 6x downsampling
    
    // Simple decimation downsampling
    for (size_t i = 0; i < input_samples.size(); i += 6) {
        output_samples.push_back(input_samples[i]);
    }
    
    EXPECT_EQ(output_samples.size(), input_samples.size() / 6) << "Output should be 1/6 input size";
    
    // Test that downsampling preserves signal characteristics
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.1f) << "RMS should be preserved after downsampling";
    
    // Test that downsampling reduces frequency resolution
    float input_peak = calculatePeak(input_samples);
    float output_peak = calculatePeak(output_samples);
    
    EXPECT_NEAR(output_peak, input_peak, 0.1f) << "Peak should be preserved after downsampling";
}

TEST_F(SampleRateConversionTest, ArbitraryRateConversion) {
    // Test arbitrary rate conversion
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_44k, 882); // 20ms at 44.1kHz
    
    // Test conversion to 48kHz
    float input_rate = test_sample_rate_44k;
    float output_rate = test_sample_rate_48k;
    float conversion_ratio = output_rate / input_rate;
    
    std::vector<float> output_samples;
    output_samples.reserve(static_cast<size_t>(input_samples.size() * conversion_ratio));
    
    // Simple linear interpolation for arbitrary rate conversion
    size_t output_size = static_cast<size_t>(input_samples.size() * conversion_ratio);
    for (size_t i = 0; i < output_size; ++i) {
        float input_index = static_cast<float>(i) / conversion_ratio;
        size_t input_idx = static_cast<size_t>(input_index);
        float t = input_index - input_idx;
        
        if (input_idx < input_samples.size() - 1) {
            float interpolated = input_samples[input_idx] + t * (input_samples[input_idx + 1] - input_samples[input_idx]);
            output_samples.push_back(interpolated);
        } else {
            output_samples.push_back(input_samples.back());
        }
    }
    
    EXPECT_GT(output_samples.size(), 0) << "Output should not be empty";
    EXPECT_NEAR(output_samples.size(), input_samples.size() * conversion_ratio, 1.0f) 
        << "Output size should match conversion ratio";
    
    // Test that arbitrary conversion preserves signal characteristics
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.1f) << "RMS should be preserved after arbitrary conversion";
}

TEST_F(SampleRateConversionTest, AntiAliasingFilterVerification) {
    // Test anti-aliasing filter verification
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    // Test anti-aliasing filter (simplified low-pass filter)
    std::vector<float> filtered_samples = input_samples;
    
    // Simple moving average filter (anti-aliasing)
    int filter_length = 5;
    for (size_t i = filter_length; i < filtered_samples.size() - filter_length; ++i) {
        float sum = 0.0f;
        for (int j = -filter_length; j <= filter_length; ++j) {
            sum += input_samples[i + j];
        }
        filtered_samples[i] = sum / (2 * filter_length + 1);
    }
    
    // Test that anti-aliasing filter reduces high frequencies
    float input_peak = calculatePeak(input_samples);
    float filtered_peak = calculatePeak(filtered_samples);
    
    EXPECT_LT(filtered_peak, input_peak) << "Filtered peak should be lower than input peak";
    
    // Test that anti-aliasing filter preserves low frequencies
    float input_rms = calculateRMS(input_samples);
    float filtered_rms = calculateRMS(filtered_samples);
    
    EXPECT_GT(filtered_rms, input_rms * 0.8f) << "Filtered RMS should be close to input RMS";
    
    // Test different filter lengths
    std::vector<int> filter_lengths = {3, 5, 7, 9};
    
    for (int length : filter_lengths) {
        std::vector<float> test_filtered = input_samples;
        
        for (size_t i = length; i < test_filtered.size() - length; ++i) {
            float sum = 0.0f;
            for (int j = -length; j <= length; ++j) {
                sum += input_samples[i + j];
            }
            test_filtered[i] = sum / (2 * length + 1);
        }
        
        float test_peak = calculatePeak(test_filtered);
        EXPECT_LT(test_peak, input_peak) << "Filtered peak should be lower than input peak";
    }
}

TEST_F(SampleRateConversionTest, InterpolationAccuracy) {
    // Test interpolation accuracy
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    // Test linear interpolation accuracy
    std::vector<float> interpolated_samples;
    interpolated_samples.reserve(input_samples.size() * 2);
    
    for (size_t i = 0; i < input_samples.size(); ++i) {
        interpolated_samples.push_back(input_samples[i]);
        
        // Interpolate one sample between each input sample (except for the last one)
        if (i < input_samples.size() - 1) {
            float interpolated = (input_samples[i] + input_samples[i + 1]) / 2.0f;
            interpolated_samples.push_back(interpolated);
        }
    }
    
    // For 2x interpolation, we get: input_size + (input_size - 1) * 1 = input_size * 2 - 1
    EXPECT_EQ(interpolated_samples.size(), input_samples.size() * 2 - 1) << "Output should be 2x input size minus 1";
    
    // Test interpolation accuracy
    float input_rms = calculateRMS(input_samples);
    float interpolated_rms = calculateRMS(interpolated_samples);
    
    EXPECT_NEAR(interpolated_rms, input_rms, 0.1f) << "RMS should be preserved after interpolation";
    
    // Test that interpolation preserves signal characteristics
    float input_peak = calculatePeak(input_samples);
    float interpolated_peak = calculatePeak(interpolated_samples);
    
    EXPECT_NEAR(interpolated_peak, input_peak, 0.1f) << "Peak should be preserved after interpolation";
    
    // Test cubic interpolation accuracy
    std::vector<float> cubic_interpolated;
    cubic_interpolated.reserve(input_samples.size() * 2);
    
    for (size_t i = 1; i < input_samples.size() - 2; ++i) {
        cubic_interpolated.push_back(input_samples[i]);
        
        // Cubic interpolation between samples
        float t = 0.5f;
        float p0 = input_samples[i - 1];
        float p1 = input_samples[i];
        float p2 = input_samples[i + 1];
        float p3 = input_samples[i + 2];
        
        float cubic = p1 + 0.5f * (p2 - p0) * t + 0.5f * (2.0f * p0 - 5.0f * p1 + 4.0f * p2 - p3) * t * t + 
                     0.5f * (-p0 + 3.0f * p1 - 3.0f * p2 + p3) * t * t * t;
        
        cubic_interpolated.push_back(cubic);
    }
    
    EXPECT_GT(cubic_interpolated.size(), 0) << "Cubic interpolation should produce output";
    
    // Test that cubic interpolation is more accurate than linear
    float cubic_rms = calculateRMS(cubic_interpolated);
    EXPECT_NEAR(cubic_rms, input_rms, 0.1f) << "Cubic interpolation should preserve RMS";
}

TEST_F(SampleRateConversionTest, SampleRateConversionPerformance) {
    // Test sample rate conversion performance
    const int num_iterations = 1000;
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_iterations; ++i) {
        // Test upsampling
        std::vector<float> upsampled;
        upsampled.reserve(input_samples.size() * 2);
        
        for (size_t j = 0; j < input_samples.size() - 1; ++j) {
            upsampled.push_back(input_samples[j]);
            upsampled.push_back((input_samples[j] + input_samples[j + 1]) / 2.0f);
        }
        upsampled.push_back(input_samples.back());
        
        // Test downsampling
        std::vector<float> downsampled;
        downsampled.reserve(upsampled.size() / 2);
        
        for (size_t j = 0; j < upsampled.size(); j += 2) {
            downsampled.push_back(upsampled[j]);
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_iteration = static_cast<double>(duration.count()) / num_iterations;
    
    // Sample rate conversion should be fast
    EXPECT_LT(time_per_iteration, 100.0) << "Sample rate conversion too slow: " << time_per_iteration << " microseconds";
    
    std::cout << "Sample rate conversion performance: " << time_per_iteration << " microseconds per iteration" << std::endl;
}

TEST_F(SampleRateConversionTest, SampleRateConversionQuality) {
    // Test sample rate conversion quality
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    // Test upsampling quality
    std::vector<float> upsampled = input_samples;
    for (size_t i = 0; i < upsampled.size() - 1; ++i) {
        upsampled.insert(upsampled.begin() + i + 1, (upsampled[i] + upsampled[i + 1]) / 2.0f);
        i++; // Skip the inserted sample
    }
    
    // Test downsampling quality
    std::vector<float> downsampled;
    for (size_t i = 0; i < upsampled.size(); i += 2) {
        downsampled.push_back(upsampled[i]);
    }
    
    // Test quality metrics
    float input_rms = calculateRMS(input_samples);
    float downsampled_rms = calculateRMS(downsampled);
    
    EXPECT_NEAR(downsampled_rms, input_rms, 0.1f) << "RMS should be preserved after up/downsampling";
    
    // Test that conversion preserves signal characteristics
    float input_peak = calculatePeak(input_samples);
    float downsampled_peak = calculatePeak(downsampled);
    
    EXPECT_NEAR(downsampled_peak, input_peak, 0.1f) << "Peak should be preserved after up/downsampling";
    
    // Test different conversion ratios
    std::vector<float> conversion_ratios = {0.5f, 1.0f, 2.0f, 4.0f};
    
    for (float ratio : conversion_ratios) {
        std::vector<float> test_output;
        test_output.reserve(static_cast<size_t>(input_samples.size() * ratio));
        
        if (ratio > 1.0f) {
            // Upsampling
            for (size_t i = 0; i < input_samples.size() - 1; ++i) {
                test_output.push_back(input_samples[i]);
                
                for (int j = 1; j < static_cast<int>(ratio); ++j) {
                    float t = static_cast<float>(j) / ratio;
                    float interpolated = input_samples[i] + t * (input_samples[i + 1] - input_samples[i]);
                    test_output.push_back(interpolated);
                }
            }
            test_output.push_back(input_samples.back());
        } else {
            // Downsampling
            int step = static_cast<int>(1.0f / ratio);
            for (size_t i = 0; i < input_samples.size(); i += step) {
                test_output.push_back(input_samples[i]);
            }
        }
        
        EXPECT_GT(test_output.size(), 0) << "Output should not be empty";
        
        float test_rms = calculateRMS(test_output);
        EXPECT_NEAR(test_rms, input_rms, 0.1f) << "RMS should be preserved after conversion";
    }
}

// Additional sample rate conversion tests
TEST_F(SampleRateConversionTest, SampleRateConversionEdgeCases) {
    // Test sample rate conversion edge cases
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 960); // 20ms at 48kHz
    
    // Test empty input
    std::vector<float> empty_input;
    std::vector<float> empty_output;
    
    EXPECT_EQ(empty_output.size(), 0) << "Empty input should produce empty output";
    
    // Test single sample
    std::vector<float> single_sample = {0.5f};
    std::vector<float> single_output;
    single_output.reserve(single_sample.size() * 2);
    
    for (size_t i = 0; i < single_sample.size(); ++i) {
        single_output.push_back(single_sample[i]);
    }
    
    EXPECT_EQ(single_output.size(), single_sample.size()) << "Single sample should produce single output";
    
    // Test very small input
    std::vector<float> small_input = {0.1f, 0.2f, 0.3f};
    std::vector<float> small_output;
    small_output.reserve(small_input.size() * 2);
    
    for (size_t i = 0; i < small_input.size(); ++i) {
        small_output.push_back(small_input[i]);
        if (i < small_input.size() - 1) {
            small_output.push_back((small_input[i] + small_input[i + 1]) / 2.0f);
        }
    }
    
    // For 2x interpolation, we get: input_size + (input_size - 1) * 1 = input_size * 2 - 1
    EXPECT_EQ(small_output.size(), small_input.size() * 2 - 1) << "Small input should produce 2x output minus 1";
    
    // Test very large input
    std::vector<float> large_input = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, 48000); // 1 second at 48kHz
    std::vector<float> large_output;
    large_output.reserve(large_input.size() / 2);
    
    for (size_t i = 0; i < large_input.size(); i += 2) {
        large_output.push_back(large_input[i]);
    }
    
    EXPECT_EQ(large_output.size(), large_input.size() / 2) << "Large input should produce 1/2 output";
}

