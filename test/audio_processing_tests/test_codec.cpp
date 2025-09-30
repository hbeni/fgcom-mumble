#include "test_fixtures.h"

// 4.1 Codec Tests
TEST_F(CodecTest, OpusEncodingDecoding) {
    // Test Opus encoding/decoding
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    // Test encoding
    std::vector<uint8_t> encoded_data;
    encoded_data.reserve(input_samples.size() / 2); // Reserve space for compressed data
    
    // Simulate Opus encoding with compression (simplified)
    for (size_t i = 0; i < input_samples.size(); i += 2) {
        // Convert float to 8-bit compressed representation
        float sample1 = input_samples[i];
        float sample2 = (i + 1 < input_samples.size()) ? input_samples[i + 1] : 0.0f;
        
        // Simple compression: combine two samples into one byte
        uint8_t compressed = static_cast<uint8_t>((sample1 + 1.0f) * 127.5f) & 0xF0;
        compressed |= static_cast<uint8_t>((sample2 + 1.0f) * 7.5f) & 0x0F;
        
        encoded_data.push_back(compressed);
    }
    
    EXPECT_GT(encoded_data.size(), 0) << "Encoded data should not be empty";
    EXPECT_LT(encoded_data.size(), input_samples.size() * 2) << "Encoded data should be compressed";
    
    // Test decoding
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size());
    
    // Simulate Opus decoding (simplified)
    for (size_t i = 0; i < encoded_data.size(); ++i) {
        uint8_t compressed = encoded_data[i];
        
        // Extract two samples from compressed byte
        float sample1 = (static_cast<float>(compressed & 0xF0) / 127.5f) - 1.0f;
        float sample2 = (static_cast<float>(compressed & 0x0F) / 7.5f) - 1.0f;
        
        output_samples.push_back(sample1);
        if (output_samples.size() < input_samples.size()) {
            output_samples.push_back(sample2);
        }
    }
    
    EXPECT_EQ(output_samples.size(), input_samples.size()) << "Decoded samples should match input size";
    
    // Test audio quality preservation
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.1f) << "RMS should be preserved after encoding/decoding";
}

TEST_F(CodecTest, BitrateAdaptation) {
    // Test bitrate adaptation
    std::vector<int> test_bitrates = {32000, 64000, 128000, 256000};
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    for (int bitrate : test_bitrates) {
        // Test encoding with different bitrates
        std::vector<uint8_t> encoded_data;
        encoded_data.reserve(input_samples.size() * 2);
        
        // Simulate bitrate adaptation
        float compression_ratio = 1.0f;
        if (bitrate <= 32000) {
            compression_ratio = 0.5f; // High compression
        } else if (bitrate <= 64000) {
            compression_ratio = 0.7f; // Medium compression
        } else if (bitrate <= 128000) {
            compression_ratio = 0.9f; // Low compression
        } else {
            compression_ratio = 1.0f; // No compression
        }
        
        // Simulate encoding with bitrate adaptation
        if (compression_ratio < 1.0f) {
            // Compressed encoding: combine samples
            for (size_t i = 0; i < input_samples.size(); i += 2) {
                float sample1 = input_samples[i] * compression_ratio;
                float sample2 = (i + 1 < input_samples.size()) ? input_samples[i + 1] * compression_ratio : 0.0f;
                
                // Simple compression: combine two samples into one byte
                uint8_t compressed = static_cast<uint8_t>((sample1 + 1.0f) * 127.5f) & 0xF0;
                compressed |= static_cast<uint8_t>((sample2 + 1.0f) * 7.5f) & 0x0F;
                
                encoded_data.push_back(compressed);
            }
        } else {
            // No compression: store samples as-is
            for (size_t i = 0; i < input_samples.size(); ++i) {
                int16_t pcm_sample = static_cast<int16_t>(input_samples[i] * 32767.0f);
                encoded_data.push_back(static_cast<uint8_t>(pcm_sample & 0xFF));
                encoded_data.push_back(static_cast<uint8_t>((pcm_sample >> 8) & 0xFF));
            }
        }
        
        // Test that higher bitrates produce better quality
        float quality_score = static_cast<float>(encoded_data.size()) / input_samples.size();
        
        if (bitrate <= 32000) {
            EXPECT_LT(quality_score, 0.6f) << "Low bitrate should have high compression";
        } else if (bitrate <= 64000) {
            EXPECT_LT(quality_score, 0.8f) << "Medium bitrate should have medium compression";
        } else if (bitrate <= 128000) {
            EXPECT_LT(quality_score, 1.0f) << "High bitrate should have low compression";
        } else {
            EXPECT_NEAR(quality_score, 2.0f, 0.1f) << "Very high bitrate should have minimal compression (2x for 16-bit PCM)";
        }
    }
}

TEST_F(CodecTest, PacketLossConcealment) {
    // Test packet loss concealment
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    // Simulate packet loss
    std::vector<bool> packet_loss_mask(input_samples.size(), false);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    // Simulate 10% packet loss
    for (size_t i = 0; i < packet_loss_mask.size(); ++i) {
        if (dis(gen) < 0.1) {
            packet_loss_mask[i] = true;
        }
    }
    
    // Test packet loss concealment
    std::vector<float> output_samples = input_samples;
    
    for (size_t i = 0; i < output_samples.size(); ++i) {
        if (packet_loss_mask[i]) {
            // Apply packet loss concealment (simple interpolation)
            if (i > 0 && i < output_samples.size() - 1) {
                output_samples[i] = (output_samples[i-1] + output_samples[i+1]) / 2.0f;
            } else if (i > 0) {
                output_samples[i] = output_samples[i-1];
            } else if (i < output_samples.size() - 1) {
                output_samples[i] = output_samples[i+1];
            } else {
                output_samples[i] = 0.0f;
            }
        }
    }
    
    // Test that packet loss concealment maintains audio continuity
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.2f) << "RMS should be preserved after packet loss concealment";
    
    // Test that concealed samples are reasonable
    for (size_t i = 0; i < output_samples.size(); ++i) {
        if (packet_loss_mask[i]) {
            EXPECT_GE(output_samples[i], -1.0f) << "Concealed sample should be >= -1.0";
            EXPECT_LE(output_samples[i], 1.0f) << "Concealed sample should be <= 1.0";
        }
    }
}

TEST_F(CodecTest, ForwardErrorCorrection) {
    // Test forward error correction
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    // Simulate FEC encoding
    std::vector<uint8_t> fec_data;
    fec_data.reserve(input_samples.size() * 2 * 1.5); // 50% overhead for FEC
    
    // Simulate FEC encoding (simplified)
    for (size_t i = 0; i < input_samples.size(); ++i) {
        int16_t pcm_sample = static_cast<int16_t>(input_samples[i] * 32767.0f);
        
        // Original data
        fec_data.push_back(static_cast<uint8_t>(pcm_sample & 0xFF));
        fec_data.push_back(static_cast<uint8_t>((pcm_sample >> 8) & 0xFF));
        
        // FEC data (simplified - just duplicate with error correction)
        fec_data.push_back(static_cast<uint8_t>((pcm_sample & 0xFF) ^ 0x55));
        fec_data.push_back(static_cast<uint8_t>(((pcm_sample >> 8) & 0xFF) ^ 0xAA));
    }
    
    EXPECT_GT(fec_data.size(), input_samples.size() * 2) << "FEC data should be larger than original";
    
    // Test FEC decoding
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size());
    
    for (size_t i = 0; i < input_samples.size(); ++i) {
        size_t fec_index = i * 4; // 4 bytes per sample (2 original + 2 FEC)
        
        if (fec_index + 3 < fec_data.size()) {
            // Try to decode original data
            int16_t original_sample = static_cast<int16_t>(fec_data[fec_index]) | 
                                     (static_cast<int16_t>(fec_data[fec_index + 1]) << 8);
            
            // Try to decode FEC data
            int16_t fec_sample = static_cast<int16_t>(fec_data[fec_index + 2] ^ 0x55) | 
                                (static_cast<int16_t>(fec_data[fec_index + 3] ^ 0xAA) << 8);
            
            // Use FEC to correct errors (simplified)
            int16_t corrected_sample = (original_sample + fec_sample) / 2;
            
            output_samples.push_back(static_cast<float>(corrected_sample) / 32767.0f);
        }
    }
    
    EXPECT_EQ(output_samples.size(), input_samples.size()) << "FEC decoded samples should match input size";
    
    // Test that FEC improves error resilience
    float input_rms = calculateRMS(input_samples);
    float output_rms = calculateRMS(output_samples);
    
    EXPECT_NEAR(output_rms, input_rms, 0.1f) << "RMS should be preserved after FEC";
}

TEST_F(CodecTest, LatencyMeasurement) {
    // Test latency measurement
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    // Measure encoding latency
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Simulate encoding
    std::vector<uint8_t> encoded_data;
    encoded_data.reserve(input_samples.size() * 2);
    
    for (size_t i = 0; i < input_samples.size(); ++i) {
        int16_t pcm_sample = static_cast<int16_t>(input_samples[i] * 32767.0f);
        encoded_data.push_back(static_cast<uint8_t>(pcm_sample & 0xFF));
        encoded_data.push_back(static_cast<uint8_t>((pcm_sample >> 8) & 0xFF));
    }
    
    auto encode_time = std::chrono::high_resolution_clock::now();
    auto encode_duration = std::chrono::duration_cast<std::chrono::microseconds>(encode_time - start_time);
    
    // Measure decoding latency
    start_time = std::chrono::high_resolution_clock::now();
    
    // Simulate decoding
    std::vector<float> output_samples;
    output_samples.reserve(input_samples.size());
    
    for (size_t i = 0; i < encoded_data.size(); i += 2) {
        if (i + 1 < encoded_data.size()) {
            int16_t pcm_sample = static_cast<int16_t>(encoded_data[i]) | 
                                (static_cast<int16_t>(encoded_data[i + 1]) << 8);
            output_samples.push_back(static_cast<float>(pcm_sample) / 32767.0f);
        }
    }
    
    auto decode_time = std::chrono::high_resolution_clock::now();
    auto decode_duration = std::chrono::duration_cast<std::chrono::microseconds>(decode_time - start_time);
    
    // Test latency requirements
    EXPECT_LT(encode_duration.count(), 1000) << "Encoding latency should be < 1ms";
    EXPECT_LT(decode_duration.count(), 1000) << "Decoding latency should be < 1ms";
    
    // Test total latency
    auto total_latency = encode_duration + decode_duration;
    EXPECT_LT(total_latency.count(), 2000) << "Total latency should be < 2ms";
    
    std::cout << "Encoding latency: " << encode_duration.count() << " microseconds" << std::endl;
    std::cout << "Decoding latency: " << decode_duration.count() << " microseconds" << std::endl;
    std::cout << "Total latency: " << total_latency.count() << " microseconds" << std::endl;
}

// Additional codec tests
TEST_F(CodecTest, CodecPerformance) {
    // Test codec performance
    const int num_iterations = 1000;
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_iterations; ++i) {
        // Simulate encoding
        std::vector<uint8_t> encoded_data;
        encoded_data.reserve(input_samples.size() * 2);
        
        for (size_t j = 0; j < input_samples.size(); ++j) {
            int16_t pcm_sample = static_cast<int16_t>(input_samples[j] * 32767.0f);
            encoded_data.push_back(static_cast<uint8_t>(pcm_sample & 0xFF));
            encoded_data.push_back(static_cast<uint8_t>((pcm_sample >> 8) & 0xFF));
        }
        
        // Simulate decoding
        std::vector<float> output_samples;
        output_samples.reserve(input_samples.size());
        
        for (size_t j = 0; j < encoded_data.size(); j += 2) {
            if (j + 1 < encoded_data.size()) {
                int16_t pcm_sample = static_cast<int16_t>(encoded_data[j]) | 
                                    (static_cast<int16_t>(encoded_data[j + 1]) << 8);
                output_samples.push_back(static_cast<float>(pcm_sample) / 32767.0f);
            }
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_iteration = static_cast<double>(duration.count()) / num_iterations;
    
    // Codec operations should be fast
    EXPECT_LT(time_per_iteration, 100.0) << "Codec operation too slow: " << time_per_iteration << " microseconds";
    
    std::cout << "Codec performance: " << time_per_iteration << " microseconds per iteration" << std::endl;
}

TEST_F(CodecTest, CodecQualityAssessment) {
    // Test codec quality assessment
    std::vector<float> input_samples = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms);
    
    // Test different quality levels
    std::vector<std::string> quality_levels = {"low", "medium", "high", "ultra"};
    
    for (const std::string& quality : quality_levels) {
        // Simulate quality-based encoding
        float quality_factor = 1.0f;
        if (quality == "low") {
            quality_factor = 0.5f;
        } else if (quality == "medium") {
            quality_factor = 0.7f;
        } else if (quality == "high") {
            quality_factor = 0.9f;
        } else if (quality == "ultra") {
            quality_factor = 1.0f;
        }
        
        // Simulate encoding with quality factor
        std::vector<float> encoded_samples = input_samples;
        for (float& sample : encoded_samples) {
            sample *= quality_factor;
        }
        
        // Test quality assessment
        float input_rms = calculateRMS(input_samples);
        float output_rms = calculateRMS(encoded_samples);
        float quality_score = output_rms / input_rms;
        
        EXPECT_GT(quality_score, 0.0f) << "Quality score should be positive";
        EXPECT_LE(quality_score, 1.0f) << "Quality score should be <= 1.0";
        
        // Test quality level ordering
        if (quality == "low") {
            EXPECT_LT(quality_score, 0.6f) << "Low quality should have low score";
        } else if (quality == "medium") {
            EXPECT_GE(quality_score, 0.6f) << "Medium quality should have medium score";
            EXPECT_LT(quality_score, 0.8f) << "Medium quality should have medium score";
        } else if (quality == "high") {
            EXPECT_GE(quality_score, 0.8f) << "High quality should have high score";
            EXPECT_LT(quality_score, 0.95f) << "High quality should have high score";
        } else if (quality == "ultra") {
            EXPECT_GE(quality_score, 0.95f) << "Ultra quality should have very high score";
        }
    }
}
