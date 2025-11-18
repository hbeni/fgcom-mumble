/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <memory>
#include <random>
#include "audio.h"

class AudioPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test audio data
        sample_rate = 48000;  // 48kHz sample rate
        channel_count = 2;    // Stereo
        buffer_size = 1024;   // 1024 samples per buffer
        
        // Allocate test audio buffers
        test_pcm = std::vector<float>(buffer_size * channel_count);
        output_pcm = std::vector<float>(buffer_size * channel_count);
        
        // Fill with test audio data (sine wave)
        generateTestAudio();
        
        // Initialize random number generator for noise testing
        rng.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }
    
    void generateTestAudio() {
        const float frequency = 1000.0f;  // 1kHz test tone
        const float amplitude = 0.5f;
        
        for (size_t i = 0; i < test_pcm.size(); i++) {
            float time = static_cast<float>(i) / static_cast<float>(sample_rate);
            test_pcm[i] = amplitude * std::sin(2.0f * M_PI * frequency * time);
        }
    }
    
    void generateNoiseAudio() {
        std::uniform_real_distribution<float> noise_dist(-0.1f, 0.1f);
        
        for (size_t i = 0; i < test_pcm.size(); i++) {
            test_pcm[i] = noise_dist(rng);
        }
    }
    
    std::vector<float> test_pcm;
    std::vector<float> output_pcm;
    uint32_t sample_rate;
    uint16_t channel_count;
    uint32_t buffer_size;
    std::mt19937 rng;
};

// Test Audio Volume Processing Performance
TEST_F(AudioPerformanceTest, VolumeProcessing_Performance) {
    const int iterations = 1000;
    const float test_volume = 0.8f;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Apply volume processing
        fgcom_audio_applyVolume(test_volume, output_pcm.data(), buffer_size, channel_count);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 1000 iterations in reasonable time (< 50ms)
    EXPECT_LT(duration.count(), 50000);
    
    // Verify audio processing worked
    for (size_t i = 0; i < output_pcm.size(); i++) {
        EXPECT_LE(output_pcm[i], 1.0f);
        EXPECT_GE(output_pcm[i], -1.0f);
    }
}

// Test Audio Noise Addition Performance
TEST_F(AudioPerformanceTest, NoiseAddition_Performance) {
    const int iterations = 1000;
    const float noise_volume = 0.1f;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Add noise
        fgcom_audio_addNoise(noise_volume, output_pcm.data(), buffer_size, channel_count);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 1000 iterations in reasonable time (< 100ms)
    EXPECT_LT(duration.count(), 100000);
}

// Test Signal Quality Degradation Performance
TEST_F(AudioPerformanceTest, SignalQualityDegradation_Performance) {
    const int iterations = 1000;
    const float dropout_probability = 0.1f;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Apply signal quality degradation
        fgcom_audio_applySignalQualityDegradation(output_pcm.data(), buffer_size, channel_count, dropout_probability);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 1000 iterations in reasonable time (< 50ms)
    EXPECT_LT(duration.count(), 50000);
}

// Test Mono Conversion Performance
TEST_F(AudioPerformanceTest, MonoConversion_Performance) {
    const int iterations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Convert to mono
        fgcom_audio_makeMono(output_pcm.data(), buffer_size, channel_count);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 1000 iterations in reasonable time (< 30ms)
    EXPECT_LT(duration.count(), 30000);
}

// Test Audio Clipping Performance
TEST_F(AudioPerformanceTest, AudioClipping_Performance) {
    const int iterations = 1000;
    
    // Generate audio that will cause clipping
    for (size_t i = 0; i < test_pcm.size(); i++) {
        test_pcm[i] = 2.0f;  // Above clipping threshold
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Apply volume processing (should trigger clipping)
        fgcom_audio_applyVolume(1.5f, output_pcm.data(), buffer_size, channel_count);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 1000 iterations in reasonable time (< 50ms)
    EXPECT_LT(duration.count(), 50000);
    
    // Verify clipping occurred
    for (size_t i = 0; i < output_pcm.size(); i++) {
        EXPECT_LE(output_pcm[i], 1.0f);
        EXPECT_GE(output_pcm[i], -1.0f);
    }
}

// Test Large Buffer Performance
TEST_F(AudioPerformanceTest, LargeBuffer_Performance) {
    const int large_buffer_size = 8192;  // 8K samples
    const int iterations = 100;
    const float test_volume = 0.8f;
    
    std::vector<float> large_pcm(large_buffer_size * channel_count);
    std::vector<float> large_output(large_buffer_size * channel_count);
    
    // Fill large buffer with test data
    for (size_t i = 0; i < large_pcm.size(); i++) {
        large_pcm[i] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * i / sample_rate);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        // Copy test data to output buffer
        std::copy(large_pcm.begin(), large_pcm.end(), large_output.begin());
        
        // Apply volume processing
        fgcom_audio_applyVolume(test_volume, large_output.data(), large_buffer_size, channel_count);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 100 iterations of 8K samples in reasonable time (< 200ms)
    EXPECT_LT(duration.count(), 200000);
}

// Test Concurrent Audio Processing
TEST_F(AudioPerformanceTest, ConcurrentProcessing_Performance) {
    const int num_threads = 4;
    const int iterations_per_thread = 250;
    std::vector<std::thread> threads;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Create multiple threads processing audio concurrently
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, iterations_per_thread]() {
            std::vector<float> thread_pcm(buffer_size * channel_count);
            std::vector<float> thread_output(buffer_size * channel_count);
            
            for (int i = 0; i < iterations_per_thread; i++) {
                // Copy test data
                std::copy(test_pcm.begin(), test_pcm.end(), thread_pcm.begin());
                
                // Process audio
                fgcom_audio_applyVolume(0.8f, thread_pcm.data(), buffer_size, channel_count);
                fgcom_audio_addNoise(0.1f, thread_pcm.data(), buffer_size, channel_count);
                fgcom_audio_applySignalQualityDegradation(thread_pcm.data(), buffer_size, channel_count, 0.05f);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should complete concurrent processing in reasonable time (< 300ms)
    EXPECT_LT(duration.count(), 300000);
}

// Test Memory Usage
TEST_F(AudioPerformanceTest, MemoryUsage_Performance) {
    const int num_buffers = 100;
    std::vector<std::vector<float>> buffers;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Create many audio buffers
    for (int i = 0; i < num_buffers; i++) {
        std::vector<float> buffer(buffer_size * channel_count);
        
        // Fill with test data
        for (size_t j = 0; j < buffer.size(); j++) {
            buffer[j] = 0.5f * std::sin(2.0f * M_PI * 1000.0f * j / sample_rate);
        }
        
        // Process audio
        fgcom_audio_applyVolume(0.8f, buffer.data(), buffer_size, channel_count);
        fgcom_audio_addNoise(0.1f, buffer.data(), buffer_size, channel_count);
        
        buffers.push_back(std::move(buffer));
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should process 100 buffers in reasonable time (< 500ms)
    EXPECT_LT(duration.count(), 500000);
    
    // Verify all buffers were processed
    EXPECT_EQ(buffers.size(), num_buffers);
}

// Test Audio Quality Metrics
TEST_F(AudioPerformanceTest, AudioQuality_Metrics) {
    // Test audio quality with different signal levels
    const std::vector<float> signal_levels = {0.1f, 0.3f, 0.5f, 0.7f, 0.9f};
    
    for (float signal_level : signal_levels) {
        // Generate test audio at different levels
        for (size_t i = 0; i < test_pcm.size(); i++) {
            test_pcm[i] = signal_level * std::sin(2.0f * M_PI * 1000.0f * i / sample_rate);
        }
        
        // Copy to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Apply signal quality degradation
        float dropout_probability = (0.3f - signal_level) * 0.5f;
        if (dropout_probability > 0.0f) {
            fgcom_audio_applySignalQualityDegradation(output_pcm.data(), buffer_size, channel_count, dropout_probability);
        }
        
        // Verify audio quality
        float max_amplitude = 0.0f;
        for (size_t i = 0; i < output_pcm.size(); i++) {
            max_amplitude = std::max(max_amplitude, std::abs(output_pcm[i]));
        }
        
        // Higher signal levels should result in higher output amplitudes
        EXPECT_GE(max_amplitude, signal_level * 0.5f);
        EXPECT_LE(max_amplitude, signal_level * 1.5f);
    }
}

// Test Real-time Performance
TEST_F(AudioPerformanceTest, RealTime_Performance) {
    const int real_time_iterations = 100;
    const auto target_frame_time = std::chrono::microseconds(20833);  // ~48kHz frame time
    
    for (int i = 0; i < real_time_iterations; i++) {
        auto frame_start = std::chrono::high_resolution_clock::now();
        
        // Copy test data to output buffer
        std::copy(test_pcm.begin(), test_pcm.end(), output_pcm.begin());
        
        // Apply all audio processing
        fgcom_audio_applyVolume(0.8f, output_pcm.data(), buffer_size, channel_count);
        fgcom_audio_addNoise(0.1f, output_pcm.data(), buffer_size, channel_count);
        fgcom_audio_applySignalQualityDegradation(output_pcm.data(), buffer_size, channel_count, 0.05f);
        fgcom_audio_makeMono(output_pcm.data(), buffer_size, channel_count);
        
        auto frame_end = std::chrono::high_resolution_clock::now();
        auto frame_duration = std::chrono::duration_cast<std::chrono::microseconds>(frame_end - frame_start);
        
        // Each frame should complete within the target frame time
        EXPECT_LT(frame_duration.count(), target_frame_time.count());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
