#ifndef AUDIO_PROCESSING_TEST_FIXTURES_H
#define AUDIO_PROCESSING_TEST_FIXTURES_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>

// Include the audio processing modules
#include "../../client/mumble-plugin/lib/audio.h"
#include "../../client/mumble-plugin/lib/agc_squelch.h"

// Test fixtures and utilities
class Audio_Processing_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_sample_rate_8k = 8000;
        test_sample_rate_16k = 16000;
        test_sample_rate_44k = 44100;
        test_sample_rate_48k = 48000;
        test_frame_size_20ms = 160; // 20ms at 8kHz
        test_frame_size_20ms_48k = 960; // 20ms at 48kHz
        
        // Initialize random number generator with a fixed seed for reproducible tests
        rng.seed(12345);
        
        // Initialize test buffers
        test_buffer_8k.resize(test_frame_size_20ms);
        test_buffer_48k.resize(test_frame_size_20ms_48k);
        
        // Initialize test data
        generateTestData();
    }
    
    void TearDown() override {
        // Clean up test resources
    }
    
    // Test parameters
    int test_sample_rate_8k;
    int test_sample_rate_16k;
    int test_sample_rate_44k;
    int test_sample_rate_48k;
    int test_frame_size_20ms;
    int test_frame_size_20ms_48k;
    
    // Test buffers
    std::vector<float> test_buffer_8k;
    std::vector<float> test_buffer_48k;
    
    // Random number generator
    std::mt19937 rng;
    
    // Helper functions
    std::vector<float> generateSineWave(float frequency, float amplitude, int sample_rate, int frame_size) {
        std::vector<float> samples(frame_size);
        float phase = 0.0f;
        float phase_increment = 2.0f * M_PI * frequency / sample_rate;
        
        for (int i = 0; i < frame_size; i++) {
            samples[i] = amplitude * std::sin(phase);
            phase += phase_increment;
        }
        
        return samples;
    }
    
    std::vector<float> generateWhiteNoise(float amplitude, int frame_size) {
        std::vector<float> samples(frame_size);
        std::uniform_real_distribution<float> dist(-amplitude, amplitude);
        
        for (int i = 0; i < frame_size; i++) {
            samples[i] = dist(rng);
        }
        
        return samples;
    }
    
    std::vector<float> generatePinkNoise(float amplitude, int frame_size) {
        std::vector<float> samples(frame_size);
        std::uniform_real_distribution<float> dist(-amplitude, amplitude);
        
        for (int i = 0; i < frame_size; i++) {
            samples[i] = dist(rng);
        }
        
        return samples;
    }
    
    float calculateRMS(const std::vector<float>& samples) {
        float sum_squares = 0.0f;
        for (float sample : samples) {
            sum_squares += sample * sample;
        }
        return std::sqrt(sum_squares / samples.size());
    }
    
    float calculateSNR(const std::vector<float>& signal, const std::vector<float>& noise) {
        float signal_power = calculateRMS(signal);
        float noise_power = calculateRMS(noise);
        return 20.0f * std::log10(signal_power / noise_power);
    }
    
    float calculatePeak(const std::vector<float>& samples) {
        float peak = 0.0f;
        for (float sample : samples) {
            float abs_sample = std::abs(sample);
            if (abs_sample > peak) {
                peak = abs_sample;
            }
        }
        return peak;
    }
    
    std::vector<float> generateSquelchTail(float amplitude, int frame_size, float duration_ms) {
        std::vector<float> samples(frame_size);
        float decay_factor = std::exp(-duration_ms / 100.0f); // Exponential decay
        
        for (int i = 0; i < frame_size; i++) {
            float t = static_cast<float>(i) / frame_size;
            samples[i] = amplitude * std::exp(-t * decay_factor);
        }
        
        return samples;
    }
    
    std::vector<float> generateClick(float amplitude, int frame_size, int click_position) {
        std::vector<float> samples(frame_size, 0.0f);
        
        if (click_position >= 0 && click_position < frame_size) {
            samples[click_position] = amplitude;
        }
        
        return samples;
    }
    
    void generateTestData() {
        // Generate test sine waves
        test_buffer_8k = generateSineWave(1000.0f, 0.5f, test_sample_rate_8k, test_frame_size_20ms);
        test_buffer_48k = generateSineWave(1000.0f, 0.5f, test_sample_rate_48k, test_frame_size_20ms_48k);
    }
    
    // Performance measurement
    template<typename Func>
    double measureTime(Func func) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
};

// Test class for codec tests
class CodecTest : public Audio_Processing_Test {
protected:
    void SetUp() override {
        Audio_Processing_Test::SetUp();
    }
};

// Test class for audio effects tests
class AudioEffectsTest : public Audio_Processing_Test {
protected:
    void SetUp() override {
        Audio_Processing_Test::SetUp();
    }
};

// Test class for sample rate conversion tests
class SampleRateConversionTest : public Audio_Processing_Test {
protected:
    void SetUp() override {
        Audio_Processing_Test::SetUp();
    }
};

#endif // AUDIO_PROCESSING_TEST_FIXTURES_H
