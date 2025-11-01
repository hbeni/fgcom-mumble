/* 
 * Test IIR1 Radio Filtering Implementation
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 */

#include <gtest/gtest.h>
#include <cmath>
#include <vector>
#include <algorithm>
#include "../../client/mumble-plugin/lib/audio_professional.h"

using namespace FGComAudio;

class IIR1RadioFilteringTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        sampleRate = 44100.0f;
        testFrequency = 1000.0f; // 1kHz test tone
        testDuration = 0.1f; // 100ms
        sampleCount = static_cast<uint32_t>(sampleRate * testDuration);
        
        // Generate test signal
        testSignal.resize(sampleCount);
        for (uint32_t i = 0; i < sampleCount; ++i) {
            float t = static_cast<float>(i) / sampleRate;
            testSignal[i] = 0.5f * std::sin(2.0f * M_PI * testFrequency * t);
        }
    }
    
    float sampleRate;
    float testFrequency;
    float testDuration;
    uint32_t sampleCount;
    std::vector<float> testSignal;
};

TEST_F(IIR1RadioFilteringTest, LowPassFiltering) {
    ProfessionalAudioEngine engine;
    engine.setRadioLowPassFilter(2000.0f, sampleRate);
    
    std::vector<float> filteredSignal = testSignal;
    
    // Apply filtering through the engine
    engine.processAudio(filteredSignal.data(), sampleCount, 1, sampleRate);
    
    // Check that high frequencies are attenuated
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float filteredAmplitude = *std::max_element(filteredSignal.begin(), filteredSignal.end());
    
    // Low-pass filter should reduce amplitude
    EXPECT_LT(filteredAmplitude, originalAmplitude) << "Low-pass filter should reduce amplitude";
    EXPECT_GT(filteredAmplitude, 0.0f) << "Filtered signal should not be zero";
}

TEST_F(IIR1RadioFilteringTest, HighPassFiltering) {
    IIR1Filter filter;
    filter.setHighPass(500.0f, sampleRate);
    
    std::vector<float> filteredSignal = testSignal;
    
    // Apply filtering
    for (uint32_t i = 0; i < sampleCount; ++i) {
        filteredSignal[i] = filter.process(testSignal[i]);
    }
    
    // High-pass filter should pass the 1kHz signal
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float filteredAmplitude = *std::max_element(filteredSignal.begin(), filteredSignal.end());
    
    // High-pass filter should pass frequencies above cutoff
    EXPECT_GT(filteredAmplitude, 0.0f) << "High-pass filter should pass 1kHz signal";
    EXPECT_LT(std::abs(filteredAmplitude - originalAmplitude), 0.1f) << "Amplitude should be similar";
}

TEST_F(IIR1RadioFilteringTest, BandPassFiltering) {
    IIR1Filter highPassFilter;
    IIR1Filter lowPassFilter;
    
    // Set up bandpass: 500Hz to 2000Hz
    highPassFilter.setHighPass(500.0f, sampleRate);
    lowPassFilter.setLowPass(2000.0f, sampleRate);
    
    std::vector<float> filteredSignal = testSignal;
    
    // Apply bandpass filtering (high-pass then low-pass)
    for (uint32_t i = 0; i < sampleCount; ++i) {
        float sample = highPassFilter.process(testSignal[i]);
        filteredSignal[i] = lowPassFilter.process(sample);
    }
    
    // Bandpass should pass the 1kHz signal
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float filteredAmplitude = *std::max_element(filteredSignal.begin(), filteredSignal.end());
    
    EXPECT_GT(filteredAmplitude, 0.0f) << "Bandpass filter should pass 1kHz signal";
    EXPECT_LT(std::abs(filteredAmplitude - originalAmplitude), 0.2f) << "Amplitude should be similar";
}

TEST_F(IIR1RadioFilteringTest, FilterReset) {
    IIR1Filter filter;
    filter.setLowPass(1000.0f, sampleRate);
    
    // Process some samples
    for (uint32_t i = 0; i < 100; ++i) {
        filter.process(testSignal[i % testSignal.size()]);
    }
    
    // Reset filter
    filter.reset();
    
    // Process same samples again
    std::vector<float> firstPass(100);
    std::vector<float> secondPass(100);
    
    for (uint32_t i = 0; i < 100; ++i) {
        firstPass[i] = filter.process(testSignal[i % testSignal.size()]);
    }
    
    filter.reset();
    
    for (uint32_t i = 0; i < 100; ++i) {
        secondPass[i] = filter.process(testSignal[i % testSignal.size()]);
    }
    
    // Results should be identical after reset
    for (uint32_t i = 0; i < 100; ++i) {
        EXPECT_FLOAT_EQ(firstPass[i], secondPass[i]) << "Filter reset should produce identical results";
    }
}

TEST_F(IIR1RadioFilteringTest, RadioBandpassFiltering) {
    ProfessionalAudioEngine engine;
    
    // Set up radio bandpass filtering
    engine.setRadioBandPassFilter(300.0f, 3000.0f, sampleRate);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio through radio filters
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Processing should modify the signal";
}

TEST_F(IIR1RadioFilteringTest, VHFRadioFiltering) {
    VHFAudioProcessor vhfProcessor;
    
    std::vector<float> testAudio(testSignal);
    
    // Process VHF audio
    vhfProcessor.processVHFAudio(testAudio.data(), sampleCount, 1, sampleRate, 0.8f);
    
    // Check that VHF processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "VHF processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "VHF processing should modify the signal";
}

TEST_F(IIR1RadioFilteringTest, HFRadioFiltering) {
    HFAudioProcessor hfProcessor;
    
    std::vector<float> testAudio(testSignal);
    
    // Process HF audio
    hfProcessor.processHFAudio(testAudio.data(), sampleCount, 1, sampleRate, 0.7f);
    
    // Check that HF processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "HF processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "HF processing should modify the signal";
}

TEST_F(IIR1RadioFilteringTest, AmateurRadioFiltering) {
    AmateurRadioProcessor amateurProcessor;
    
    std::vector<float> testAudio(testSignal);
    
    // Process amateur radio audio
    amateurProcessor.processAmateurAudio(testAudio.data(), sampleCount, 1, sampleRate, 0.9f);
    
    // Check that amateur radio processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Amateur radio processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Amateur radio processing should modify the signal";
}

TEST_F(IIR1RadioFilteringTest, SovietVHFRadioFiltering) {
    SovietVHFProcessor sovietProcessor("R-105");
    
    std::vector<float> testAudio(testSignal);
    
    // Process Soviet VHF audio
    sovietProcessor.processSovietVHFAudio(testAudio.data(), sampleCount, 1, sampleRate, 0.6f, 1.5);
    
    // Check that Soviet VHF processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Soviet VHF processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Soviet VHF processing should modify the signal";
}

TEST_F(IIR1RadioFilteringTest, PerformanceComparison) {
    // Test that IIR1 filters are more efficient than biquad for radio filtering
    IIR1Filter iir1Filter;
    BiquadFilter biquadFilter;
    
    iir1Filter.setLowPass(1000.0f, sampleRate);
    biquadFilter.setLowPass(1000.0f, sampleRate, 0.707f);
    
    std::vector<float> iir1Result = testSignal;
    std::vector<float> biquadResult = testSignal;
    
    // Time IIR1 processing
    auto start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < sampleCount; ++i) {
        iir1Result[i] = iir1Filter.process(testSignal[i]);
    }
    auto iir1Time = std::chrono::high_resolution_clock::now() - start;
    
    // Time biquad processing
    start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < sampleCount; ++i) {
        biquadResult[i] = biquadFilter.process(testSignal[i]);
    }
    auto biquadTime = std::chrono::high_resolution_clock::now() - start;
    
    // IIR1 should be faster (fewer operations per sample)
    auto iir1Microseconds = std::chrono::duration_cast<std::chrono::microseconds>(iir1Time).count();
    auto biquadMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(biquadTime).count();
    
    EXPECT_LE(iir1Microseconds, biquadMicroseconds) << "IIR1 should be faster than biquad for radio filtering";
    
    // Results should be similar (both are low-pass filters)
    float iir1Amplitude = *std::max_element(iir1Result.begin(), iir1Result.end());
    float biquadAmplitude = *std::max_element(biquadResult.begin(), biquadResult.end());
    
    EXPECT_GT(iir1Amplitude, 0.0f) << "IIR1 result should not be zero";
    EXPECT_GT(biquadAmplitude, 0.0f) << "Biquad result should not be zero";
}
