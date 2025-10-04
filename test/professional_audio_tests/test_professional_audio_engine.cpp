/* 
 * Test Professional Audio Engine
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

class ProfessionalAudioEngineTest : public ::testing::Test {
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

TEST_F(ProfessionalAudioEngineTest, BasicAudioProcessing) {
    ProfessionalAudioEngine engine;
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Verify processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Processing should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, RadioBandpassFiltering) {
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

TEST_F(ProfessionalAudioEngineTest, VolumeControl) {
    ProfessionalAudioEngine engine;
    
    // Set volume to 0.5
    engine.setVolume(0.5f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that volume was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_LT(processedAmplitude, originalAmplitude) << "Volume reduction should reduce amplitude";
}

TEST_F(ProfessionalAudioEngineTest, SignalQualityDegradation) {
    ProfessionalAudioEngine engine;
    
    // Set signal quality to 0.5 (50% quality)
    engine.setSignalQuality(0.5f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that quality degradation occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Quality degradation should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, NoiseLevel) {
    ProfessionalAudioEngine engine;
    
    // Set noise level to 0.1
    engine.setNoiseLevel(0.1f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that noise was added
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Noise addition should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, ReverbEffect) {
    ProfessionalAudioEngine engine;
    
    // Enable reverb
    engine.enableReverb(true, 0.3f, 0.5f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that reverb was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Reverb should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, ChorusEffect) {
    ProfessionalAudioEngine engine;
    
    // Enable chorus
    engine.enableChorus(true, 0.5f, 0.1f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that chorus was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Chorus should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, CompressionEffect) {
    ProfessionalAudioEngine engine;
    
    // Enable compression
    engine.enableCompression(true, -20.0f, 3.0f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that compression was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Compression should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, NoiseGateEffect) {
    ProfessionalAudioEngine engine;
    
    // Enable noise gate
    engine.enableNoiseGate(true, -40.0f);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that noise gate was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Noise gate should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, EQEffect) {
    ProfessionalAudioEngine engine;
    
    // Enable EQ with specific frequencies and gains
    std::vector<float> frequencies = {1000.0f, 2000.0f, 4000.0f};
    std::vector<float> gains = {2.0f, 0.5f, 1.5f};
    engine.enableEQ(true, frequencies, gains);
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that EQ was applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "EQ should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, RadioEffects) {
    ProfessionalAudioEngine engine;
    
    // Enable radio effects
    engine.enableRadioEffects(true);
    engine.setRadioType("VHF");
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that radio effects were applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Radio effects should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, PropagationEffects) {
    ProfessionalAudioEngine engine;
    
    // Set propagation effects
    engine.setPropagationEffects(100.0f, 0.7f); // 100km distance, 70% quality
    
    std::vector<float> testAudio(testSignal);
    
    // Process audio
    engine.processAudio(testAudio.data(), sampleCount, 1, sampleRate);
    
    // Check that propagation effects were applied
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Propagation effects should modify the signal";
}

TEST_F(ProfessionalAudioEngineTest, MultiChannelProcessing) {
    ProfessionalAudioEngine engine;
    
    // Create stereo test signal
    std::vector<float> stereoSignal(sampleCount * 2);
    for (uint32_t i = 0; i < sampleCount; ++i) {
        float t = static_cast<float>(i) / sampleRate;
        stereoSignal[i * 2] = 0.5f * std::sin(2.0f * M_PI * testFrequency * t); // Left channel
        stereoSignal[i * 2 + 1] = 0.5f * std::sin(2.0f * M_PI * testFrequency * t); // Right channel
    }
    
    // Process stereo audio
    engine.processAudio(stereoSignal.data(), sampleCount, 2, sampleRate);
    
    // Check that processing occurred
    float maxAmplitude = *std::max_element(stereoSignal.begin(), stereoSignal.end());
    EXPECT_GT(maxAmplitude, 0.0f) << "Stereo processed audio should not be zero";
}

TEST_F(ProfessionalAudioEngineTest, PerformanceTest) {
    ProfessionalAudioEngine engine;
    
    // Create larger test signal for performance testing
    uint32_t largeSampleCount = sampleCount * 10; // 1 second of audio
    std::vector<float> largeTestSignal(largeSampleCount);
    for (uint32_t i = 0; i < largeSampleCount; ++i) {
        float t = static_cast<float>(i) / sampleRate;
        largeTestSignal[i] = 0.5f * std::sin(2.0f * M_PI * testFrequency * t);
    }
    
    // Time the processing
    auto start = std::chrono::high_resolution_clock::now();
    engine.processAudio(largeTestSignal.data(), largeSampleCount, 1, sampleRate);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Processing should be fast (less than 1ms per sample)
    EXPECT_LT(duration.count(), largeSampleCount) << "Processing should be fast";
    
    // Check that processing occurred
    float maxAmplitude = *std::max_element(largeTestSignal.begin(), largeTestSignal.end());
    EXPECT_GT(maxAmplitude, 0.0f) << "Processed audio should not be zero";
}







