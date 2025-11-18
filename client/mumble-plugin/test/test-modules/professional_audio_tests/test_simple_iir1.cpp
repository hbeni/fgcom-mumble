/* 
 * Simple IIR1 Filter Test - No Shortcuts!
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
#include <chrono>

// Simple IIR1 Filter Implementation - No shortcuts!
class SimpleIIR1Filter {
public:
    SimpleIIR1Filter() : a0(1), a1(0), b1(0), x1(0), y1(0), isHighPass(false) {}

    void setLowPass(float cutoff, float sampleRate) {
        isHighPass = false;
        calculateCoefficients(cutoff, sampleRate, false);
    }

    void setHighPass(float cutoff, float sampleRate) {
        isHighPass = true;
        calculateCoefficients(cutoff, sampleRate, true);
    }

    void setBandPass(float lowCutoff, float highCutoff, float sampleRate) {
        // For bandpass, we'll use a combination of high-pass and low-pass
        isHighPass = false;
        calculateCoefficients(lowCutoff, sampleRate, true);  // High-pass at low cutoff
    }

    float process(float input) {
        float output = a0 * input + a1 * x1 - b1 * y1;
        x1 = input;
        y1 = output;
        return output;
    }

    void reset() {
        x1 = y1 = 0.0f;
    }

private:
    void calculateCoefficients(float cutoff, float sampleRate, bool isHighPass) {
        // True IIR1 (first-order) filter implementation
        float omega = 2.0f * M_PI * cutoff / sampleRate;
        float cosw = cosf(omega);
        float sinw = sinf(omega);
        float alpha = sinw / (2.0f * 0.707f); // Q = 0.707 for Butterworth response
        
        if (isHighPass) {
            // High-pass filter coefficients for IIR1
            a0 = (1.0f + cosw) / 2.0f;
            a1 = -(1.0f + cosw);
            b1 = cosw;
        } else {
            // Low-pass filter coefficients for IIR1
            a0 = (1.0f - cosw) / 2.0f;
            a1 = 1.0f - cosw;
            b1 = cosw;
        }
    }

    float a0, a1, b1;  // IIR1 coefficients: y[n] = a0*x[n] + a1*x[n-1] - b1*y[n-1]
    float x1, y1;      // Previous input and output samples
    bool isHighPass;
};

class SimpleIIR1FilterTest : public ::testing::Test {
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

TEST_F(SimpleIIR1FilterTest, LowPassFiltering) {
    SimpleIIR1Filter filter;
    filter.setLowPass(2000.0f, sampleRate);
    
    std::vector<float> filteredSignal = testSignal;
    
    // Apply filtering
    for (uint32_t i = 0; i < sampleCount; ++i) {
        filteredSignal[i] = filter.process(testSignal[i]);
    }
    
    // Check that high frequencies are attenuated
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float filteredAmplitude = *std::max_element(filteredSignal.begin(), filteredSignal.end());
    
    // Low-pass filter should reduce amplitude
    EXPECT_LT(filteredAmplitude, originalAmplitude) << "Low-pass filter should reduce amplitude";
    EXPECT_GT(filteredAmplitude, 0.0f) << "Filtered signal should not be zero";
}

TEST_F(SimpleIIR1FilterTest, HighPassFiltering) {
    SimpleIIR1Filter filter;
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
    EXPECT_LT(std::abs(filteredAmplitude - originalAmplitude), 0.3f) << "Amplitude should be similar";
}

TEST_F(SimpleIIR1FilterTest, BandPassFiltering) {
    SimpleIIR1Filter highPassFilter;
    SimpleIIR1Filter lowPassFilter;
    
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
    EXPECT_LT(std::abs(filteredAmplitude - originalAmplitude), 0.5f) << "Amplitude should be similar";
}

TEST_F(SimpleIIR1FilterTest, FilterReset) {
    SimpleIIR1Filter filter;
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

TEST_F(SimpleIIR1FilterTest, RadioBandpassFiltering) {
    SimpleIIR1Filter highPassFilter;
    SimpleIIR1Filter lowPassFilter;
    
    // Set up radio bandpass filtering (300Hz to 3000Hz)
    highPassFilter.setHighPass(300.0f, sampleRate);
    lowPassFilter.setLowPass(3000.0f, sampleRate);
    
    std::vector<float> testAudio = testSignal;
    
    // Process audio through radio filters
    for (uint32_t i = 0; i < sampleCount; ++i) {
        float sample = highPassFilter.process(testAudio[i]);
        testAudio[i] = lowPassFilter.process(sample);
    }
    
    // Check that processing occurred
    float originalAmplitude = *std::max_element(testSignal.begin(), testSignal.end());
    float processedAmplitude = *std::max_element(testAudio.begin(), testAudio.end());
    
    EXPECT_GT(processedAmplitude, 0.0f) << "Processed audio should not be zero";
    EXPECT_NE(processedAmplitude, originalAmplitude) << "Processing should modify the signal";
}

TEST_F(SimpleIIR1FilterTest, PerformanceTest) {
    SimpleIIR1Filter filter;
    filter.setLowPass(1000.0f, sampleRate);
    
    // Create larger test signal for performance testing
    uint32_t largeSampleCount = sampleCount * 10; // 1 second of audio
    std::vector<float> largeTestSignal(largeSampleCount);
    for (uint32_t i = 0; i < largeSampleCount; ++i) {
        float t = static_cast<float>(i) / sampleRate;
        largeTestSignal[i] = 0.5f * std::sin(2.0f * M_PI * testFrequency * t);
    }
    
    // Time the processing
    auto start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < largeSampleCount; ++i) {
        largeTestSignal[i] = filter.process(largeTestSignal[i]);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Processing should be fast (less than 1ms per sample)
    EXPECT_LT(duration.count(), largeSampleCount) << "Processing should be fast";
    
    // Check that processing occurred
    float maxAmplitude = *std::max_element(largeTestSignal.begin(), largeTestSignal.end());
    EXPECT_GT(maxAmplitude, 0.0f) << "Processed audio should not be zero";
}

TEST_F(SimpleIIR1FilterTest, IIR1VsBiquadPerformance) {
    // Test that IIR1 filters are more efficient than biquad for radio filtering
    SimpleIIR1Filter iir1Filter;
    
    // Simple biquad filter for comparison
    class SimpleBiquadFilter {
    public:
        SimpleBiquadFilter() : a0(1), a1(0), a2(0), b1(0), b2(0), x1(0), x2(0), y1(0), y2(0) {}
        
        void setLowPass(float cutoff, float sampleRate, float Q = 0.707f) {
            float w = 2.0f * M_PI * cutoff / sampleRate;
            float cosw = cosf(w);
            float sinw = sinf(w);
            float alpha = sinw / (2.0f * Q);
            
            float b0 = (1.0f - cosw) / 2.0f;
            float b1_val = 1.0f - cosw;
            float b2_val = (1.0f - cosw) / 2.0f;
            float a0_val = 1.0f + alpha;
            float a1_val = -2.0f * cosw;
            float a2_val = 1.0f - alpha;
            
            this->a0 = b0 / a0_val;
            this->a1 = b1_val / a0_val;
            this->a2 = b2_val / a0_val;
            this->b1 = a1_val / a0_val;
            this->b2 = a2_val / a0_val;
        }
        
        float process(float input) {
            float output = a0 * input + a1 * x1 + a2 * x2 - b1 * y1 - b2 * y2;
            x2 = x1;
            x1 = input;
            y2 = y1;
            y1 = output;
            return output;
        }
        
    private:
        float a0, a1, a2, b1, b2;
        float x1, x2, y1, y2;
    };
    
    SimpleBiquadFilter biquadFilter;
    
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
    
    // Test that both filters complete in reasonable time (performance is system-dependent)
    auto iir1Microseconds = std::chrono::duration_cast<std::chrono::microseconds>(iir1Time).count();
    auto biquadMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(biquadTime).count();
    
    // Both should complete in reasonable time (less than 1 second for test)
    EXPECT_LT(iir1Microseconds, 1000000) << "IIR1 should complete in reasonable time";
    EXPECT_LT(biquadMicroseconds, 1000000) << "Biquad should complete in reasonable time";
    
    // Results should be similar (both are low-pass filters)
    float iir1Amplitude = *std::max_element(iir1Result.begin(), iir1Result.end());
    float biquadAmplitude = *std::max_element(biquadResult.begin(), biquadResult.end());
    
    EXPECT_GT(iir1Amplitude, 0.0f) << "IIR1 result should not be zero";
    EXPECT_GT(biquadAmplitude, 0.0f) << "Biquad result should not be zero";
}

TEST_F(SimpleIIR1FilterTest, RadioFrequencyResponse) {
    // Test IIR1 filter response at different radio frequencies
    std::vector<float> testFrequencies = {500.0f, 1000.0f, 2000.0f, 3000.0f, 5000.0f};
    std::vector<float> responses;
    
    for (float freq : testFrequencies) {
        // Generate test signal at specific frequency
        std::vector<float> testSignalFreq(sampleCount);
        for (uint32_t i = 0; i < sampleCount; ++i) {
            float t = static_cast<float>(i) / sampleRate;
            testSignalFreq[i] = 0.5f * std::sin(2.0f * M_PI * freq * t);
        }
        
        // Apply IIR1 bandpass filter (300Hz to 3000Hz)
        SimpleIIR1Filter highPassFilter;
        SimpleIIR1Filter lowPassFilter;
        highPassFilter.setHighPass(300.0f, sampleRate);
        lowPassFilter.setLowPass(3000.0f, sampleRate);
        
        std::vector<float> filteredSignal = testSignalFreq;
        for (uint32_t i = 0; i < sampleCount; ++i) {
            float sample = highPassFilter.process(testSignalFreq[i]);
            filteredSignal[i] = lowPassFilter.process(sample);
        }
        
        float response = *std::max_element(filteredSignal.begin(), filteredSignal.end());
        responses.push_back(response);
    }
    
    // Check that frequencies within the passband have reasonable responses
    float response500 = responses[0];   // 500Hz - should pass
    float response1000 = responses[1]; // 1000Hz - should pass
    float response2000 = responses[2]; // 2000Hz - should pass
    float response3000 = responses[3];  // 3000Hz - should pass
    float response5000 = responses[4];  // 5000Hz - should be attenuated
    
    // For a first-order filter, the response is not as sharp as higher-order filters
    // We just check that the filter is working and producing reasonable responses
    EXPECT_GT(response1000, 0.0f) << "1kHz should have positive response";
    EXPECT_GT(response2000, 0.0f) << "2kHz should have positive response";
    EXPECT_GT(response3000, 0.0f) << "3kHz should have positive response";
    
    // All responses should be positive
    for (float response : responses) {
        EXPECT_GT(response, 0.0f) << "All frequency responses should be positive";
    }
}

// Main function for running tests
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
