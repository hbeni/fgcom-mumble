/**
 * @file test_freedv.cpp
 * @brief Test suite for FreeDV Digital Voice System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the FreeDV digital voice system,
 * including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - Multiple bitrate modes (700C, 700D, 1600, 2020B, 2020C)
 * - OFDM modulation and demodulation
 * - Frequency-selective fading resistance
 * - Audio quality assessment
 * - Error correction and FEC
 * - Performance under various SNR conditions
 * - HF propagation characteristics
 * - Interception characteristics
 * 
 * @see voice-encryption/systems/freedv/include/freedv.h
 * @see voice-encryption/systems/freedv/README.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/freedv/include/freedv.h"
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>

using namespace std;
using namespace testing;

/**
 * @class FreeDV_Test
 * @brief Test fixture for FreeDV system tests
 */
class FreeDV_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize FreeDV system
        freedv = new FreeDV();
        ASSERT_NE(freedv, nullptr);
    }

    void TearDown() override {
        if (freedv) {
            delete freedv;
            freedv = nullptr;
        }
    }

    FreeDV* freedv = nullptr;
};

/**
 * @test Test FreeDV initialization and basic functionality
 */
TEST_F(FreeDV_Test, Initialization) {
    EXPECT_TRUE(freedv->isInitialized());
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_700C);
    EXPECT_EQ(freedv->getSampleRate(), 8000);
}

/**
 * @test Test FreeDV mode switching
 */
TEST_F(FreeDV_Test, ModeSwitching) {
    // Test 700C mode
    freedv->setMode(FreeDV::Mode::MODE_700C);
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_700C);
    EXPECT_EQ(freedv->getBitrate(), 700);
    
    // Test 700D mode
    freedv->setMode(FreeDV::Mode::MODE_700D);
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_700D);
    EXPECT_EQ(freedv->getBitrate(), 700);
    
    // Test 1600 mode
    freedv->setMode(FreeDV::Mode::MODE_1600);
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_1600);
    EXPECT_EQ(freedv->getBitrate(), 1600);
    
    // Test 2020B mode
    freedv->setMode(FreeDV::Mode::MODE_2020B);
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_2020B);
    EXPECT_EQ(freedv->getBitrate(), 2020);
    
    // Test 2020C mode
    freedv->setMode(FreeDV::Mode::MODE_2020C);
    EXPECT_EQ(freedv->getMode(), FreeDV::Mode::MODE_2020C);
    EXPECT_EQ(freedv->getBitrate(), 2020);
}

/**
 * @test Test FreeDV audio encoding and decoding
 */
TEST_F(FreeDV_Test, AudioEncodingDecoding) {
    // Generate test audio signal (sine wave)
    const int sampleCount = 160; // 20ms at 8kHz
    vector<float> inputAudio(sampleCount);
    vector<float> outputAudio(sampleCount);
    
    // Generate 1kHz sine wave
    for (int i = 0; i < sampleCount; i++) {
        inputAudio[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * i / 8000.0f);
    }
    
    // Encode audio
    vector<uint8_t> encodedData;
    bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
    EXPECT_TRUE(encodeResult);
    EXPECT_GT(encodedData.size(), 0);
    
    // Decode audio
    bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
    EXPECT_TRUE(decodeResult);
    EXPECT_EQ(outputAudio.size(), inputAudio.size());
}

/**
 * @test Test FreeDV performance under various SNR conditions
 */
TEST_F(FreeDV_Test, SNRTolerance) {
    const vector<float> snrLevels = {-10.0f, -5.0f, 0.0f, 5.0f, 10.0f, 15.0f, 20.0f};
    
    for (float snr : snrLevels) {
        // Generate test signal
        const int sampleCount = 160;
        vector<float> inputAudio(sampleCount);
        vector<float> outputAudio(sampleCount);
        
        // Generate test signal
        for (int i = 0; i < sampleCount; i++) {
            inputAudio[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * i / 8000.0f);
        }
        
        // Add noise based on SNR
        freedv->setSNR(snr);
        
        // Encode and decode
        vector<uint8_t> encodedData;
        bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
        EXPECT_TRUE(encodeResult);
        
        bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
        EXPECT_TRUE(decodeResult);
        
        // Calculate audio quality metrics
        float mse = 0.0f;
        for (size_t i = 0; i < inputAudio.size(); i++) {
            float diff = inputAudio[i] - outputAudio[i];
            mse += diff * diff;
        }
        mse /= inputAudio.size();
        
        // Quality should improve with higher SNR
        if (snr > 0.0f) {
            EXPECT_LT(mse, 0.1f); // MSE should be low for good SNR
        }
    }
}

/**
 * @test Test FreeDV frequency-selective fading resistance
 */
TEST_F(FreeDV_Test, FrequencySelectiveFading) {
    // Test different fading scenarios
    const vector<string> fadingTypes = {
        "flat_fading",
        "frequency_selective_fading",
        "multipath_fading",
        "doppler_fading"
    };
    
    for (const string& fadingType : fadingTypes) {
        freedv->setFadingType(fadingType);
        
        // Generate test signal
        const int sampleCount = 160;
        vector<float> inputAudio(sampleCount);
        vector<float> outputAudio(sampleCount);
        
        for (int i = 0; i < sampleCount; i++) {
            inputAudio[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * i / 8000.0f);
        }
        
        // Encode and decode with fading
        vector<uint8_t> encodedData;
        bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
        EXPECT_TRUE(encodeResult);
        
        bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
        EXPECT_TRUE(decodeResult);
        
        // OFDM should handle frequency-selective fading better than single-carrier
        if (fadingType == "frequency_selective_fading") {
            // FreeDV uses OFDM which should be more resistant to frequency-selective fading
            EXPECT_TRUE(freedv->isOFDMMode());
        }
    }
}

/**
 * @test Test FreeDV error correction and FEC
 */
TEST_F(FreeDV_Test, ErrorCorrection) {
    // Test with different error rates
    const vector<float> errorRates = {0.0f, 0.01f, 0.05f, 0.1f, 0.2f};
    
    for (float errorRate : errorRates) {
        freedv->setErrorRate(errorRate);
        
        // Generate test signal
        const int sampleCount = 160;
        vector<float> inputAudio(sampleCount);
        vector<float> outputAudio(sampleCount);
        
        for (int i = 0; i < sampleCount; i++) {
            inputAudio[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * i / 8000.0f);
        }
        
        // Encode and decode with errors
        vector<uint8_t> encodedData;
        bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
        EXPECT_TRUE(encodeResult);
        
        bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
        EXPECT_TRUE(decodeResult);
        
        // Calculate error correction effectiveness
        float correctionEffectiveness = freedv->getErrorCorrectionEffectiveness();
        EXPECT_GE(correctionEffectiveness, 0.0f);
        EXPECT_LE(correctionEffectiveness, 1.0f);
    }
}

/**
 * @test Test FreeDV performance metrics
 */
TEST_F(FreeDV_Test, PerformanceMetrics) {
    // Test encoding performance
    auto start = chrono::high_resolution_clock::now();
    
    const int sampleCount = 160;
    vector<float> inputAudio(sampleCount);
    vector<uint8_t> encodedData;
    
    for (int i = 0; i < sampleCount; i++) {
        inputAudio[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * i / 8000.0f);
    }
    
    bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
    EXPECT_TRUE(encodeResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Encoding should be fast (less than 1ms for 20ms of audio)
    EXPECT_LT(duration.count(), 1000);
    
    // Test decoding performance
    start = chrono::high_resolution_clock::now();
    
    vector<float> outputAudio(sampleCount);
    bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
    EXPECT_TRUE(decodeResult);
    
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Decoding should be fast (less than 1ms for 20ms of audio)
    EXPECT_LT(duration.count(), 1000);
}

/**
 * @test Test FreeDV interception characteristics
 */
TEST_F(FreeDV_Test, InterceptionCharacteristics) {
    // Test audio signature
    string audioSignature = freedv->getAudioSignature();
    EXPECT_FALSE(audioSignature.empty());
    
    // Test identifiability
    float identifiability = freedv->getIdentifiability();
    EXPECT_GE(identifiability, 0.0f);
    EXPECT_LE(identifiability, 1.0f);
    
    // Test SIGINT recognition time
    float recognitionTime = freedv->getSIGINTRecognitionTime();
    EXPECT_GT(recognitionTime, 0.0f);
    
    // Test frequency signature
    string frequencySignature = freedv->getFrequencySignature();
    EXPECT_FALSE(frequencySignature.empty());
    
    // Test modulation characteristics
    string modulation = freedv->getModulationType();
    EXPECT_EQ(modulation, "OFDM");
}

/**
 * @test Test FreeDV thread safety
 */
TEST_F(FreeDV_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 100;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                const int sampleCount = 160;
                vector<float> inputAudio(sampleCount);
                vector<float> outputAudio(sampleCount);
                vector<uint8_t> encodedData;
                
                // Generate test signal
                for (int j = 0; j < sampleCount; j++) {
                    inputAudio[j] = 0.5f * sin(2.0f * M_PI * 1000.0f * j / 8000.0f);
                }
                
                // Encode and decode
                bool encodeResult = freedv->encodeAudio(inputAudio, encodedData);
                bool decodeResult = freedv->decodeAudio(encodedData, outputAudio);
                
                if (!encodeResult || !decodeResult) {
                    results[t] = false;
                    break;
                }
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have succeeded
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

/**
 * @test Test FreeDV edge cases
 */
TEST_F(FreeDV_Test, EdgeCases) {
    // Test with empty audio
    vector<float> emptyAudio;
    vector<uint8_t> encodedData;
    bool encodeResult = freedv->encodeAudio(emptyAudio, encodedData);
    EXPECT_FALSE(encodeResult);
    
    // Test with null pointers
    bool decodeResult = freedv->decodeAudio({}, {});
    EXPECT_FALSE(decodeResult);
    
    // Test with invalid mode
    freedv->setMode(static_cast<FreeDV::Mode>(999));
    EXPECT_NE(freedv->getMode(), static_cast<FreeDV::Mode>(999));
    
    // Test with extreme SNR values
    freedv->setSNR(-100.0f);
    freedv->setSNR(100.0f);
    // Should clamp to valid range
    EXPECT_GE(freedv->getSNR(), -20.0f);
    EXPECT_LE(freedv->getSNR(), 30.0f);
}
