/**
 * @file test_melpe.cpp
 * @brief Test suite for MELPe NATO Standard Vocoder
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the MELPe (Mixed Excitation Linear Prediction enhanced)
 * NATO standard vocoder system, including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - STANAG 4591 compliance
 * - 2400 bps digital voice encoding
 * - LPC analysis and synthesis
 * - Voice quality assessment
 * - Military communication characteristics
 * - Error handling and edge cases
 * - Performance under various conditions
 * - Interception characteristics
 * 
 * @see voice-encryption/systems/melpe/include/melpe.h
 * @see voice-encryption/systems/melpe/README.md
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/melpe/include/melpe.h"
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>

using namespace std;
using namespace testing;

/**
 * @class MELPe_Test
 * @brief Test fixture for MELPe system tests
 */
class MELPe_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize MELPe system
        melpe = new MELPe();
        ASSERT_NE(melpe, nullptr);
    }

    void TearDown() override {
        if (melpe) {
            delete melpe;
            melpe = nullptr;
        }
    }

    MELPe* melpe = nullptr;
};

/**
 * @test Test MELPe initialization and basic functionality
 */
TEST_F(MELPe_Test, Initialization) {
    EXPECT_TRUE(melpe->isInitialized());
    EXPECT_EQ(melpe->getBitrate(), 2400);
    EXPECT_EQ(melpe->getSampleRate(), 8000);
    EXPECT_EQ(melpe->getFrameSize(), 180); // 22.5ms at 8kHz
    EXPECT_TRUE(melpe->isSTANAG4591Compliant());
}

/**
 * @test Test MELPe voice encoding and decoding
 */
TEST_F(MELPe_Test, VoiceEncodingDecoding) {
    // Generate test voice signal (speech-like)
    const int frameSize = 180; // 22.5ms at 8kHz
    vector<float> inputVoice(frameSize);
    vector<float> outputVoice(frameSize);
    
    // Generate speech-like signal (formant structure)
    for (int i = 0; i < frameSize; i++) {
        float t = static_cast<float>(i) / 8000.0f;
        // Simulate formants at 800Hz, 1200Hz, 2500Hz
        inputVoice[i] = 0.3f * sin(2.0f * M_PI * 800.0f * t) +
                       0.2f * sin(2.0f * M_PI * 1200.0f * t) +
                       0.1f * sin(2.0f * M_PI * 2500.0f * t);
    }
    
    // Encode voice
    vector<uint8_t> encodedData;
    bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
    EXPECT_TRUE(encodeResult);
    EXPECT_GT(encodedData.size(), 0);
    EXPECT_EQ(encodedData.size(), 30); // 2400 bps * 22.5ms = 54 bits = 6.75 bytes, rounded to 30 bytes
    
    // Decode voice
    bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
    EXPECT_TRUE(decodeResult);
    EXPECT_EQ(outputVoice.size(), inputVoice.size());
}

/**
 * @test Test MELPe LPC analysis and synthesis
 */
TEST_F(MELPe_Test, LPCAnalysisSynthesis) {
    const int frameSize = 180;
    vector<float> inputVoice(frameSize);
    
    // Generate test voice signal
    for (int i = 0; i < frameSize; i++) {
        float t = static_cast<float>(i) / 8000.0f;
        inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
    }
    
    // Test LPC analysis
    vector<float> lpcCoeffs;
    bool analysisResult = melpe->analyzeLPC(inputVoice, lpcCoeffs);
    EXPECT_TRUE(analysisResult);
    EXPECT_EQ(lpcCoeffs.size(), 10); // 10th order LPC
    
    // Test LPC synthesis
    vector<float> synthesizedVoice;
    bool synthesisResult = melpe->synthesizeLPC(lpcCoeffs, synthesizedVoice);
    EXPECT_TRUE(synthesisResult);
    EXPECT_EQ(synthesizedVoice.size(), frameSize);
}

/**
 * @test Test MELPe voice quality assessment
 */
TEST_F(MELPe_Test, VoiceQualityAssessment) {
    const int frameSize = 180;
    vector<float> inputVoice(frameSize);
    vector<float> outputVoice(frameSize);
    
    // Generate test voice signal
    for (int i = 0; i < frameSize; i++) {
        float t = static_cast<float>(i) / 8000.0f;
        inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
    }
    
    // Encode and decode
    vector<uint8_t> encodedData;
    bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
    EXPECT_TRUE(encodeResult);
    
    bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
    EXPECT_TRUE(decodeResult);
    
    // Calculate voice quality metrics
    float mse = 0.0f;
    float snr = 0.0f;
    float pesq = 0.0f;
    
    melpe->calculateQualityMetrics(inputVoice, outputVoice, mse, snr, pesq);
    
    EXPECT_GT(mse, 0.0f);
    EXPECT_GT(snr, 0.0f);
    EXPECT_GT(pesq, 0.0f);
    EXPECT_LE(pesq, 5.0f); // PESQ range is 0-5
}

/**
 * @test Test MELPe performance under various SNR conditions
 */
TEST_F(MELPe_Test, SNRTolerance) {
    const vector<float> snrLevels = {-5.0f, 0.0f, 5.0f, 10.0f, 15.0f, 20.0f, 25.0f};
    
    for (float snr : snrLevels) {
        melpe->setSNR(snr);
        
        const int frameSize = 180;
        vector<float> inputVoice(frameSize);
        vector<float> outputVoice(frameSize);
        
        // Generate test voice signal
        for (int i = 0; i < frameSize; i++) {
            float t = static_cast<float>(i) / 8000.0f;
            inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
        }
        
        // Encode and decode
        vector<uint8_t> encodedData;
        bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
        EXPECT_TRUE(encodeResult);
        
        bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
        EXPECT_TRUE(decodeResult);
        
        // Calculate quality metrics
        float mse, snr_calc, pesq;
        melpe->calculateQualityMetrics(inputVoice, outputVoice, mse, snr_calc, pesq);
        
        // Quality should improve with higher SNR
        if (snr > 10.0f) {
            EXPECT_GT(pesq, 2.0f); // Good quality for high SNR
        }
    }
}

/**
 * @test Test MELPe military communication characteristics
 */
TEST_F(MELPe_Test, MilitaryCharacteristics) {
    // Test NATO standard compliance
    EXPECT_TRUE(melpe->isSTANAG4591Compliant());
    EXPECT_EQ(melpe->getStandard(), "STANAG 4591");
    EXPECT_EQ(melpe->getBitrate(), 2400);
    
    // Test military voice characteristics
    string voiceCharacteristics = melpe->getVoiceCharacteristics();
    EXPECT_FALSE(voiceCharacteristics.empty());
    
    // Test digital voice quality
    float digitalVoiceQuality = melpe->getDigitalVoiceQuality();
    EXPECT_GE(digitalVoiceQuality, 0.0f);
    EXPECT_LE(digitalVoiceQuality, 1.0f);
    
    // Test military communication features
    EXPECT_TRUE(melpe->hasErrorCorrection());
    EXPECT_TRUE(melpe->hasVoiceActivityDetection());
    EXPECT_TRUE(melpe->hasNoiseSuppression());
}

/**
 * @test Test MELPe error correction and robustness
 */
TEST_F(MELPe_Test, ErrorCorrection) {
    const vector<float> errorRates = {0.0f, 0.01f, 0.05f, 0.1f, 0.2f};
    
    for (float errorRate : errorRates) {
        melpe->setErrorRate(errorRate);
        
        const int frameSize = 180;
        vector<float> inputVoice(frameSize);
        vector<float> outputVoice(frameSize);
        
        // Generate test voice signal
        for (int i = 0; i < frameSize; i++) {
            float t = static_cast<float>(i) / 8000.0f;
            inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
        }
        
        // Encode and decode with errors
        vector<uint8_t> encodedData;
        bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
        EXPECT_TRUE(encodeResult);
        
        bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
        EXPECT_TRUE(decodeResult);
        
        // Calculate error correction effectiveness
        float correctionEffectiveness = melpe->getErrorCorrectionEffectiveness();
        EXPECT_GE(correctionEffectiveness, 0.0f);
        EXPECT_LE(correctionEffectiveness, 1.0f);
    }
}

/**
 * @test Test MELPe performance metrics
 */
TEST_F(MELPe_Test, PerformanceMetrics) {
    // Test encoding performance
    auto start = chrono::high_resolution_clock::now();
    
    const int frameSize = 180;
    vector<float> inputVoice(frameSize);
    vector<uint8_t> encodedData;
    
    for (int i = 0; i < frameSize; i++) {
        float t = static_cast<float>(i) / 8000.0f;
        inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
    }
    
    bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
    EXPECT_TRUE(encodeResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Encoding should be fast (less than 5ms for 22.5ms of voice)
    EXPECT_LT(duration.count(), 5000);
    
    // Test decoding performance
    start = chrono::high_resolution_clock::now();
    
    vector<float> outputVoice(frameSize);
    bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
    EXPECT_TRUE(decodeResult);
    
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Decoding should be fast (less than 5ms for 22.5ms of voice)
    EXPECT_LT(duration.count(), 5000);
}

/**
 * @test Test MELPe interception characteristics
 */
TEST_F(MELPe_Test, InterceptionCharacteristics) {
    // Test audio signature
    string audioSignature = melpe->getAudioSignature();
    EXPECT_FALSE(audioSignature.empty());
    EXPECT_EQ(audioSignature, "Digital voice, robotic, NATO standard");
    
    // Test identifiability
    float identifiability = melpe->getIdentifiability();
    EXPECT_GE(identifiability, 0.0f);
    EXPECT_LE(identifiability, 1.0f);
    
    // Test SIGINT recognition time
    float recognitionTime = melpe->getSIGINTRecognitionTime();
    EXPECT_GT(recognitionTime, 0.0f);
    EXPECT_LT(recognitionTime, 5.0f); // Should be quickly identifiable
    
    // Test frequency signature
    string frequencySignature = melpe->getFrequencySignature();
    EXPECT_FALSE(frequencySignature.empty());
    
    // Test modulation characteristics
    string modulation = melpe->getModulationType();
    EXPECT_EQ(modulation, "Digital voice");
    
    // Test military voice characteristics
    string militaryCharacteristics = melpe->getMilitaryVoiceCharacteristics();
    EXPECT_FALSE(militaryCharacteristics.empty());
}

/**
 * @test Test MELPe thread safety
 */
TEST_F(MELPe_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 100;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                const int frameSize = 180;
                vector<float> inputVoice(frameSize);
                vector<float> outputVoice(frameSize);
                vector<uint8_t> encodedData;
                
                // Generate test voice signal
                for (int j = 0; j < frameSize; j++) {
                    float time = static_cast<float>(j) / 8000.0f;
                    inputVoice[j] = 0.5f * sin(2.0f * M_PI * 1000.0f * time);
                }
                
                // Encode and decode
                bool encodeResult = melpe->encodeVoice(inputVoice, encodedData);
                bool decodeResult = melpe->decodeVoice(encodedData, outputVoice);
                
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
 * @test Test MELPe edge cases
 */
TEST_F(MELPe_Test, EdgeCases) {
    // Test with empty voice
    vector<float> emptyVoice;
    vector<uint8_t> encodedData;
    bool encodeResult = melpe->encodeVoice(emptyVoice, encodedData);
    EXPECT_FALSE(encodeResult);
    
    // Test with null pointers
    bool decodeResult = melpe->decodeVoice({}, {});
    EXPECT_FALSE(decodeResult);
    
    // Test with invalid frame size
    vector<float> invalidVoice(100); // Wrong frame size
    encodeResult = melpe->encodeVoice(invalidVoice, encodedData);
    EXPECT_FALSE(encodeResult);
    
    // Test with extreme SNR values
    melpe->setSNR(-100.0f);
    melpe->setSNR(100.0f);
    // Should clamp to valid range
    EXPECT_GE(melpe->getSNR(), -10.0f);
    EXPECT_LE(melpe->getSNR(), 30.0f);
    
    // Test with extreme error rates
    melpe->setErrorRate(-1.0f);
    melpe->setErrorRate(2.0f);
    // Should clamp to valid range
    EXPECT_GE(melpe->getErrorRate(), 0.0f);
    EXPECT_LE(melpe->getErrorRate(), 1.0f);
}

/**
 * @test Test MELPe voice activity detection
 */
TEST_F(MELPe_Test, VoiceActivityDetection) {
    const int frameSize = 180;
    vector<float> inputVoice(frameSize);
    
    // Test with silence
    fill(inputVoice.begin(), inputVoice.end(), 0.0f);
    bool hasVoice = melpe->detectVoiceActivity(inputVoice);
    EXPECT_FALSE(hasVoice);
    
    // Test with voice
    for (int i = 0; i < frameSize; i++) {
        float t = static_cast<float>(i) / 8000.0f;
        inputVoice[i] = 0.5f * sin(2.0f * M_PI * 1000.0f * t);
    }
    hasVoice = melpe->detectVoiceActivity(inputVoice);
    EXPECT_TRUE(hasVoice);
    
    // Test with noise
    for (int i = 0; i < frameSize; i++) {
        inputVoice[i] = 0.1f * (static_cast<float>(rand()) / RAND_MAX - 0.5f);
    }
    hasVoice = melpe->detectVoiceActivity(inputVoice);
    EXPECT_FALSE(hasVoice);
}
