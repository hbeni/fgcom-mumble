/**
 * @file test_piper_tts.cpp
 * @brief Test suite for Piper TTS Integration
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for Piper TTS integration,
 * including model management, audio generation, and performance.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include <fstream>
#include "piper_tts.h"

using namespace std;
using namespace testing;

/**
 * @class PiperTTS_Test
 * @brief Test fixture for Piper TTS tests
 */
class PiperTTS_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize Piper TTS system
        piperTTS = new PiperTTS();
        ASSERT_NE(piperTTS, nullptr);
    }

    void TearDown() override {
        if (piperTTS) {
            delete piperTTS;
            piperTTS = nullptr;
        }
    }

    PiperTTS* piperTTS = nullptr;
};

/**
 * @test Test Piper TTS initialization
 */
TEST_F(PiperTTS_Test, Initialization) {
    EXPECT_TRUE(piperTTS->isInitialized());
    EXPECT_FALSE(piperTTS->getDefaultModel().empty());
    EXPECT_GT(piperTTS->getSampleRate(), 0);
    EXPECT_GT(piperTTS->getBitrate(), 0);
}

/**
 * @test Test Piper TTS model management
 */
TEST_F(PiperTTS_Test, ModelManagement) {
    // Test available models
    vector<string> availableModels = piperTTS->getAvailableModels();
    EXPECT_GT(availableModels.size(), 0);
    
    // Test model selection
    string defaultModel = piperTTS->getDefaultModel();
    EXPECT_TRUE(piperTTS->setModel(defaultModel));
    EXPECT_EQ(piperTTS->getCurrentModel(), defaultModel);
    
    // Test invalid model
    EXPECT_FALSE(piperTTS->setModel("INVALID_MODEL"));
}

/**
 * @test Test Piper TTS audio generation
 */
TEST_F(PiperTTS_Test, AudioGeneration) {
    string testText = "This is a test message for Piper TTS.";
    string outputFile = "test_piper_output.wav";
    
    // Test audio generation
    bool generateResult = piperTTS->generateAudio(testText, outputFile);
    EXPECT_TRUE(generateResult);
    
    // Test output file existence
    ifstream file(outputFile);
    EXPECT_TRUE(file.good());
    file.close();
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test Piper TTS performance
 */
TEST_F(PiperTTS_Test, Performance) {
    // Test audio generation performance
    auto start = chrono::high_resolution_clock::now();
    
    string testText = "Performance test message for Piper TTS.";
    string outputFile = "performance_test.wav";
    bool generateResult = piperTTS->generateAudio(testText, outputFile);
    EXPECT_TRUE(generateResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    // Audio generation should be reasonable (less than 5 seconds for short text)
    EXPECT_LT(duration.count(), 5000);
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test Piper TTS error handling
 */
TEST_F(PiperTTS_Test, ErrorHandling) {
    // Test with empty text
    string outputFile = "empty_test.wav";
    bool generateResult = piperTTS->generateAudio("", outputFile);
    EXPECT_FALSE(generateResult);
    
    // Test with invalid output path
    generateResult = piperTTS->generateAudio("Test message", "/invalid/path/test.wav");
    EXPECT_FALSE(generateResult);
}

/**
 * @test Test Piper TTS thread safety
 */
TEST_F(PiperTTS_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 10;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                string testText = "Thread " + to_string(t) + " iteration " + to_string(i);
                string outputFile = "thread_" + to_string(t) + "_" + to_string(i) + ".wav";
                
                bool generateResult = piperTTS->generateAudio(testText, outputFile);
                
                if (!generateResult) {
                    results[t] = false;
                    break;
                }
                
                // Clean up
                remove(outputFile.c_str());
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
