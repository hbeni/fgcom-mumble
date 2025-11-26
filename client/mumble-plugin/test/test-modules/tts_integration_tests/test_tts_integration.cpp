/**
 * @file test_tts_integration.cpp
 * @brief Test suite for TTS Integration System
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for the TTS integration system,
 * including unit tests, integration tests, and performance tests.
 * 
 * @details
 * The test suite covers:
 * - TTS system initialization and configuration
 * - Piper TTS integration and functionality
 * - ATIS text generation and processing
 * - Audio file generation and validation
 * - Template processing and customization
 * - Error handling and edge cases
 * - Performance under various conditions
 * - Integration with FGcom-mumble server
 * 
 * @see scripts/tts/README.md
 * @see scripts/tts/piper_tts_integration.sh
 * @see scripts/tts/atis_tts_generator.py
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include <fstream>
#include "tts_integration.h"
#include <thread>
#include <fstream>
#include <sstream>

using namespace std;
using namespace testing;

/**
 * @class TTSIntegration_Test
 * @brief Test fixture for TTS integration system tests
 */
class TTSIntegration_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize TTS integration system
        ttsSystem = new TTSIntegration();
        ASSERT_NE(ttsSystem, nullptr);
    }

    void TearDown() override {
        if (ttsSystem) {
            delete ttsSystem;
            ttsSystem = nullptr;
        }
    }

    TTSIntegration* ttsSystem = nullptr;
};

/**
 * @test Test TTS system initialization
 */
TEST_F(TTSIntegration_Test, Initialization) {
    EXPECT_TRUE(ttsSystem->isInitialized());
    EXPECT_TRUE(ttsSystem->isEnabled());
    EXPECT_FALSE(ttsSystem->getDefaultModel().empty());
    EXPECT_GT(ttsSystem->getSampleRate(), 0);
    EXPECT_GT(ttsSystem->getBitrate(), 0);
}

/**
 * @test Test TTS configuration loading
 */
TEST_F(TTSIntegration_Test, ConfigurationLoading) {
    // Test configuration file loading
    EXPECT_TRUE(ttsSystem->loadConfiguration("../../../scripts/tts/tts_config.conf"));
    
    // Test configuration validation
    EXPECT_TRUE(ttsSystem->validateConfiguration());
    
    // Test configuration parameters
    EXPECT_FALSE(ttsSystem->getDefaultModel().empty());
    EXPECT_GT(ttsSystem->getSampleRate(), 0);
    EXPECT_GT(ttsSystem->getBitrate(), 0);
    EXPECT_FALSE(ttsSystem->getOutputDirectory().empty());
}

/**
 * @test Test TTS model management
 */
TEST_F(TTSIntegration_Test, ModelManagement) {
    // Test available models
    vector<string> availableModels = ttsSystem->getAvailableModels();
    EXPECT_GT(availableModels.size(), 0);
    
    // Test model selection
    string defaultModel = ttsSystem->getDefaultModel();
    EXPECT_TRUE(ttsSystem->setModel(defaultModel));
    EXPECT_EQ(ttsSystem->getCurrentModel(), defaultModel);
    
    // Test invalid model
    EXPECT_FALSE(ttsSystem->setModel("INVALID_MODEL"));
}

/**
 * @test Test TTS text processing
 */
TEST_F(TTSIntegration_Test, TextProcessing) {
    // Test text preprocessing
    string inputText = "This is a test message for TTS processing.";
    string processedText = ttsSystem->preprocessText(inputText);
    EXPECT_FALSE(processedText.empty());
    EXPECT_NE(processedText, inputText); // Should be processed
    
    // Test text validation
    EXPECT_TRUE(ttsSystem->validateText(inputText));
    EXPECT_FALSE(ttsSystem->validateText("")); // Empty text should be invalid
    EXPECT_FALSE(ttsSystem->validateText(string(10000, 'a'))); // Too long text should be invalid
}

/**
 * @test Test TTS audio generation
 */
TEST_F(TTSIntegration_Test, AudioGeneration) {
    string testText = "This is a test message for audio generation.";
    string outputFile = "test_output.wav";
    
    // Test audio generation
    bool generateResult = ttsSystem->generateAudio(testText, outputFile);
    EXPECT_TRUE(generateResult);
    
    // Test output file existence and validity
    ifstream file(outputFile);
    EXPECT_TRUE(file.good());
    file.close();
    
    // Test audio file validation
    EXPECT_TRUE(ttsSystem->validateAudioFile(outputFile));
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test TTS performance
 */
TEST_F(TTSIntegration_Test, Performance) {
    // Test text processing performance
    auto start = chrono::high_resolution_clock::now();
    
    string testText = "This is a performance test message.";
    string processedText = ttsSystem->preprocessText(testText);
    EXPECT_FALSE(processedText.empty());
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // Text processing should be fast (less than 1ms)
    EXPECT_LT(duration.count(), 1000);
    
    // Test audio generation performance
    start = chrono::high_resolution_clock::now();
    
    string outputFile = "performance_test.wav";
    bool generateResult = ttsSystem->generateAudio(testText, outputFile);
    EXPECT_TRUE(generateResult);
    
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    // Audio generation should be reasonable (less than 5 seconds for short text)
    EXPECT_LT(duration.count(), 5000);
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test TTS error handling
 */
TEST_F(TTSIntegration_Test, ErrorHandling) {
    // Test with empty text
    string outputFile = "empty_test.wav";
    bool generateResult = ttsSystem->generateAudio("", outputFile);
    EXPECT_FALSE(generateResult);
    
    // Test with invalid output path
    generateResult = ttsSystem->generateAudio("Test message", "/invalid/path/test.wav");
    EXPECT_FALSE(generateResult);
    
    // Test with null pointers
    EXPECT_TRUE(ttsSystem->preprocessText("").empty());
    EXPECT_FALSE(ttsSystem->validateText(""));
}

/**
 * @test Test TTS thread safety
 */
TEST_F(TTSIntegration_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 10;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                string testText = "Thread " + to_string(t) + " iteration " + to_string(i);
                string outputFile = "thread_" + to_string(t) + "_" + to_string(i) + ".wav";
                
                // Generate audio
                bool generateResult = ttsSystem->generateAudio(testText, outputFile);
                
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

/**
 * @test Test TTS integration with ATIS
 */
TEST_F(TTSIntegration_Test, ATISIntegration) {
    // Test ATIS text generation
    string airportCode = "KJFK";
    string weatherInfo = "Wind 270 at 15 knots, visibility 10 miles, few clouds at 3000 feet";
    string runwayInfo = "Runway 04L/22R, Runway 04R/22L";
    
    string atisText = ttsSystem->generateATISText(airportCode, weatherInfo, runwayInfo);
    EXPECT_FALSE(atisText.empty());
    EXPECT_NE(atisText.find(airportCode), string::npos);
    EXPECT_NE(atisText.find(weatherInfo), string::npos);
    EXPECT_NE(atisText.find(runwayInfo), string::npos);
    
    // Test ATIS audio generation
    string outputFile = "atis_test.wav";
    bool generateResult = ttsSystem->generateATISAudio(airportCode, weatherInfo, runwayInfo, outputFile);
    EXPECT_TRUE(generateResult);
    
    // Test output file
    ifstream file(outputFile);
    EXPECT_TRUE(file.good());
    file.close();
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test TTS template processing
 */
TEST_F(TTSIntegration_Test, TemplateProcessing) {
    // Test template loading
    string templatePath = "../../../../fgcom-mumble/scripts/tts/atis_templates/standard_atis.txt";
    string templateContent = ttsSystem->loadTemplate(templatePath);
    EXPECT_FALSE(templateContent.empty());
    
    // Test template processing
    map<string, string> variables = {
        {"AIRPORT_CODE", "KJFK"},
        {"WIND_DIRECTION", "270"},
        {"WIND_SPEED", "15"},
        {"VISIBILITY", "10"},
        {"WEATHER_CONDITIONS", "few clouds"},
        {"TEMPERATURE", "22"},
        {"ALTIMETER", "29.92"},
        {"ATIS_LETTER", "A"}
    };
    
    string processedTemplate = ttsSystem->processTemplate(templateContent, variables);
    EXPECT_FALSE(processedTemplate.empty());
    EXPECT_NE(processedTemplate.find("KJFK"), string::npos);
    EXPECT_NE(processedTemplate.find("270"), string::npos);
    EXPECT_NE(processedTemplate.find("15"), string::npos);
}

/**
 * @test Test TTS configuration management
 */
TEST_F(TTSIntegration_Test, ConfigurationManagement) {
    // Test configuration saving
    EXPECT_TRUE(ttsSystem->saveConfiguration("test_tts_config.conf"));
    
    // Test configuration reset
    ttsSystem->resetConfiguration();
    EXPECT_TRUE(ttsSystem->isDefaultConfiguration());
    
    // Test configuration validation
    EXPECT_TRUE(ttsSystem->validateConfiguration());
    
    // Test configuration parameters
    EXPECT_FALSE(ttsSystem->getDefaultModel().empty());
    EXPECT_GT(ttsSystem->getSampleRate(), 0);
    EXPECT_GT(ttsSystem->getBitrate(), 0);
}

/**
 * @test Test TTS logging and monitoring
 */
TEST_F(TTSIntegration_Test, LoggingAndMonitoring) {
    // Test logging initialization
    EXPECT_TRUE(ttsSystem->initializeLogging());
    
    // Test log levels
    ttsSystem->setLogLevel("DEBUG");
    EXPECT_EQ(ttsSystem->getLogLevel(), "DEBUG");
    
    ttsSystem->setLogLevel("INFO");
    EXPECT_EQ(ttsSystem->getLogLevel(), "INFO");
    
    ttsSystem->setLogLevel("WARNING");
    EXPECT_EQ(ttsSystem->getLogLevel(), "WARNING");
    
    ttsSystem->setLogLevel("ERROR");
    EXPECT_EQ(ttsSystem->getLogLevel(), "ERROR");
    
    // Test monitoring
    EXPECT_TRUE(ttsSystem->startMonitoring());
    EXPECT_TRUE(ttsSystem->isMonitoring());
    
    // Test monitoring data
    map<string, string> monitoringData = ttsSystem->getMonitoringData();
    EXPECT_GT(monitoringData.size(), 0);
    
    // Test monitoring stop
    ttsSystem->stopMonitoring();
    EXPECT_FALSE(ttsSystem->isMonitoring());
}
