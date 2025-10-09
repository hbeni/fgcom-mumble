/**
 * @file test_atis_generation.cpp
 * @brief Test suite for ATIS Generation
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for ATIS generation,
 * including text processing, template handling, and audio generation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>

using namespace std;
using namespace testing;

/**
 * @class ATISGeneration_Test
 * @brief Test fixture for ATIS generation tests
 */
class ATISGeneration_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize ATIS generation system
        atisGenerator = new ATISGenerator();
        ASSERT_NE(atisGenerator, nullptr);
    }

    void TearDown() override {
        if (atisGenerator) {
            delete atisGenerator;
            atisGenerator = nullptr;
        }
    }

    ATISGenerator* atisGenerator = nullptr;
};

/**
 * @test Test ATIS generator initialization
 */
TEST_F(ATISGeneration_Test, Initialization) {
    EXPECT_TRUE(atisGenerator->isInitialized());
    EXPECT_FALSE(atisGenerator->getDefaultTemplate().empty());
    EXPECT_GT(atisGenerator->getUpdateInterval(), 0);
}

/**
 * @test Test ATIS text generation
 */
TEST_F(ATISGeneration_Test, TextGeneration) {
    // Test ATIS text generation
    string airportCode = "KJFK";
    string weatherInfo = "Wind 270 at 15 knots, visibility 10 miles, few clouds at 3000 feet";
    string runwayInfo = "Runway 04L/22R, Runway 04R/22L";
    
    string atisText = atisGenerator->generateATISText(airportCode, weatherInfo, runwayInfo);
    EXPECT_FALSE(atisText.empty());
    EXPECT_NE(atisText.find(airportCode), string::npos);
    EXPECT_NE(atisText.find(weatherInfo), string::npos);
    EXPECT_NE(atisText.find(runwayInfo), string::npos);
}

/**
 * @test Test ATIS template processing
 */
TEST_F(ATISGeneration_Test, TemplateProcessing) {
    // Test template loading
    string templatePath = "../../scripts/tts/atis_templates/standard_atis.txt";
    string templateContent = atisGenerator->loadTemplate(templatePath);
    EXPECT_FALSE(templateContent.empty());
    
    // Test template processing
    map<string, string> variables = {
        {"AIRPORT_CODE", "KJFK"},
        {"WEATHER", "Wind 270 at 15 knots"},
        {"RUNWAY", "Runway 04L/22R"}
    };
    
    string processedTemplate = atisGenerator->processTemplate(templateContent, variables);
    EXPECT_FALSE(processedTemplate.empty());
    EXPECT_NE(processedTemplate.find("KJFK"), string::npos);
    EXPECT_NE(processedTemplate.find("Wind 270 at 15 knots"), string::npos);
    EXPECT_NE(processedTemplate.find("Runway 04L/22R"), string::npos);
}

/**
 * @test Test ATIS audio generation
 */
TEST_F(ATISGeneration_Test, AudioGeneration) {
    // Test ATIS audio generation
    string airportCode = "KJFK";
    string weatherInfo = "Wind 270 at 15 knots, visibility 10 miles";
    string runwayInfo = "Runway 04L/22R";
    string outputFile = "atis_audio_test.wav";
    
    bool generateResult = atisGenerator->generateATISAudio(airportCode, weatherInfo, runwayInfo, outputFile);
    EXPECT_TRUE(generateResult);
    
    // Test output file
    ifstream file(outputFile);
    EXPECT_TRUE(file.good());
    file.close();
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test ATIS performance
 */
TEST_F(ATISGeneration_Test, Performance) {
    // Test ATIS generation performance
    auto start = chrono::high_resolution_clock::now();
    
    string airportCode = "KJFK";
    string weatherInfo = "Wind 270 at 15 knots, visibility 10 miles";
    string runwayInfo = "Runway 04L/22R";
    string outputFile = "atis_performance_test.wav";
    
    bool generateResult = atisGenerator->generateATISAudio(airportCode, weatherInfo, runwayInfo, outputFile);
    EXPECT_TRUE(generateResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    // ATIS generation should be reasonable (less than 10 seconds)
    EXPECT_LT(duration.count(), 10000);
    
    // Clean up
    remove(outputFile.c_str());
}

/**
 * @test Test ATIS error handling
 */
TEST_F(ATISGeneration_Test, ErrorHandling) {
    // Test with invalid airport code
    string invalidAirport = "";
    string weatherInfo = "Wind 270 at 15 knots";
    string runwayInfo = "Runway 04L/22R";
    string outputFile = "atis_error_test.wav";
    
    bool generateResult = atisGenerator->generateATISAudio(invalidAirport, weatherInfo, runwayInfo, outputFile);
    EXPECT_FALSE(generateResult);
    
    // Test with invalid output path
    generateResult = atisGenerator->generateATISAudio("KJFK", weatherInfo, runwayInfo, "/invalid/path/test.wav");
    EXPECT_FALSE(generateResult);
}

/**
 * @test Test ATIS thread safety
 */
TEST_F(ATISGeneration_Test, ThreadSafety) {
    const int numThreads = 4;
    const int iterationsPerThread = 5;
    vector<thread> threads;
    vector<bool> results(numThreads, true);
    
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([this, t, iterationsPerThread, &results]() {
            for (int i = 0; i < iterationsPerThread; i++) {
                string airportCode = "KJFK";
                string weatherInfo = "Wind 270 at 15 knots, visibility 10 miles";
                string runwayInfo = "Runway 04L/22R";
                string outputFile = "atis_thread_" + to_string(t) + "_" + to_string(i) + ".wav";
                
                bool generateResult = atisGenerator->generateATISAudio(airportCode, weatherInfo, runwayInfo, outputFile);
                
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
