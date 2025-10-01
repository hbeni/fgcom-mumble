/*
 * WebRTC Test Framework
 * 
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
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

#ifndef WEBRTC_TEST_FRAMEWORK_H
#define WEBRTC_TEST_FRAMEWORK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

// WebRTC Test Configuration
struct WebRTCTestConfig {
    std::string serverUrl;
    std::string mumbleServerUrl;
    int mumbleServerPort;
    int udpPort;
    int testTimeout;
    double audioQualityThreshold;
    int maxLatency;
    std::string testResultsDir;
    std::string audioTestDir;
    std::string logDir;
};

// WebRTC Connection State
enum class WebRTCConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    FAILED
};

// Audio Quality Metrics
struct AudioQualityMetrics {
    double signalToNoiseRatio;
    double latency;
    double jitter;
    double packetLoss;
    double bandwidth;
    bool isValid;
};

// Radio Channel Structure
struct RadioChannel {
    std::string id;
    double frequency;
    bool ptt;
    int power;
    int volume;
    int squelch;
    bool operational;
};

// Radio Data Structure
struct RadioData {
    std::string callsign;
    double latitude;
    double longitude;
    double altitude;
    std::vector<RadioChannel> channels;
};

// WebRTC Test Framework Class
class WebRTCTestFramework {
public:
    static void initialize();
    static void cleanup();
    static WebRTCTestConfig& getConfig();
    
    // Connection management
    static bool establishConnection(const std::string& serverUrl);
    static void closeConnection();
    static WebRTCConnectionState getConnectionState();
    
    // Audio testing
    static bool startAudioStream();
    static void stopAudioStream();
    static AudioQualityMetrics measureAudioQuality();
    static bool validateAudioQuality(const AudioQualityMetrics& metrics);
    
    // Data transmission testing
    static bool sendRadioData(const RadioData& data);
    static RadioData receiveRadioData();
    static bool validateRadioData(const RadioData& data);
    
    // Protocol translation testing
    static std::string jsonToUDP(const std::string& jsonData);
    static std::string udpToJSON(const std::string& udpData);
    static bool validateProtocolTranslation(const std::string& input, const std::string& output);
    
    // Performance testing
    static double measureLatency();
    static double measureBandwidth();
    static bool validatePerformance(double latency, double bandwidth);
    
    // Error simulation
    static void simulateNetworkError();
    static void simulateAudioError();
    static void simulateConnectionLoss();
    static void restoreConnection();
    
    // Test utilities
    static std::string generateTestCallsign();
    static RadioData generateTestRadioData();
    static std::string generateTestJSON();
    static std::string generateTestUDP();
    
    // Helper functions for test classes
    static RadioData createTestRadioData();
    static std::string createTestJSON();
    static std::string createTestUDP();
    
    // Logging
    static void logTestResult(const std::string& testName, bool passed, const std::string& details = "");
    static void logAudioQuality(const AudioQualityMetrics& metrics);
    static void logPerformance(double latency, double bandwidth);
    
private:
    static WebRTCTestConfig config_;
    static WebRTCConnectionState connectionState_;
    static std::mutex frameworkMutex_;
    static std::condition_variable frameworkCV_;
    static bool isInitialized_;
};

// WebRTC Connection Test Base Class
class WebRTCConnectionTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        WebRTCTestFramework::initialize();
        ASSERT_TRUE(WebRTCTestFramework::establishConnection(WebRTCTestFramework::getConfig().serverUrl));
    }
    
    void TearDown() override {
        WebRTCTestFramework::closeConnection();
        WebRTCTestFramework::cleanup();
    }
    
    // Helper methods
    RadioData createTestRadioData() {
        return WebRTCTestFramework::generateTestRadioData();
    }
    
    std::string createTestJSON() {
        return WebRTCTestFramework::generateTestJSON();
    }
    
    std::string createTestUDP() {
        return WebRTCTestFramework::generateTestUDP();
    }
    
    bool waitForConnection(int timeoutMs = 5000) {
        auto start = std::chrono::high_resolution_clock::now();
        while (WebRTCTestFramework::getConnectionState() != WebRTCConnectionState::CONNECTED) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
            if (elapsed.count() > timeoutMs) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return true;
    }
};

// Audio Processing Test Base Class
class AudioProcessingTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        WebRTCTestFramework::initialize();
        ASSERT_TRUE(WebRTCTestFramework::establishConnection(WebRTCTestFramework::getConfig().serverUrl));
        ASSERT_TRUE(WebRTCTestFramework::startAudioStream());
    }
    
    void TearDown() override {
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::closeConnection();
        WebRTCTestFramework::cleanup();
    }
    
    AudioQualityMetrics measureAudioQuality() {
        return WebRTCTestFramework::measureAudioQuality();
    }
    
    bool validateAudioQuality(const AudioQualityMetrics& metrics) {
        return WebRTCTestFramework::validateAudioQuality(metrics);
    }
};

// Protocol Translation Test Base Class
class ProtocolTranslationTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        WebRTCTestFramework::initialize();
    }
    
    void TearDown() override {
        WebRTCTestFramework::cleanup();
    }
    
    std::string translateJSONToUDP(const std::string& jsonData) {
        return WebRTCTestFramework::jsonToUDP(jsonData);
    }
    
    std::string translateUDPToJSON(const std::string& udpData) {
        return WebRTCTestFramework::udpToJSON(udpData);
    }
    
    bool validateTranslation(const std::string& input, const std::string& output) {
        return WebRTCTestFramework::validateProtocolTranslation(input, output);
    }
};

// Performance Test Base Class
class PerformanceTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        WebRTCTestFramework::initialize();
        ASSERT_TRUE(WebRTCTestFramework::establishConnection(WebRTCTestFramework::getConfig().serverUrl));
    }
    
    void TearDown() override {
        WebRTCTestFramework::closeConnection();
        WebRTCTestFramework::cleanup();
    }
    
    double measureLatency() {
        return WebRTCTestFramework::measureLatency();
    }
    
    double measureBandwidth() {
        return WebRTCTestFramework::measureBandwidth();
    }
    
    bool validatePerformance(double latency, double bandwidth) {
        return WebRTCTestFramework::validatePerformance(latency, bandwidth);
    }
};

// Mock WebRTC Connection for testing
class MockWebRTCConnection {
public:
    MOCK_METHOD(bool, connect, (const std::string& serverUrl));
    MOCK_METHOD(void, disconnect, ());
    MOCK_METHOD(WebRTCConnectionState, getState, ());
    MOCK_METHOD(bool, sendData, (const std::string& data));
    MOCK_METHOD(std::string, receiveData, ());
    MOCK_METHOD(bool, startAudio, ());
    MOCK_METHOD(void, stopAudio, ());
    MOCK_METHOD(AudioQualityMetrics, getAudioQuality, ());
};

// Mock Audio Processor for testing
class MockAudioProcessor {
public:
    MOCK_METHOD(bool, processAudio, (const std::vector<uint8_t>& input, std::vector<uint8_t>& output));
    MOCK_METHOD(bool, convertCodec, (const std::string& fromCodec, const std::string& toCodec));
    MOCK_METHOD(AudioQualityMetrics, analyzeQuality, (const std::vector<uint8_t>& audioData));
    MOCK_METHOD(double, measureLatency, ());
    MOCK_METHOD(double, measureJitter, ());
};

// Mock Protocol Translator for testing
class MockProtocolTranslator {
public:
    MOCK_METHOD(std::string, jsonToUDP, (const std::string& jsonData));
    MOCK_METHOD(std::string, udpToJSON, (const std::string& udpData));
    MOCK_METHOD(bool, validateJSON, (const std::string& jsonData));
    MOCK_METHOD(bool, validateUDP, (const std::string& udpData));
    MOCK_METHOD(RadioData, parseJSON, (const std::string& jsonData));
    MOCK_METHOD(std::string, serializeJSON, (const RadioData& data));
};

// Test Data Generators
class WebRTCTestDataGenerator {
public:
    static RadioData generateRadioData(const std::string& callsign = "TEST123");
    static std::string generateJSONData(const RadioData& data);
    static std::string generateUDPData(const RadioData& data);
    static std::vector<uint8_t> generateAudioData(size_t length = 1024);
    static AudioQualityMetrics generateAudioQualityMetrics();
    
private:
    static int testDataCounter_;
};

// Test Assertions
#define ASSERT_WEBRTC_CONNECTION(connection) \
    ASSERT_EQ(WebRTCTestFramework::getConnectionState(), WebRTCConnectionState::CONNECTED)

#define ASSERT_AUDIO_QUALITY(metrics) \
    ASSERT_TRUE(WebRTCTestFramework::validateAudioQuality(metrics))

#define ASSERT_PROTOCOL_TRANSLATION(input, output) \
    ASSERT_TRUE(WebRTCTestFramework::validateProtocolTranslation(input, output))

#define ASSERT_PERFORMANCE(latency, bandwidth) \
    ASSERT_TRUE(WebRTCTestFramework::validatePerformance(latency, bandwidth))

// Test Utilities
namespace WebRTCTestUtils {
    std::string formatTestResult(const std::string& testName, bool passed, const std::string& details = "");
    void saveAudioTestData(const std::vector<uint8_t>& data, const std::string& filename);
    void savePerformanceData(double latency, double bandwidth, const std::string& filename);
    std::string generateTestReport(const std::string& testName, const std::map<std::string, std::string>& results);
}

#endif // WEBRTC_TEST_FRAMEWORK_H
