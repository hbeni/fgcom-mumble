/*
 * WebRTC API Tests - Main Test Runner
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

// WebRTC API Test Framework
#include "webrtc_test_framework.h"

// Test modules
#include "test_webrtc_connection.h"
#include "test_protocol_translation.h"
#include "test_audio_processing.h"
#include "test_web_interface.h"
#include "test_authentication.h"
#include "test_webrtc_mumble_integration.h"
#include "test_multi_client.h"
#include "test_audio_quality.h"
#include "test_performance.h"
#include "test_full_workflow.h"
#include "test_mobile_compatibility.h"
#include "test_cross_platform.h"
#include "test_error_recovery.h"

using namespace testing;

// Global test configuration
WebRTCTestConfig g_testConfig;

// Test environment setup
class WebRTCAPITestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        std::cout << "Setting up WebRTC API test environment..." << std::endl;
        
        // Initialize test configuration
        g_testConfig.serverUrl = "ws://localhost:3000";
        g_testConfig.mumbleServerUrl = "localhost";
        g_testConfig.mumbleServerPort = 64738;
        g_testConfig.udpPort = 16661;
        g_testConfig.testTimeout = 30000; // 30 seconds
        g_testConfig.audioQualityThreshold = 0.8;
        g_testConfig.maxLatency = 100; // 100ms
        
        // Create test directories
        g_testConfig.testResultsDir = "test_results";
        g_testConfig.audioTestDir = "test_results/audio";
        g_testConfig.logDir = "test_results/logs";
        
        int result = std::system("mkdir -p test_results test_results/audio test_results/logs");
        (void)result; // Suppress unused result warning
        
        // Initialize WebRTC test framework
        WebRTCTestFramework::initialize();
        
        std::cout << "WebRTC API test environment ready." << std::endl;
    }
    
    void TearDown() override {
        std::cout << "Tearing down WebRTC API test environment..." << std::endl;
        
        // Cleanup test framework
        WebRTCTestFramework::cleanup();
        
        std::cout << "WebRTC API test environment cleanup complete." << std::endl;
    }
};

// Custom test listener for WebRTC-specific reporting
class WebRTCTestListener : public ::testing::EmptyTestEventListener {
public:
    void OnTestStart(const ::testing::TestInfo& test_info) override {
        std::cout << "\n[WebRTC] Starting test: " << test_info.name() << std::endl;
        test_start_time_ = std::chrono::high_resolution_clock::now();
    }
    
    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - test_start_time_);
        
        std::cout << "[WebRTC] Test " << test_info.name() 
                  << " completed in " << duration.count() << "ms" << std::endl;
        
        // Log test results
        logTestResult(test_info, duration.count());
    }
    
    void OnTestPartResult(const ::testing::TestPartResult& result) override {
        if (result.failed()) {
            std::cout << "[WebRTC] Test failure: " << result.summary() << std::endl;
        }
    }
    
private:
    std::chrono::high_resolution_clock::time_point test_start_time_;
    
    void logTestResult(const ::testing::TestInfo& test_info, long duration_ms) {
        std::ofstream log_file(g_testConfig.logDir + "/test_results.log", std::ios::app);
        if (log_file.is_open()) {
            log_file << "[" << std::chrono::system_clock::now().time_since_epoch().count() << "] "
                     << test_info.test_case_name() << "." << test_info.name() 
                     << " - Duration: " << duration_ms << "ms" << std::endl;
            log_file.close();
        }
    }
};

// Test suite registration
void registerWebRTCTestSuites() {
    // Register test suites
    ::testing::RegisterTest(
        "WebRTCConnection", "BasicConnection", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebRTCConnectionTest(); }
    );
    
    ::testing::RegisterTest(
        "WebRTCConnection", "Signaling", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebRTCSignalingTest(); }
    );
    
    ::testing::RegisterTest(
        "WebRTCConnection", "AudioStream", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebRTCAudioStreamTest(); }
    );
    
    ::testing::RegisterTest(
        "ProtocolTranslation", "JSONToUDP", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new ProtocolTranslationTest(); }
    );
    
    ::testing::RegisterTest(
        "ProtocolTranslation", "UDPToJSON", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new ProtocolTranslationTest(); }
    );
    
    ::testing::RegisterTest(
        "AudioProcessing", "CodecConversion", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new AudioProcessingTest(); }
    );
    
    ::testing::RegisterTest(
        "AudioProcessing", "QualityAnalysis", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new AudioQualityTest(); }
    );
    
    ::testing::RegisterTest(
        "WebInterface", "RadioControls", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebInterfaceTest(); }
    );
    
    ::testing::RegisterTest(
        "WebInterface", "MapIntegration", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new MapIntegrationTest(); }
    );
    
    ::testing::RegisterTest(
        "Authentication", "UserLogin", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new AuthenticationTest(); }
    );
    
    ::testing::RegisterTest(
        "Authentication", "SessionManagement", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new SessionManagementTest(); }
    );
    
    ::testing::RegisterTest(
        "Integration", "WebRTCToMumble", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebRTCToMumbleIntegrationTest(); }
    );
    
    ::testing::RegisterTest(
        "Integration", "MultiClient", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new WebRTCToMumbleMultiClientTest(); }
    );
    
    ::testing::RegisterTest(
        "Performance", "Latency", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new PerformanceTest(); }
    );
    
    ::testing::RegisterTest(
        "Performance", "Bandwidth", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new BandwidthTest(); }
    );
    
    ::testing::RegisterTest(
        "EndToEnd", "FullWorkflow", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new FullWorkflowTest(); }
    );
    
    ::testing::RegisterTest(
        "Mobile", "TouchControls", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new MobileCompatibilityTest(); }
    );
    
    ::testing::RegisterTest(
        "CrossPlatform", "BrowserCompatibility", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new CrossPlatformTest(); }
    );
    
    ::testing::RegisterTest(
        "ErrorRecovery", "ConnectionLoss", nullptr, nullptr,
        __FILE__, __LINE__,
        []() -> ::testing::Test* { return new ErrorRecoveryTest(); }
    );
}

int main(int argc, char** argv) {
    std::cout << "=== FGCom-mumble WebRTC API Test Suite ===" << std::endl;
    std::cout << "Testing WebRTC integration for web browser clients" << std::endl;
    std::cout << "================================================" << std::endl;
    
    // Initialize Google Test
    ::testing::InitGoogleTest(&argc, argv);
    
    // Initialize Google Mock
    ::testing::InitGoogleMock(&argc, argv);
    
    // Set up test environment
    ::testing::AddGlobalTestEnvironment(new WebRTCAPITestEnvironment());
    
    // Add custom test listener
    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new WebRTCTestListener());
    
    // Register WebRTC test suites
    registerWebRTCTestSuites();
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--webrtc-only") {
            ::testing::GTEST_FLAG(filter) = "*WebRTC*";
        } else if (arg == "--connection-only") {
            ::testing::GTEST_FLAG(filter) = "*Connection*";
        } else if (arg == "--audio-only") {
            ::testing::GTEST_FLAG(filter) = "*Audio*";
        } else if (arg == "--protocol-only") {
            ::testing::GTEST_FLAG(filter) = "*Protocol*";
        } else if (arg == "--integration-only") {
            ::testing::GTEST_FLAG(filter) = "*Integration*";
        } else if (arg == "--performance-only") {
            ::testing::GTEST_FLAG(filter) = "*Performance*";
        } else if (arg == "--mobile-only") {
            ::testing::GTEST_FLAG(filter) = "*Mobile*";
        } else if (arg == "--e2e-only") {
            ::testing::GTEST_FLAG(filter) = "*EndToEnd*";
        }
    }
    
    // Run tests
    int result = RUN_ALL_TESTS();
    
    // Generate test report
    if (result == 0) {
        std::cout << "\n=== WebRTC API Tests PASSED ===" << std::endl;
    } else {
        std::cout << "\n=== WebRTC API Tests FAILED ===" << std::endl;
    }
    
    return result;
}
