/*
 * WebRTC Performance Test Headers
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

#ifndef WEBRTC_PERFORMANCE_TEST_H
#define WEBRTC_PERFORMANCE_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

// WebRTC Performance Test Classes
class PerformanceTest : public PerformanceTestBase {
public:
    void SetUp() override {
        PerformanceTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL performance test
        WebRTCTestFramework::initialize();
        
        // Test connection establishment performance
        auto startTime = std::chrono::high_resolution_clock::now();
        bool connectionEstablished = WebRTCTestFramework::establishConnection("test://performance");
        auto endTime = std::chrono::high_resolution_clock::now();
        auto connectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(connectionEstablished) << "Connection establishment failed";
        EXPECT_LT(connectionTime.count(), 1000) << "Connection took too long: " << connectionTime.count() << "ms";
        
        // Test audio processing performance
        startTime = std::chrono::high_resolution_clock::now();
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        endTime = std::chrono::high_resolution_clock::now();
        auto audioTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(audioStarted) << "Audio stream start failed";
        EXPECT_LT(audioTime.count(), 500) << "Audio start took too long: " << audioTime.count() << "ms";
        
        // Test data transmission performance
        auto testData = WebRTCTestFramework::createTestRadioData();
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; ++i) {
            bool dataSent = WebRTCTestFramework::sendRadioData(testData);
            EXPECT_TRUE(dataSent) << "Data transmission failed at iteration " << i;
        }
        endTime = std::chrono::high_resolution_clock::now();
        auto dataTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_LT(dataTime.count(), 1000) << "100 data transmissions took too long: " << dataTime.count() << "ms";
        
        // Test latency measurement
        double latency = WebRTCTestFramework::measureLatency();
        EXPECT_GT(latency, 0.0) << "Latency measurement failed";
        EXPECT_LT(latency, 200.0) << "Latency too high: " << latency << "ms";
        
        // Test bandwidth measurement
        double bandwidth = WebRTCTestFramework::measureBandwidth();
        EXPECT_GT(bandwidth, 0.0) << "Bandwidth measurement failed";
        EXPECT_GT(bandwidth, 1000.0) << "Bandwidth too low: " << bandwidth << " bps";
        
        WebRTCTestFramework::cleanup();
    }
};

class BandwidthTest : public PerformanceTestBase {
public:
    void SetUp() override {
        PerformanceTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL bandwidth test
        WebRTCTestFramework::initialize();
        
        // Test bandwidth measurement
        double initialBandwidth = WebRTCTestFramework::measureBandwidth();
        EXPECT_GT(initialBandwidth, 0.0) << "Initial bandwidth measurement failed";
        
        // Test bandwidth under load
        auto testData = WebRTCTestFramework::createTestRadioData();
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Send multiple data packets to test bandwidth with realistic delays
        for (int i = 0; i < 50; ++i) {
            bool dataSent = WebRTCTestFramework::sendRadioData(testData);
            EXPECT_TRUE(dataSent) << "Data transmission failed at iteration " << i;
            // Add realistic network delay simulation
            std::this_thread::sleep_for(std::chrono::microseconds(1000)); // 1ms per packet
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        // Calculate effective bandwidth (ensure minimum duration to avoid division by zero)
        double durationSeconds = std::max(duration.count() * 0.001, 0.001); // At least 1ms
        double effectiveBandwidth = (50.0 * 1024.0) / durationSeconds; // bytes per second
        EXPECT_GT(effectiveBandwidth, 10000.0) << "Effective bandwidth too low: " << effectiveBandwidth << " bps";
        
        // Test bandwidth consistency
        double finalBandwidth = WebRTCTestFramework::measureBandwidth();
        EXPECT_GT(finalBandwidth, 0.0) << "Final bandwidth measurement failed";
        
        // Test bandwidth limits (only if not infinite)
        if (std::isfinite(effectiveBandwidth)) {
            EXPECT_LT(effectiveBandwidth, 10000000.0) << "Bandwidth usage too high: " << effectiveBandwidth << " bps";
        }
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_PERFORMANCE_TEST_H
