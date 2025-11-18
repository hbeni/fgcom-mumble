/*
 * WebRTC Cross-Platform Test Headers
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

#ifndef WEBRTC_CROSS_PLATFORM_TEST_H
#define WEBRTC_CROSS_PLATFORM_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Cross-Platform Test Classes
class CrossPlatformTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL cross-platform test
        WebRTCTestFramework::initialize();
        
        // Test cross-platform connection
        bool crossPlatformConnected = WebRTCTestFramework::establishConnection("test://crossplatform");
        EXPECT_TRUE(crossPlatformConnected) << "Cross-platform connection failed";
        
        // Test cross-platform audio
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Cross-platform audio failed";
        
        // Test cross-platform data transmission
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataSent) << "Cross-platform data transmission failed";
        
        // Test cross-platform protocol compatibility
        std::string udpData = WebRTCTestFramework::jsonToUDP(testData);
        EXPECT_FALSE(udpData.empty()) << "Cross-platform protocol translation failed";
        
        auto convertedData = WebRTCTestFramework::udpToJSON(udpData);
        EXPECT_EQ(convertedData.callsign, testData.callsign) 
            << "Cross-platform round-trip conversion failed";
        
        // Test cross-platform performance
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Cross-platform audio quality failed";
        
        double latency = WebRTCTestFramework::measureLatency();
        EXPECT_LT(latency, 300.0) << "Cross-platform latency too high: " << latency << "ms";
        
        // Test cross-platform cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::closeConnection();
        
        auto finalState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(finalState, WebRTCConnectionState::DISCONNECTED) 
            << "Cross-platform cleanup failed";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_CROSS_PLATFORM_TEST_H
