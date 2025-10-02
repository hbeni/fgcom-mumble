/*
 * WebRTC Full Workflow Test Headers
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

#ifndef WEBRTC_FULL_WORKFLOW_TEST_H
#define WEBRTC_FULL_WORKFLOW_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Full Workflow Test Classes
class FullWorkflowTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL full workflow test
        WebRTCTestFramework::initialize();
        
        // Test complete WebRTC workflow
        bool connectionEstablished = WebRTCTestFramework::establishConnection("test://workflow");
        EXPECT_TRUE(connectionEstablished) << "Connection establishment failed";
        
        // Test audio stream
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Audio stream start failed";
        
        // Test data transmission
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataSent) << "Data transmission failed";
        
        // Test protocol translation
        std::string udpData = WebRTCTestFramework::jsonToUDP(testData);
        EXPECT_FALSE(udpData.empty()) << "Protocol translation failed";
        
        // Test round-trip conversion
        auto convertedData = WebRTCTestFramework::udpToJSON(udpData);
        EXPECT_EQ(convertedData.callsign, testData.callsign) 
            << "Round-trip conversion failed";
        
        // Test audio quality
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Audio quality check failed";
        
        // Test performance
        double latency = WebRTCTestFramework::measureLatency();
        EXPECT_LT(latency, 150.0) << "Latency too high: " << latency << "ms";
        
        // Test cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::closeConnection();
        
        auto finalState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(finalState, WebRTCConnectionState::DISCONNECTED) 
            << "Cleanup failed";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_FULL_WORKFLOW_TEST_H
