/*
 * WebRTC Multi-Client Test Headers
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

#ifndef WEBRTC_MULTI_CLIENT_TEST_H
#define WEBRTC_MULTI_CLIENT_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Multi-Client Test Classes
class MultiClientTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL multi-client test
        WebRTCTestFramework::initialize();
        
        // Test multiple client connections
        bool client1Connected = WebRTCTestFramework::establishConnection("test://multi1");
        EXPECT_TRUE(client1Connected) << "Multi-client 1 connection failed";
        
        bool client2Connected = WebRTCTestFramework::establishConnection("test://multi2");
        EXPECT_TRUE(client2Connected) << "Multi-client 2 connection failed";
        
        // Test audio streams for multiple clients
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Multi-client audio stream failed";
        
        // Test concurrent data transmission
        auto testData1 = WebRTCTestFramework::createTestRadioData();
        testData1.callsign = "MULTI1";
        bool data1Sent = WebRTCTestFramework::sendRadioData(testData1);
        EXPECT_TRUE(data1Sent) << "Multi-client 1 data transmission failed";
        
        auto testData2 = WebRTCTestFramework::createTestRadioData();
        testData2.callsign = "MULTI2";
        bool data2Sent = WebRTCTestFramework::sendRadioData(testData2);
        EXPECT_TRUE(data2Sent) << "Multi-client 2 data transmission failed";
        
        // Test multi-client audio quality
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Multi-client audio quality failed";
        
        // Test multi-client performance
        double latency = WebRTCTestFramework::measureLatency();
        EXPECT_LT(latency, 250.0) << "Multi-client latency too high: " << latency << "ms";
        
        // Test bandwidth under multi-client load
        double bandwidth = WebRTCTestFramework::measureBandwidth();
        EXPECT_GT(bandwidth, 0.0) << "Multi-client bandwidth measurement failed";
        
        // Test data reception from multiple clients
        auto receivedData = WebRTCTestFramework::receiveRadioData();
        EXPECT_FALSE(receivedData.callsign.empty()) << "Multi-client data reception failed";
        
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_MULTI_CLIENT_TEST_H
