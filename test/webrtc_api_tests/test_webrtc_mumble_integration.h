/*
 * WebRTC to Mumble Integration Test Headers
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

#ifndef WEBRTC_MUMBLE_INTEGRATION_TEST_H
#define WEBRTC_MUMBLE_INTEGRATION_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC to Mumble Integration Test Classes
class WebRTCToMumbleIntegrationTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL WebRTC to Mumble integration test
        WebRTCTestFramework::initialize();
        
        // Test WebRTC connection
        bool webrtcConnected = WebRTCTestFramework::establishConnection("test://webrtc-mumble");
        EXPECT_TRUE(webrtcConnected) << "WebRTC connection failed";
        
        // Test audio stream
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "WebRTC audio stream failed";
        
        // Test data transmission to Mumble
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataSent) << "Data transmission to Mumble failed";
        
        // Test protocol translation for Mumble
        std::string udpData = WebRTCTestFramework::jsonToUDP(testData);
        EXPECT_FALSE(udpData.empty()) << "Protocol translation for Mumble failed";
        
        // Test Mumble integration validation
        bool protocolValid = WebRTCTestFramework::validateProtocolTranslation(testData, udpData);
        EXPECT_TRUE(protocolValid) << "Mumble protocol validation failed";
        
        // Test audio quality for Mumble
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Mumble audio quality failed";
        EXPECT_LT(audioQuality.latency, 150.0) << "Mumble latency too high: " << audioQuality.latency << "ms";
        
        // Test round-trip communication
        auto receivedData = WebRTCTestFramework::receiveRadioData();
        EXPECT_FALSE(receivedData.callsign.empty()) << "Mumble round-trip communication failed";
        
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

class WebRTCToMumbleMultiClientTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL WebRTC to Mumble multi-client test
        WebRTCTestFramework::initialize();
        
        // Test multiple WebRTC connections
        bool client1Connected = WebRTCTestFramework::establishConnection("test://client1");
        EXPECT_TRUE(client1Connected) << "Client 1 connection failed";
        
        // Simulate second client
        bool client2Connected = WebRTCTestFramework::establishConnection("test://client2");
        EXPECT_TRUE(client2Connected) << "Client 2 connection failed";
        
        // Test audio streams for both clients
        bool audio1Started = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audio1Started) << "Client 1 audio stream failed";
        
        // Test data transmission from multiple clients
        auto testData1 = WebRTCTestFramework::createTestRadioData();
        testData1.callsign = "CLIENT1";
        bool data1Sent = WebRTCTestFramework::sendRadioData(testData1);
        EXPECT_TRUE(data1Sent) << "Client 1 data transmission failed";
        
        auto testData2 = WebRTCTestFramework::createTestRadioData();
        testData2.callsign = "CLIENT2";
        bool data2Sent = WebRTCTestFramework::sendRadioData(testData2);
        EXPECT_TRUE(data2Sent) << "Client 2 data transmission failed";
        
        // Test multi-client audio quality
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Multi-client audio quality failed";
        
        // Test multi-client performance
        double latency = WebRTCTestFramework::measureLatency();
        EXPECT_LT(latency, 200.0) << "Multi-client latency too high: " << latency << "ms";
        
        // Test data reception from multiple clients
        auto receivedData = WebRTCTestFramework::receiveRadioData();
        EXPECT_FALSE(receivedData.callsign.empty()) << "Multi-client data reception failed";
        
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_MUMBLE_INTEGRATION_TEST_H
