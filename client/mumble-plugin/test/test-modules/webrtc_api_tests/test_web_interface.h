/*
 * WebRTC Web Interface Test Headers
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

#ifndef WEBRTC_WEB_INTERFACE_TEST_H
#define WEBRTC_WEB_INTERFACE_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Web Interface Test Classes
class WebInterfaceTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL web interface test
        WebRTCTestFramework::initialize();
        
        // Test interface initialization
        bool interfaceInitialized = WebRTCTestFramework::establishConnection("test://interface");
        EXPECT_TRUE(interfaceInitialized) << "Web interface initialization failed";
        
        // Test radio controls
        auto testData = WebRTCTestFramework::createTestRadioData();
        testData.channels[0].frequency = 123.45;
        testData.channels[0].power = 100;
        testData.channels[0].volume = 80;
        
        bool controlsWorking = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(controlsWorking) << "Radio controls not working";
        
        // Test interface responsiveness
        auto startTime = std::chrono::high_resolution_clock::now();
        auto responseData = WebRTCTestFramework::receiveRadioData();
        auto endTime = std::chrono::high_resolution_clock::now();
        auto responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_FALSE(responseData.callsign.empty()) << "Interface response failed";
        EXPECT_LT(responseTime.count(), 100) << "Interface too slow: " << responseTime.count() << "ms";
        
        // Test multiple radio channels
        testData.channels.push_back(WebRTCTestFramework::createTestRadioData().channels[0]);
        testData.channels[1].frequency = 456.78;
        testData.channels[1].power = 50;
        
        bool multiChannelWorking = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(multiChannelWorking) << "Multi-channel interface failed";
        
        WebRTCTestFramework::cleanup();
    }
};

class MapIntegrationTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL map integration test
        WebRTCTestFramework::initialize();
        
        // Test map initialization
        bool mapInitialized = WebRTCTestFramework::establishConnection("test://map");
        EXPECT_TRUE(mapInitialized) << "Map initialization failed";
        
        // Test position data
        auto testData = WebRTCTestFramework::createTestRadioData();
        testData.latitude = 40.7128;
        testData.longitude = -74.0060;
        testData.altitude = 1000.0;
        
        bool positionSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(positionSent) << "Position data transmission failed";
        
        // Test position validation
        EXPECT_GE(testData.latitude, -90.0) << "Invalid latitude";
        EXPECT_LE(testData.latitude, 90.0) << "Invalid latitude";
        EXPECT_GE(testData.longitude, -180.0) << "Invalid longitude";
        EXPECT_LE(testData.longitude, 180.0) << "Invalid longitude";
        EXPECT_GE(testData.altitude, 0.0) << "Invalid altitude";
        
        // Test map responsiveness
        auto startTime = std::chrono::high_resolution_clock::now();
        auto mapResponse = WebRTCTestFramework::receiveRadioData();
        auto endTime = std::chrono::high_resolution_clock::now();
        auto mapTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_FALSE(mapResponse.callsign.empty()) << "Map response failed";
        EXPECT_LT(mapTime.count(), 200) << "Map too slow: " << mapTime.count() << "ms";
        
        // Test coordinate precision
        EXPECT_DOUBLE_EQ(mapResponse.latitude, testData.latitude) << "Latitude precision lost";
        EXPECT_DOUBLE_EQ(mapResponse.longitude, testData.longitude) << "Longitude precision lost";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_WEB_INTERFACE_TEST_H
