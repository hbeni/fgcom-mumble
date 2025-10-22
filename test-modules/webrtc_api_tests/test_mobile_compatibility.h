/*
 * WebRTC Mobile Compatibility Test Headers
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

#ifndef WEBRTC_MOBILE_COMPATIBILITY_TEST_H
#define WEBRTC_MOBILE_COMPATIBILITY_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Mobile Compatibility Test Classes
class MobileCompatibilityTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL mobile compatibility test
        WebRTCTestFramework::initialize();
        
        // Test mobile connection establishment
        bool mobileConnected = WebRTCTestFramework::establishConnection("test://mobile");
        EXPECT_TRUE(mobileConnected) << "Mobile connection failed";
        
        // Test mobile audio constraints
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Mobile audio stream failed";
        
        // Test mobile performance
        auto startTime = std::chrono::high_resolution_clock::now();
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto mobileTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(dataSent) << "Mobile data transmission failed";
        EXPECT_LT(mobileTime.count(), 500) << "Mobile performance too slow: " << mobileTime.count() << "ms";
        
        // Test mobile audio quality
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Mobile audio quality failed";
        EXPECT_LT(audioQuality.latency, 200.0) << "Mobile latency too high: " << audioQuality.latency << "ms";
        
        // Test mobile bandwidth efficiency
        double bandwidth = WebRTCTestFramework::measureBandwidth();
        EXPECT_GT(bandwidth, 0.0) << "Mobile bandwidth measurement failed";
        EXPECT_LT(bandwidth, 256000.0) << "Mobile bandwidth usage too high: " << bandwidth << " bps";
        
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_MOBILE_COMPATIBILITY_TEST_H
