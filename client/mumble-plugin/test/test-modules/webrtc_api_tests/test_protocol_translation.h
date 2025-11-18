/*
 * WebRTC Protocol Translation Test Headers
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

#ifndef WEBRTC_PROTOCOL_TRANSLATION_TEST_H
#define WEBRTC_PROTOCOL_TRANSLATION_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Protocol Translation Test Classes
class ProtocolTranslationTest : public ProtocolTranslationTestBase {
public:
    void SetUp() override {
        ProtocolTranslationTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL protocol translation test
        WebRTCTestFramework::initialize();
        
        // Test JSON to UDP conversion
        auto testRadioData = WebRTCTestFramework::createTestRadioData();
        std::string udpData = WebRTCTestFramework::jsonToUDP(testRadioData);
        
        EXPECT_FALSE(udpData.empty()) << "JSON to UDP conversion failed";
        EXPECT_NE(udpData.find("callsign="), std::string::npos) 
            << "UDP data should contain callsign field";
        EXPECT_NE(udpData.find("lat="), std::string::npos) 
            << "UDP data should contain latitude field";
        EXPECT_NE(udpData.find("lon="), std::string::npos) 
            << "UDP data should contain longitude field";
        
        // Test UDP to JSON conversion
        auto convertedRadioData = WebRTCTestFramework::udpToJSON(udpData);
        EXPECT_EQ(convertedRadioData.callsign, testRadioData.callsign) 
            << "Callsign not preserved in round-trip conversion";
        EXPECT_DOUBLE_EQ(convertedRadioData.latitude, testRadioData.latitude) 
            << "Latitude not preserved in round-trip conversion";
        EXPECT_DOUBLE_EQ(convertedRadioData.longitude, testRadioData.longitude) 
            << "Longitude not preserved in round-trip conversion";
        
        // Test channel data conversion
        EXPECT_EQ(convertedRadioData.channels.size(), testRadioData.channels.size()) 
            << "Channel count not preserved";
        
        for (size_t i = 0; i < testRadioData.channels.size(); ++i) {
            EXPECT_DOUBLE_EQ(convertedRadioData.channels[i].frequency, testRadioData.channels[i].frequency)
                << "Channel " << i << " frequency not preserved";
            EXPECT_EQ(convertedRadioData.channels[i].power, testRadioData.channels[i].power)
                << "Channel " << i << " power not preserved";
            EXPECT_EQ(convertedRadioData.channels[i].ptt, testRadioData.channels[i].ptt)
                << "Channel " << i << " PTT state not preserved";
        }
        
        // Test protocol validation
        bool isValid = WebRTCTestFramework::validateProtocolTranslation(testRadioData, udpData);
        EXPECT_TRUE(isValid) << "Protocol translation validation failed";
        
        // Test performance
        auto startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000; ++i) {
            auto testData = WebRTCTestFramework::createTestRadioData();
            std::string udp = WebRTCTestFramework::jsonToUDP(testData);
            auto json = WebRTCTestFramework::udpToJSON(udp);
        }
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
        
        EXPECT_LT(duration.count(), 100000) << "Protocol translation too slow: " << duration.count() << "μs for 1000 conversions";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_PROTOCOL_TRANSLATION_TEST_H
