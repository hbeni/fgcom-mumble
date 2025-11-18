/*
 * WebRTC Error Recovery Test Headers
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

#ifndef WEBRTC_ERROR_RECOVERY_TEST_H
#define WEBRTC_ERROR_RECOVERY_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Error Recovery Test Classes
class ErrorRecoveryTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL error recovery test
        WebRTCTestFramework::initialize();
        
        // Test connection establishment
        bool connectionEstablished = WebRTCTestFramework::establishConnection("test://errorrecovery");
        EXPECT_TRUE(connectionEstablished) << "Initial connection failed";
        
        // Test audio stream
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Audio stream start failed";
        
        // Test error simulation
        WebRTCTestFramework::simulateNetworkError();
        
        // Test connection recovery
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        bool reconnected = WebRTCTestFramework::establishConnection("test://errorrecovery");
        EXPECT_TRUE(reconnected) << "Connection recovery failed";
        
        // Test audio recovery
        bool audioRecovered = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioRecovered) << "Audio recovery failed";
        
        // Test data transmission after recovery
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataSent) << "Data transmission after recovery failed";
        
        // Test performance after recovery
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Audio quality after recovery failed";
        
        // Test final cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::closeConnection();
        
        auto finalState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(finalState, WebRTCConnectionState::DISCONNECTED) 
            << "Final cleanup failed";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_ERROR_RECOVERY_TEST_H
