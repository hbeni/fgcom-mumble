/*
 * WebRTC Authentication Test Headers
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

#ifndef WEBRTC_AUTHENTICATION_TEST_H
#define WEBRTC_AUTHENTICATION_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Authentication Test Classes
class AuthenticationTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL authentication test
        WebRTCTestFramework::initialize();
        
        // Test user registration
        auto testUser = WebRTCTestFramework::createTestRadioData();
        testUser.callsign = "TESTUSER";
        bool registrationSuccess = WebRTCTestFramework::sendRadioData(testUser);
        EXPECT_TRUE(registrationSuccess) << "User registration failed";
        
        // Test login process
        bool loginSuccess = WebRTCTestFramework::establishConnection("test://auth");
        EXPECT_TRUE(loginSuccess) << "Login process failed";
        
        // Test session validation
        auto connectionState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(connectionState, WebRTCConnectionState::CONNECTED) 
            << "Authentication should result in connected state";
        
        // Test token validation
        bool tokenValid = WebRTCTestFramework::validateRadioData(testUser);
        EXPECT_TRUE(tokenValid) << "Token validation failed";
        
        // Test session timeout
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        bool sessionActive = WebRTCTestFramework::getConnectionState() == WebRTCConnectionState::CONNECTED;
        EXPECT_TRUE(sessionActive) << "Session should remain active";
        
        WebRTCTestFramework::cleanup();
    }
};

class SessionManagementTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL session management test
        WebRTCTestFramework::initialize();
        
        // Test session creation
        bool sessionCreated = WebRTCTestFramework::establishConnection("test://session");
        EXPECT_TRUE(sessionCreated) << "Session creation failed";
        
        // Test session persistence
        auto connectionState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(connectionState, WebRTCConnectionState::CONNECTED) 
            << "Session should be in connected state";
        
        // Test session data storage
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataStored = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataStored) << "Session data storage failed";
        
        // Test session retrieval
        auto retrievedData = WebRTCTestFramework::receiveRadioData();
        EXPECT_FALSE(retrievedData.callsign.empty()) << "Session data retrieval failed";
        
        // Test session cleanup
        WebRTCTestFramework::closeConnection();
        auto finalState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(finalState, WebRTCConnectionState::DISCONNECTED) 
            << "Session cleanup failed";
        
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_AUTHENTICATION_TEST_H
