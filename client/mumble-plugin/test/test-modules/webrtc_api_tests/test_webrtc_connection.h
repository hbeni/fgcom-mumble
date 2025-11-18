/*
 * WebRTC Connection Test Headers
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

#ifndef WEBRTC_CONNECTION_TEST_H
#define WEBRTC_CONNECTION_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Connection Test Classes
class WebRTCConnectionTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL WebRTC connection test
        WebRTCTestFramework::initialize();
        
        // Test WebRTC peer connection creation
        auto config = WebRTCTestFramework::getConfig();
        bool connectionEstablished = WebRTCTestFramework::establishConnection(config.serverUrl);
        
        EXPECT_TRUE(connectionEstablished) << "Failed to establish WebRTC connection";
        
        // Test connection state
        auto connectionState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(connectionState, WebRTCConnectionState::CONNECTED) 
            << "WebRTC connection should be in CONNECTED state";
        
        // Test audio stream
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Failed to start audio stream";
        
        // Test data channel
        auto testData = WebRTCTestFramework::createTestRadioData();
        bool dataSent = WebRTCTestFramework::sendRadioData(testData);
        EXPECT_TRUE(dataSent) << "Failed to send radio data via WebRTC";
        
        // Cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::closeConnection();
        WebRTCTestFramework::cleanup();
    }
};

class WebRTCSignalingTest : public WebRTCConnectionTestBase {
public:
    void SetUp() override {
        WebRTCConnectionTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL WebRTC signaling test
        WebRTCTestFramework::initialize();
        
        // Test offer/answer exchange
        auto config = WebRTCTestFramework::getConfig();
        bool connectionEstablished = WebRTCTestFramework::establishConnection(config.serverUrl);
        EXPECT_TRUE(connectionEstablished) << "Failed to establish connection for signaling test";
        
        // Test ICE candidate handling
        bool iceCandidatesHandled = WebRTCTestFramework::handleIceCandidates();
        EXPECT_TRUE(iceCandidatesHandled) << "Failed to handle ICE candidates";
        
        // Test signaling state
        auto connectionState = WebRTCTestFramework::getConnectionState();
        EXPECT_EQ(connectionState, WebRTCConnectionState::CONNECTED) 
            << "Signaling should result in CONNECTED state";
        
        // Test data channel creation
        bool dataChannelCreated = WebRTCTestFramework::createDataChannel();
        EXPECT_TRUE(dataChannelCreated) << "Failed to create data channel";
        
        // Test signaling performance
        auto startTime = std::chrono::high_resolution_clock::now();
        bool signalingComplete = WebRTCTestFramework::completeSignaling();
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(signalingComplete) << "Signaling did not complete successfully";
        EXPECT_LT(duration.count(), 5000) << "Signaling took too long: " << duration.count() << "ms";
        
        // Cleanup
        WebRTCTestFramework::closeConnection();
        WebRTCTestFramework::cleanup();
    }
};

class WebRTCAudioStreamTest : public AudioProcessingTestBase {
public:
    void SetUp() override {
        AudioProcessingTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL WebRTC audio stream test
        WebRTCTestFramework::initialize();
        
        // Test audio stream creation
        bool audioStreamStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStreamStarted) << "Failed to start audio stream";
        
        // Test audio quality
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Audio quality measurement failed";
        EXPECT_GT(audioQuality.signalToNoiseRatio, 20.0) 
            << "Signal-to-noise ratio too low: " << audioQuality.signalToNoiseRatio;
        EXPECT_LT(audioQuality.latency, 100.0) 
            << "Audio latency too high: " << audioQuality.latency << "ms";
        EXPECT_LT(audioQuality.jitter, 50.0) 
            << "Audio jitter too high: " << audioQuality.jitter << "ms";
        
        // Test audio codec
        bool codecSupported = WebRTCTestFramework::testAudioCodec();
        EXPECT_TRUE(codecSupported) << "Audio codec not supported";
        
        // Test audio level monitoring
        double audioLevel = WebRTCTestFramework::getAudioLevel();
        EXPECT_GE(audioLevel, 0.0) << "Audio level should be non-negative";
        EXPECT_LE(audioLevel, 100.0) << "Audio level should not exceed 100%";
        
        // Test audio stream performance
        auto startTime = std::chrono::high_resolution_clock::now();
        bool audioProcessingWorking = WebRTCTestFramework::testAudioProcessing();
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(audioProcessingWorking) << "Audio processing failed";
        EXPECT_LT(duration.count(), 1000) << "Audio processing took too long: " << duration.count() << "ms";
        
        // Cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_CONNECTION_TEST_H
