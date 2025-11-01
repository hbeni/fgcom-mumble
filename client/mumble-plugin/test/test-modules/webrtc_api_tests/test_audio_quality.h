/*
 * WebRTC Audio Quality Test Headers
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

#ifndef WEBRTC_AUDIO_QUALITY_TEST_H
#define WEBRTC_AUDIO_QUALITY_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Audio Quality Test Classes
class AudioQualityTest : public AudioProcessingTestBase {
public:
    void SetUp() override {
        AudioProcessingTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL audio quality test
        WebRTCTestFramework::initialize();
        
        // Test audio stream quality
        bool audioStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStarted) << "Audio stream start failed";
        
        // Test audio quality metrics
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Audio quality measurement failed";
        
        // Test signal-to-noise ratio
        EXPECT_GT(audioQuality.signalToNoiseRatio, 20.0) 
            << "Signal-to-noise ratio too low: " << audioQuality.signalToNoiseRatio << " dB";
        
        // Test latency requirements
        EXPECT_LT(audioQuality.latency, 100.0) 
            << "Audio latency too high: " << audioQuality.latency << " ms";
        
        // Test jitter tolerance
        EXPECT_LT(audioQuality.jitter, 20.0) 
            << "Audio jitter too high: " << audioQuality.jitter << " ms";
        
        // Test packet loss tolerance
        EXPECT_LT(audioQuality.packetLoss, 1.0) 
            << "Packet loss too high: " << audioQuality.packetLoss << "%";
        
        // Test bandwidth efficiency
        EXPECT_GT(audioQuality.bandwidth, 0.0) 
            << "Bandwidth measurement failed";
        EXPECT_LT(audioQuality.bandwidth, 128000.0) 
            << "Bandwidth usage too high: " << audioQuality.bandwidth << " bps";
        
        // Test audio level monitoring
        double audioLevel = WebRTCTestFramework::getAudioLevel();
        EXPECT_GE(audioLevel, 0.0) << "Audio level should be non-negative";
        EXPECT_LE(audioLevel, 100.0) << "Audio level should not exceed 100%";
        
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_AUDIO_QUALITY_TEST_H
