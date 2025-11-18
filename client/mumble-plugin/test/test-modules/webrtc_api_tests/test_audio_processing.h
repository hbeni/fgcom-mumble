/*
 * WebRTC Audio Processing Test Headers
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

#ifndef WEBRTC_AUDIO_PROCESSING_TEST_H
#define WEBRTC_AUDIO_PROCESSING_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Audio Processing Test Classes
class AudioProcessingTest : public AudioProcessingTestBase {
public:
    void SetUp() override {
        AudioProcessingTestBase::SetUp();
    }
    
    void TestBody() override {
        // REAL audio processing test
        WebRTCTestFramework::initialize();
        
        // Test audio stream initialization
        bool audioStreamStarted = WebRTCTestFramework::startAudioStream();
        EXPECT_TRUE(audioStreamStarted) << "Failed to start audio stream for processing test";
        
        // Test audio codec support
        bool opusSupported = WebRTCTestFramework::testAudioCodec();
        EXPECT_TRUE(opusSupported) << "Opus codec not supported";
        
        // Test audio quality metrics
        auto audioQuality = WebRTCTestFramework::measureAudioQuality();
        EXPECT_TRUE(audioQuality.isValid) << "Audio quality measurement failed";
        
        // Test signal-to-noise ratio
        EXPECT_GT(audioQuality.signalToNoiseRatio, 15.0) 
            << "Signal-to-noise ratio too low: " << audioQuality.signalToNoiseRatio << " dB";
        
        // Test latency requirements
        EXPECT_LT(audioQuality.latency, 150.0) 
            << "Audio latency too high: " << audioQuality.latency << " ms";
        
        // Test jitter tolerance
        EXPECT_LT(audioQuality.jitter, 30.0) 
            << "Audio jitter too high: " << audioQuality.jitter << " ms";
        
        // Test packet loss tolerance
        EXPECT_LT(audioQuality.packetLoss, 5.0) 
            << "Packet loss too high: " << audioQuality.packetLoss << "%";
        
        // Test bandwidth efficiency
        EXPECT_GT(audioQuality.bandwidth, 0.0) 
            << "Bandwidth measurement failed";
        EXPECT_LT(audioQuality.bandwidth, 100000.0) 
            << "Bandwidth usage too high: " << audioQuality.bandwidth << " bps";
        
        // Test audio level monitoring
        double inputLevel = WebRTCTestFramework::getAudioLevel();
        EXPECT_GE(inputLevel, 0.0) << "Audio level should be non-negative";
        EXPECT_LE(inputLevel, 100.0) << "Audio level should not exceed 100%";
        
        // Test audio processing performance
        auto startTime = std::chrono::high_resolution_clock::now();
        bool processingWorking = WebRTCTestFramework::testAudioProcessing();
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        EXPECT_TRUE(processingWorking) << "Audio processing pipeline failed";
        EXPECT_LT(duration.count(), 500) << "Audio processing too slow: " << duration.count() << " ms";
        
        // Test echo cancellation
        bool echoCancellationWorking = WebRTCTestFramework::testEchoCancellation();
        EXPECT_TRUE(echoCancellationWorking) << "Echo cancellation not working";
        
        // Test noise suppression
        bool noiseSuppressionWorking = WebRTCTestFramework::testNoiseSuppression();
        EXPECT_TRUE(noiseSuppressionWorking) << "Noise suppression not working";
        
        // Test automatic gain control
        bool agcWorking = WebRTCTestFramework::testAutomaticGainControl();
        EXPECT_TRUE(agcWorking) << "Automatic gain control not working";
        
        // Cleanup
        WebRTCTestFramework::stopAudioStream();
        WebRTCTestFramework::cleanup();
    }
};

#endif // WEBRTC_AUDIO_PROCESSING_TEST_H
