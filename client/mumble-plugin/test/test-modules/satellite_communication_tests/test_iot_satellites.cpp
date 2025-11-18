/**
 * @file test_iot_satellites.cpp
 * @brief Test suite for IoT Satellite Systems
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for IoT satellite systems,
 * including Orbcomm and Gonets satellites.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/satellites/iot/orbcomm.h"
#include "../../voice-encryption/systems/satellites/iot/gonets.h"
#include <vector>
#include <string>
#include <cmath>

using namespace std;
using namespace testing;

/**
 * @class IoTSatellites_Test
 * @brief Test fixture for IoT satellite systems tests
 */
class IoTSatellites_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize IoT satellite systems
        orbcomm = new Orbcomm();
        gonets = new Gonets();
        ASSERT_NE(orbcomm, nullptr);
        ASSERT_NE(gonets, nullptr);
    }

    void TearDown() override {
        if (orbcomm) {
            delete orbcomm;
            orbcomm = nullptr;
        }
        if (gonets) {
            delete gonets;
            gonets = nullptr;
        }
    }

    Orbcomm* orbcomm = nullptr;
    Gonets* gonets = nullptr;
};

/**
 * @test Test Orbcomm satellite system initialization
 */
TEST_F(IoTSatellites_Test, OrbcommInitialization) {
    EXPECT_TRUE(orbcomm->isInitialized());
    EXPECT_EQ(orbcomm->getSatelliteName(), "Orbcomm");
    EXPECT_EQ(orbcomm->getOrbitType(), "LEO");
    EXPECT_GE(orbcomm->getAltitude(), 700.0f);
    EXPECT_LE(orbcomm->getAltitude(), 800.0f);
}

/**
 * @test Test Gonets satellite system initialization
 */
TEST_F(IoTSatellites_Test, GonetsInitialization) {
    EXPECT_TRUE(gonets->isInitialized());
    EXPECT_EQ(gonets->getSatelliteName(), "Gonets");
    EXPECT_EQ(gonets->getOrbitType(), "LEO");
    EXPECT_GE(gonets->getAltitude(), 1400.0f);
    EXPECT_LE(gonets->getAltitude(), 1500.0f);
}

/**
 * @test Test IoT satellite frequency bands
 */
TEST_F(IoTSatellites_Test, FrequencyBands) {
    // Test Orbcomm frequencies
    vector<float> orbcommFreqs = orbcomm->getSupportedFrequencies();
    EXPECT_GT(orbcommFreqs.size(), 0);
    
    // Test Gonets frequencies
    vector<float> gonetsFreqs = gonets->getSupportedFrequencies();
    EXPECT_GT(gonetsFreqs.size(), 0);
    
    // Verify Orbcomm VHF frequencies (137-138 MHz downlink, 148-150.05 MHz uplink)
    bool hasVHFFreq = false;
    for (float freq : orbcommFreqs) {
        if (freq >= 137.0f && freq <= 138.0f) {
            hasVHFFreq = true;
            break;
        }
    }
    EXPECT_TRUE(hasVHFFreq);
    
    // Verify Gonets UHF frequencies (387-390 MHz)
    bool hasUHFFreq = false;
    for (float freq : gonetsFreqs) {
        if (freq >= 387.0f && freq <= 390.0f) {
            hasUHFFreq = true;
            break;
        }
    }
    EXPECT_TRUE(hasUHFFreq);
}

/**
 * @test Test IoT satellite communication protocols
 */
TEST_F(IoTSatellites_Test, CommunicationProtocols) {
    // Test Orbcomm M2M protocols
    EXPECT_TRUE(orbcomm->supportsM2M());
    EXPECT_TRUE(orbcomm->supportsAssetTracking());
    EXPECT_TRUE(orbcomm->supportsMaritime());
    EXPECT_FALSE(orbcomm->supportsVoice());
    
    // Test Gonets store-and-forward
    EXPECT_TRUE(gonets->isStoreAndForward());
    EXPECT_TRUE(gonets->supportsMessaging());
    EXPECT_TRUE(gonets->supportsIoT());
    EXPECT_FALSE(gonets->supportsVoice());
}

/**
 * @test Test IoT satellite data transmission
 */
TEST_F(IoTSatellites_Test, DataTransmission) {
    // Test Orbcomm data transmission
    string testData = "Test IoT data packet";
    bool sendResult = orbcomm->sendData(testData);
    EXPECT_TRUE(sendResult);
    
    // Test Gonets messaging
    string testMessage = "Test store-and-forward message";
    bool messageResult = gonets->sendMessage(testMessage);
    EXPECT_TRUE(messageResult);
}

/**
 * @test Test IoT satellite performance
 */
TEST_F(IoTSatellites_Test, Performance) {
    // Test Orbcomm data throughput
    vector<uint8_t> testData(1024, 0xAA);
    bool throughputResult = orbcomm->transmitData(testData);
    EXPECT_TRUE(throughputResult);
    
    // Test Gonets message processing
    string testMessage = "Performance test message";
    bool processResult = gonets->processMessage(testMessage);
    EXPECT_TRUE(processResult);
}
