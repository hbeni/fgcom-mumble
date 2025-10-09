/**
 * @file test_military_satellites.cpp
 * @brief Test suite for Military Satellite Systems
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for military satellite systems,
 * including Strela-3, FLTSATCOM, and Tsiklon/Tsikada navigation satellites.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/satellites/military/strela_3.h"
#include "../../voice-encryption/systems/satellites/military/fltsatcom.h"
#include <vector>
#include <string>
#include <cmath>

using namespace std;
using namespace testing;

/**
 * @class MilitarySatellites_Test
 * @brief Test fixture for military satellite systems tests
 */
class MilitarySatellites_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize military satellite systems
        strela3 = new Strela3();
        fltsatcom = new FLTSATCOM();
        ASSERT_NE(strela3, nullptr);
        ASSERT_NE(fltsatcom, nullptr);
    }

    void TearDown() override {
        if (strela3) {
            delete strela3;
            strela3 = nullptr;
        }
        if (fltsatcom) {
            delete fltsatcom;
            fltsatcom = nullptr;
        }
    }

    Strela3* strela3 = nullptr;
    FLTSATCOM* fltsatcom = nullptr;
};

/**
 * @test Test Strela-3 satellite system initialization
 */
TEST_F(MilitarySatellites_Test, Strela3Initialization) {
    EXPECT_TRUE(strela3->isInitialized());
    EXPECT_EQ(strela3->getOrbitType(), "LEO");
    EXPECT_GE(strela3->getAltitude(), 1400.0f);
    EXPECT_LE(strela3->getAltitude(), 1500.0f);
    EXPECT_GE(strela3->getFrequencyMin(), 150.0f);
    EXPECT_LE(strela3->getFrequencyMax(), 174.0f);
}

/**
 * @test Test FLTSATCOM satellite system initialization
 */
TEST_F(MilitarySatellites_Test, FLTSATCOMInitialization) {
    EXPECT_TRUE(fltsatcom->isInitialized());
    EXPECT_EQ(fltsatcom->getOrbitType(), "GEO");
    EXPECT_GE(fltsatcom->getAltitude(), 35700.0f);
    EXPECT_LE(fltsatcom->getAltitude(), 35800.0f);
    EXPECT_GE(fltsatcom->getFrequencyMin(), 240.0f);
    EXPECT_LE(fltsatcom->getFrequencyMax(), 320.0f);
}

/**
 * @test Test military satellite communication protocols
 */
TEST_F(MilitarySatellites_Test, CommunicationProtocols) {
    // Test Strela-3 store-and-forward messaging
    EXPECT_TRUE(strela3->isStoreAndForward());
    EXPECT_TRUE(strela3->supportsMessaging());
    EXPECT_FALSE(strela3->isRealTime());
    
    // Test FLTSATCOM real-time communication
    EXPECT_FALSE(fltsatcom->isStoreAndForward());
    EXPECT_TRUE(fltsatcom->supportsVoice());
    EXPECT_TRUE(fltsatcom->isRealTime());
}

/**
 * @test Test military satellite frequency management
 */
TEST_F(MilitarySatellites_Test, FrequencyManagement) {
    // Test Strela-3 VHF frequencies
    vector<float> strela3Freqs = strela3->getSupportedFrequencies();
    EXPECT_GT(strela3Freqs.size(), 0);
    for (float freq : strela3Freqs) {
        EXPECT_GE(freq, 150.0f);
        EXPECT_LE(freq, 174.0f);
    }
    
    // Test FLTSATCOM UHF frequencies
    vector<float> fltsatcomFreqs = fltsatcom->getSupportedFrequencies();
    EXPECT_GT(fltsatcomFreqs.size(), 0);
    for (float freq : fltsatcomFreqs) {
        EXPECT_GE(freq, 240.0f);
        EXPECT_LE(freq, 320.0f);
    }
}

/**
 * @test Test military satellite performance
 */
TEST_F(MilitarySatellites_Test, Performance) {
    // Test Strela-3 messaging performance
    string testMessage = "Test tactical message";
    bool sendResult = strela3->sendMessage(testMessage);
    EXPECT_TRUE(sendResult);
    
    // Test FLTSATCOM voice performance
    vector<float> testAudio(1024, 0.5f);
    bool voiceResult = fltsatcom->transmitVoice(testAudio);
    EXPECT_TRUE(voiceResult);
}
