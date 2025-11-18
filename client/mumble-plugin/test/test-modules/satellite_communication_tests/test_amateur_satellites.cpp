/**
 * @file test_amateur_satellites.cpp
 * @brief Test suite for Amateur Radio Satellite Systems
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for amateur radio satellite systems,
 * including linear transponders, FM repeaters, and digital mode satellites.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/satellites/amateur/ao_7.h"
#include "../../voice-encryption/systems/satellites/amateur/iss.h"
#include <vector>
#include <string>
#include <cmath>

using namespace std;
using namespace testing;

/**
 * @class AmateurSatellites_Test
 * @brief Test fixture for amateur radio satellite systems tests
 */
class AmateurSatellites_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize amateur satellite systems
        ao7 = new AO7();
        iss = new ISS();
        ASSERT_NE(ao7, nullptr);
        ASSERT_NE(iss, nullptr);
    }

    void TearDown() override {
        if (ao7) {
            delete ao7;
            ao7 = nullptr;
        }
        if (iss) {
            delete iss;
            iss = nullptr;
        }
    }

    AO7* ao7 = nullptr;
    ISS* iss = nullptr;
};

/**
 * @test Test AO-7 satellite system initialization
 */
TEST_F(AmateurSatellites_Test, AO7Initialization) {
    EXPECT_TRUE(ao7->isInitialized());
    EXPECT_EQ(ao7->getSatelliteName(), "AO-7");
    EXPECT_EQ(ao7->getNORAD(), 07530);
    EXPECT_EQ(ao7->getOrbitType(), "LEO");
    EXPECT_GE(ao7->getAltitude(), 1400.0f);
    EXPECT_LE(ao7->getAltitude(), 1500.0f);
}

/**
 * @test Test ISS satellite system initialization
 */
TEST_F(AmateurSatellites_Test, ISSInitialization) {
    EXPECT_TRUE(iss->isInitialized());
    EXPECT_EQ(iss->getSatelliteName(), "ISS");
    EXPECT_EQ(iss->getNORAD(), 25544);
    EXPECT_EQ(iss->getOrbitType(), "LEO");
    EXPECT_GE(iss->getAltitude(), 400.0f);
    EXPECT_LE(iss->getAltitude(), 450.0f);
}

/**
 * @test Test amateur satellite frequency bands
 */
TEST_F(AmateurSatellites_Test, FrequencyBands) {
    // Test AO-7 2m/70cm bands
    vector<float> ao7Freqs = ao7->getSupportedFrequencies();
    EXPECT_GT(ao7Freqs.size(), 0);
    
    // Test ISS 2m band
    vector<float> issFreqs = iss->getSupportedFrequencies();
    EXPECT_GT(issFreqs.size(), 0);
    
    // Verify 2m band (144-146 MHz)
    bool has2mBand = false;
    for (float freq : issFreqs) {
        if (freq >= 144.0f && freq <= 146.0f) {
            has2mBand = true;
            break;
        }
    }
    EXPECT_TRUE(has2mBand);
}

/**
 * @test Test amateur satellite communication modes
 */
TEST_F(AmateurSatellites_Test, CommunicationModes) {
    // Test AO-7 linear transponder modes
    EXPECT_TRUE(ao7->supportsMode("SSB"));
    EXPECT_TRUE(ao7->supportsMode("CW"));
    EXPECT_FALSE(ao7->supportsMode("FM"));
    
    // Test ISS FM voice repeater
    EXPECT_TRUE(iss->supportsMode("FM"));
    EXPECT_TRUE(iss->isVoiceRepeater());
    EXPECT_FALSE(iss->isLinearTransponder());
}

/**
 * @test Test amateur satellite performance
 */
TEST_F(AmateurSatellites_Test, Performance) {
    // Test AO-7 transponder performance
    vector<float> testSignal(1024, 0.5f);
    bool transpondResult = ao7->processSignal(testSignal);
    EXPECT_TRUE(transpondResult);
    
    // Test ISS voice repeater performance
    vector<float> testVoice(1024, 0.5f);
    bool voiceResult = iss->processVoice(testVoice);
    EXPECT_TRUE(voiceResult);
}
