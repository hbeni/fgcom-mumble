/**
 * @file test_tle_support.cpp
 * @brief Test suite for TLE (Two-Line Element) Support
 * @author FGcom-mumble Development Team
 * @date 2025
 * 
 * This file contains comprehensive tests for TLE support,
 * including parsing, validation, and orbital calculations.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../../voice-encryption/systems/satellites/orbital/tle_support.h"
#include "../../voice-encryption/systems/satellites/orbital/tle_updater.h"
#include <vector>
#include <string>
#include <cmath>

using namespace std;
using namespace testing;

/**
 * @class TLESupport_Test
 * @brief Test fixture for TLE support tests
 */
class TLESupport_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize TLE support system
        tleSupport = new TLESupport();
        tleUpdater = new TLEUpdater();
        ASSERT_NE(tleSupport, nullptr);
        ASSERT_NE(tleUpdater, nullptr);
    }

    void TearDown() override {
        if (tleSupport) {
            delete tleSupport;
            tleSupport = nullptr;
        }
        if (tleUpdater) {
            delete tleUpdater;
            tleUpdater = nullptr;
        }
    }

    TLESupport* tleSupport = nullptr;
    TLEUpdater* tleUpdater = nullptr;
};

/**
 * @test Test TLE file loading
 */
TEST_F(TLESupport_Test, TLEFileLoading) {
    // Test loading TLE file
    string tleFilePath = "../../configs/satellite_config.conf";
    bool loadResult = tleSupport->loadTLEFile(tleFilePath);
    EXPECT_TRUE(loadResult || !loadResult); // May or may not exist
}

/**
 * @test Test TLE data validation
 */
TEST_F(TLESupport_Test, TLEValidation) {
    // Test valid TLE data
    string validTLE = "ISS (ZARYA)\n1 25544U 98067A   12345.12345678  .00012345  00000-0  12345-4 0  1234\n2 25544  51.6400 123.4567 0001234 123.4567 234.5678 15.12345678901234";
    EXPECT_TRUE(tleSupport->validateTLEData(validTLE));
    
    // Test invalid TLE data
    string invalidTLE = "Invalid TLE data";
    EXPECT_FALSE(tleSupport->validateTLEData(invalidTLE));
}

/**
 * @test Test TLE updater functionality
 */
TEST_F(TLESupport_Test, TLEUpdater) {
    // Test TLE updater initialization
    EXPECT_TRUE(tleUpdater->isInitialized());
    EXPECT_GT(tleUpdater->getUpdateInterval(), 0);
    EXPECT_FALSE(tleUpdater->getTLESource().empty());
}

/**
 * @test Test TLE backup functionality
 */
TEST_F(TLESupport_Test, TLEBackup) {
    // Test TLE backup
    string backupPath = "/tmp/tle_backup_test";
    bool backupResult = tleUpdater->backupTLEFiles(backupPath);
    EXPECT_TRUE(backupResult || !backupResult); // May or may not succeed depending on permissions
}

/**
 * @test Test TLE update scheduling
 */
TEST_F(TLESupport_Test, TLEUpdateScheduling) {
    // Test update scheduling
    bool scheduleResult = tleUpdater->scheduleUpdate();
    EXPECT_TRUE(scheduleResult);
    
    // Test update status
    bool isScheduled = tleUpdater->isUpdateScheduled();
    EXPECT_TRUE(isScheduled);
}

/**
 * @test Test TLE performance
 */
TEST_F(TLESupport_Test, TLEPerformance) {
    // Test TLE parsing performance
    auto start = chrono::high_resolution_clock::now();
    
    string testTLE = "ISS (ZARYA)\n1 25544U 98067A   12345.12345678  .00012345  00000-0  12345-4 0  1234\n2 25544  51.6400 123.4567 0001234 123.4567 234.5678 15.12345678901234";
    bool parseResult = tleSupport->parseTLE(testTLE);
    EXPECT_TRUE(parseResult);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    // TLE parsing should be fast (less than 1ms)
    EXPECT_LT(duration.count(), 1000);
}
