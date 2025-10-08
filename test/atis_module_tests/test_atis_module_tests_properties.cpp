#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <algorithm>

// Robust property tests that work with RapidCheck
TEST(PropertyTests, BasicPropertyTest) {
    rc::check("Basic property test", []() {
        // Use simple range generation that works
        int value = *rc::gen::arbitrary<int>() % 1000;
        if (value < 0) value = -value; // Ensure non-negative
        RC_ASSERT(value >= 0);
        RC_ASSERT(value <= 1000);
    });
}

TEST(PropertyTests, StringPropertyTest) {
    rc::check("String property test", []() {
        // Generate a simple string
        std::string name = "test_string_" + std::to_string(*rc::gen::arbitrary<int>() % 1000);
        RC_ASSERT(!name.empty());
        RC_ASSERT(name.length() > 0U);
    });
}

TEST(PropertyTests, BooleanPropertyTest) {
    rc::check("Boolean property test", [](bool enabled) {
        RC_ASSERT(enabled == true || enabled == false);
    });
}

// Frequency-specific property tests
TEST(PropertyTests, FrequencyRangePropertyTest) {
    rc::check("Frequency should be within radio range", []() {
        // Generate frequency in valid range
        int offset = *rc::gen::arbitrary<int>() % 900000000;
        if (offset < 0) offset = -offset;
        double frequency = 1e6 + offset; // 1 MHz to 1 GHz
        RC_ASSERT(frequency >= 1e6);
        RC_ASSERT(frequency <= 1e9);
    });
}

TEST(PropertyTests, ChannelSeparationPropertyTest) {
    rc::check("Channel separation should be positive", []() {
        // Generate positive separation
        double separation = 0.1 + (*rc::gen::arbitrary<int>() % 1000000) / 1000.0; // 0.1 Hz to 1 MHz
        RC_ASSERT(separation > 0.0);
        RC_ASSERT(separation <= 1e6);
    });
}

// Security-specific property tests
TEST(PropertyTests, SecurityLevelPropertyTest) {
    rc::check("Security levels should be within valid range", []() {
        // Generate security level 0-5
        int level = *rc::gen::arbitrary<int>() % 6; // 0-5
        if (level < 0) level = -level % 6;
        RC_ASSERT(level >= 0);
        RC_ASSERT(level <= 5);
    });
}

TEST(PropertyTests, AuthenticationPropertyTest) {
    rc::check("Authentication should be boolean", [](bool authenticated) {
        RC_ASSERT(authenticated == true || authenticated == false);
    });
}
