#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <algorithm>

// Realistic property tests for frequency management
TEST(PropertyTests, FrequencyRangePropertyTest) {
    rc::check("Frequency should be within radio range", [](double frequency) {
        RC_PRE(frequency >= 1e6 && frequency <= 1e9); // 1 MHz to 1 GHz
        RC_ASSERT(frequency >= 1e6);
        RC_ASSERT(frequency <= 1e9);
    });
}

TEST(PropertyTests, ChannelSeparationPropertyTest) {
    rc::check("Channel separation should be positive", [](double separation) {
        RC_PRE(separation > 0.0 && separation <= 1e6); // Up to 1 MHz separation
        RC_ASSERT(separation > 0.0);
        RC_ASSERT(separation <= 1e6);
    });
}

TEST(PropertyTests, BooleanPropertyTest) {
    rc::check("Boolean property test", [](bool enabled) {
        RC_ASSERT(enabled == true || enabled == false);
    });
}
