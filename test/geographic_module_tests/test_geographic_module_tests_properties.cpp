#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <algorithm>

// Simple property test that works with RapidCheck
TEST(PropertyTests, BasicPropertyTest) {
    rc::check("Basic property test", [](int value) {
        RC_ASSERT(value >= 0);
        RC_ASSERT(value <= 1000);
    });
}

TEST(PropertyTests, StringPropertyTest) {
    rc::check("String property test", [](const std::string& name) {
        RC_ASSERT(!name.empty());
        RC_ASSERT(name.length() > 0);
    });
}

TEST(PropertyTests, BooleanPropertyTest) {
    rc::check("Boolean property test", [](bool enabled) {
        RC_ASSERT(enabled == true || enabled == false);
    });
}
