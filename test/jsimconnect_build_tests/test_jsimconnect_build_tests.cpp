#include <gtest/gtest.h>
#include <gmock/gmock.h>

// Simple test to verify JSIMConnect build environment
TEST(JSIMConnectBuildTest, BasicFunctionality) {
    EXPECT_TRUE(true);
}

TEST(JSIMConnectBuildTest, EnvironmentCheck) {
    // Test that we can compile and link
    int result = 42;
    EXPECT_EQ(result, 42);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
