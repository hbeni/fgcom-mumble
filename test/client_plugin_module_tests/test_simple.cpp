#include <gtest/gtest.h>
#include <iostream>

// Simple test to check if we can compile
TEST(SimpleTest, BasicTest) {
    EXPECT_TRUE(true);
    std::cout << "Simple test passed!" << std::endl;
}
