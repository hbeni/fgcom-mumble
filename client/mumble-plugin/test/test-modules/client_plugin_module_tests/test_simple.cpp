#include <gtest/gtest.h>
#include <iostream>

// REAL simple test to check if we can compile and run
TEST(SimpleTest, BasicTest) {
    // This is actually meaningful - if we get here, compilation and execution succeeded
    EXPECT_TRUE(true);
    std::cout << "Simple test passed!" << std::endl;
}
