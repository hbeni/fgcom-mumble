#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cassert>

// Simple test framework for FGCom-mumble
class TestFramework {
private:
    static int totalTests;
    static int passedTests;
    static int failedTests;
    static std::vector<std::string> failures;

public:
    static void initialize() {
        totalTests = 0;
        passedTests = 0;
        failedTests = 0;
        failures.clear();
    }

    static void runTest(const std::string& testName, bool result, const std::string& message = "") {
        totalTests++;
        if (result) {
            passedTests++;
            std::cout << "✓ " << testName << " PASSED";
            if (!message.empty()) {
                std::cout << " - " << message;
            }
            std::cout << std::endl;
        } else {
            failedTests++;
            std::string failureMsg = testName + " FAILED";
            if (!message.empty()) {
                failureMsg += " - " + message;
            }
            failures.push_back(failureMsg);
            std::cout << "✗ " << failureMsg << std::endl;
        }
    }

    static void printSummary() {
        std::cout << "\n=== TEST SUMMARY ===" << std::endl;
        std::cout << "Total Tests: " << totalTests << std::endl;
        std::cout << "Passed: " << passedTests << std::endl;
        std::cout << "Failed: " << failedTests << std::endl;
        
        if (failedTests > 0) {
            std::cout << "\nFAILURES:" << std::endl;
            for (const auto& failure : failures) {
                std::cout << "  - " << failure << std::endl;
            }
        }
        
        std::cout << "\nResult: " << (failedTests == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
    }

    static bool allTestsPassed() {
        return failedTests == 0;
    }
};

// Test macros
#define ASSERT_TRUE(condition, message) \
    TestFramework::runTest(__FUNCTION__, (condition), message)

#define ASSERT_FALSE(condition, message) \
    TestFramework::runTest(__FUNCTION__, !(condition), message)

#define ASSERT_EQ(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) == (actual), message)

#define ASSERT_NE(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) != (actual), message)

#define ASSERT_LT(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) < (actual), message)

#define ASSERT_LE(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) <= (actual), message)

#define ASSERT_GT(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) > (actual), message)

#define ASSERT_GE(expected, actual, message) \
    TestFramework::runTest(__FUNCTION__, (expected) >= (actual), message)

// Test suite macros
#define TEST_SUITE(name) \
    class name { \
    public: \
        static void runAllTests() { \
            TestFramework::initialize(); \
            std::cout << "Running " #name " tests..." << std::endl;

#define TEST_CASE(testName) \
    static void testName() { \
        std::cout << "  Testing " #testName "..." << std::endl;

#define END_TEST_CASE \
    }

#define BEFORE_EACH() \
    static void beforeEach() {

#define AFTER_EACH() \
    static void afterEach() {

#define END_BEFORE_EACH \
    }

#define END_AFTER_EACH \
    }

#define END_TEST_SUITE \
        TestFramework::printSummary(); \
        } \
    };

// Global test framework instance
int TestFramework::totalTests = 0;
int TestFramework::passedTests = 0;
int TestFramework::failedTests = 0;
std::vector<std::string> TestFramework::failures;

#endif // TEST_FRAMEWORK_H
