#ifndef FGCOM_TEST_FRAMEWORK_H
#define FGCOM_TEST_FRAMEWORK_H

#include <string>
#include <vector>
#include <functional>
#include <iostream>
#include <chrono>
#include <memory>

/**
 * Simple Testing Framework for FGCom-mumble
 * 
 * Provides basic unit testing capabilities for the plugin components
 */

class TestFramework {
private:
    struct TestCase {
        std::string name;
        std::function<bool()> test_function;
        std::string description;
    };
    
    std::vector<TestCase> test_cases;
    int passed_tests = 0;
    int failed_tests = 0;
    
public:
    // Register a test case
    void addTest(const std::string& name, std::function<bool()> test_func, const std::string& description = "") {
        test_cases.push_back({name, test_func, description});
    }
    
    // Run all tests
    bool runAllTests() {
        std::cout << "Running FGCom-mumble Test Suite..." << std::endl;
        std::cout << "=====================================" << std::endl;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (const auto& test : test_cases) {
            std::cout << "Running test: " << test.name;
            if (!test.description.empty()) {
                std::cout << " - " << test.description;
            }
            std::cout << std::endl;
            
            try {
                bool result = test.test_function();
                if (result) {
                    std::cout << "  ✓ PASSED" << std::endl;
                    passed_tests++;
                } else {
                    std::cout << "  ✗ FAILED" << std::endl;
                    failed_tests++;
                }
            } catch (const std::exception& e) {
                std::cout << "  ✗ FAILED with exception: " << e.what() << std::endl;
                failed_tests++;
            } catch (...) {
                std::cout << "  ✗ FAILED with unknown exception" << std::endl;
                failed_tests++;
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "=====================================" << std::endl;
        std::cout << "Test Results:" << std::endl;
        std::cout << "  Passed: " << passed_tests << std::endl;
        std::cout << "  Failed: " << failed_tests << std::endl;
        std::cout << "  Total:  " << (passed_tests + failed_tests) << std::endl;
        std::cout << "  Time:   " << duration.count() << "ms" << std::endl;
        
        return failed_tests == 0;
    }
    
    // Get test statistics
    int getPassedCount() const { return passed_tests; }
    int getFailedCount() const { return failed_tests; }
    int getTotalCount() const { return passed_tests + failed_tests; }
};

// Test assertion macros
#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            std::cout << "    Assertion failed: " << #condition << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define ASSERT_FALSE(condition) \
    do { \
        if (condition) { \
            std::cout << "    Assertion failed: " << #condition << " should be false at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            std::cout << "    Assertion failed: expected " << (expected) << " but got " << (actual) << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == nullptr) { \
            std::cout << "    Assertion failed: pointer is null at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != nullptr) { \
            std::cout << "    Assertion failed: pointer should be null at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#endif // FGCOM_TEST_FRAMEWORK_H
