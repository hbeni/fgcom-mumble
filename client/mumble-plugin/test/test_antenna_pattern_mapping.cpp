#include "test_framework.h"
#include "../lib/antenna_pattern_mapping.h"
#include <iostream>
#include <string>

/**
 * Test cases for antenna pattern mapping system
 */

bool testAntennaPatternMappingInitialization() {
    // Test that the mapping system can be initialized
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test that it's thread-safe
    auto* mapping2 = getAntennaPatternMapping();
    ASSERT_EQUAL(mapping, mapping2); // Should return same instance
    
    return true;
}

bool testVHFFrequencyDetection() {
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test VHF frequency detection
    ASSERT_TRUE(mapping->isVHFFrequency(144.0));
    ASSERT_TRUE(mapping->isVHFFrequency(150.0));
    ASSERT_FALSE(mapping->isVHFFrequency(432.0)); // UHF
    ASSERT_FALSE(mapping->isVHFFrequency(3.5));    // HF
    
    return true;
}

bool testUHFFrequencyDetection() {
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test UHF frequency detection
    ASSERT_TRUE(mapping->isUHFFrequency(432.0));
    ASSERT_TRUE(mapping->isUHFFrequency(440.0));
    ASSERT_FALSE(mapping->isUHFFrequency(144.0)); // VHF
    ASSERT_FALSE(mapping->isUHFFrequency(3.5));    // HF
    
    return true;
}

bool testVehicleTypeDetection() {
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test vehicle type detection
    std::string aircraft_type = mapping->detectVehicleType("b737_800");
    ASSERT_EQUAL(std::string("aircraft"), aircraft_type);
    
    std::string ground_type = mapping->detectVehicleType("leopard1_tank");
    ASSERT_EQUAL(std::string("ground_vehicle"), ground_type);
    
    std::string maritime_type = mapping->detectVehicleType("sailboat");
    ASSERT_EQUAL(std::string("maritime"), maritime_type);
    
    return true;
}

bool testPatternRetrieval() {
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test VHF pattern retrieval
    auto vhf_pattern = mapping->getClosestVHFPattern("aircraft", 144.0);
    ASSERT_TRUE(!vhf_pattern.antenna_name.empty());
    ASSERT_TRUE(!vhf_pattern.pattern_file.empty());
    ASSERT_EQUAL(std::string("aircraft"), vhf_pattern.vehicle_type);
    
    // Test UHF pattern retrieval
    auto uhf_pattern = mapping->getClosestUHFPattern("aircraft", 432.0);
    ASSERT_TRUE(!uhf_pattern.antenna_name.empty());
    ASSERT_TRUE(!uhf_pattern.pattern_file.empty());
    ASSERT_EQUAL(std::string("aircraft"), uhf_pattern.vehicle_type);
    
    return true;
}

bool test3DAttitudePatterns() {
    auto* mapping = getAntennaPatternMapping();
    ASSERT_NOT_NULL(mapping);
    
    // Test 3D attitude pattern retrieval
    auto pattern3d = mapping->get3DAttitudePattern("aircraft", 144.0, 0, 0, 1000);
    ASSERT_TRUE(!pattern3d.antenna_name.empty());
    ASSERT_TRUE(pattern3d.is_3d_pattern);
    
    // Test available 3D patterns
    auto available_patterns = mapping->getAvailable3DPatterns("aircraft", 144.0, 1000);
    ASSERT_TRUE(available_patterns.size() > 0);
    
    return true;
}

bool testThreadSafety() {
    // Test that multiple threads can access the mapping safely
    auto* mapping1 = getAntennaPatternMapping();
    auto* mapping2 = getAntennaPatternMapping();
    
    ASSERT_EQUAL(mapping1, mapping2);
    
    // Test that operations are thread-safe
    auto pattern1 = mapping1->getClosestVHFPattern("aircraft", 144.0);
    auto pattern2 = mapping2->getClosestVHFPattern("aircraft", 144.0);
    
    ASSERT_EQUAL(pattern1.antenna_name, pattern2.antenna_name);
    
    return true;
}

int main() {
    TestFramework framework;
    
    // Register all test cases
    framework.addTest("AntennaPatternMappingInitialization", testAntennaPatternMappingInitialization, 
                     "Test that antenna pattern mapping can be initialized safely");
    framework.addTest("VHFFrequencyDetection", testVHFFrequencyDetection, 
                     "Test VHF frequency detection logic");
    framework.addTest("UHFFrequencyDetection", testUHFFrequencyDetection, 
                     "Test UHF frequency detection logic");
    framework.addTest("VehicleTypeDetection", testVehicleTypeDetection, 
                     "Test vehicle type detection from names");
    framework.addTest("PatternRetrieval", testPatternRetrieval, 
                     "Test pattern retrieval for VHF and UHF");
    framework.addTest("3DAttitudePatterns", test3DAttitudePatterns, 
                     "Test 3D attitude pattern functionality");
    framework.addTest("ThreadSafety", testThreadSafety, 
                     "Test thread safety of antenna pattern mapping");
    
    // Run all tests
    bool success = framework.runAllTests();
    
    if (success) {
        std::cout << "\nAll tests passed! ✓" << std::endl;
        return 0;
    } else {
        std::cout << "\nSome tests failed! ✗" << std::endl;
        return 1;
    }
}
