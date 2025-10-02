#include <iostream>
#include <string>
#include "lib/antenna_pattern_mapping.h"

int main() {
    std::cout << "Testing 4m band pattern mapping..." << std::endl;
    
    // Test if the pattern mapping can find 4m band patterns
    auto mapping = getAntennaPatternMapping();
    
    // Test 70MHz frequency
    auto pattern_info = mapping->getVHFPattern("ground_station", 70.15);
    
    std::cout << "Pattern for 70.15 MHz:" << std::endl;
    std::cout << "  Antenna name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern file: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    std::cout << "  Vehicle type: " << pattern_info.vehicle_type << std::endl;
    std::cout << "  Antenna type: " << pattern_info.antenna_type << std::endl;
    std::cout << "  Is loaded: " << (pattern_info.is_loaded ? "Yes" : "No") << std::endl;
    
    if (!pattern_info.antenna_name.empty()) {
        std::cout << "SUCCESS: 4m band pattern mapping is working!" << std::endl;
        return 0;
    } else {
        std::cout << "FAILURE: 4m band pattern mapping not found!" << std::endl;
        return 1;
    }
}
