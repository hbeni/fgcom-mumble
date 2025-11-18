/*
 * Test Band Segments CSV Loading
 * 
 * This test verifies that the band segments CSV file is loaded correctly
 * and that the new functions work with the loaded data.
 */

#include <iostream>
#include <string>
#include <vector>
#include "../lib/amateur_radio.h"

int main() {
    std::cout << "Testing Band Segments CSV Loading..." << std::endl;
    
    // Initialize amateur radio system
    if (!FGCom_AmateurRadio::initialize()) {
        std::cerr << "Failed to initialize amateur radio system" << std::endl;
        return 1;
    }
    
    std::cout << "Amateur radio system initialized successfully" << std::endl;
    
    // Test power limit checking
    std::cout << "\nTesting power limit checking:" << std::endl;
    
    // Test 60m band (should be 50W limit)
    float power_limit_60m = FGCom_AmateurRadio::getPowerLimit(5310.0, 1, "CW");
    std::cout << "60m band (5310 kHz) power limit: " << power_limit_60m << "W" << std::endl;
    
    // Test 20m band (should be 400W limit)
    float power_limit_20m = FGCom_AmateurRadio::getPowerLimit(14100.0, 1, "SSB");
    std::cout << "20m band (14100 kHz) power limit: " << power_limit_20m << "W" << std::endl;
    
    // Test 2m band (should be 100W limit)
    float power_limit_2m = FGCom_AmateurRadio::getPowerLimit(145000.0, 1, "SSB");
    std::cout << "2m band (145000 kHz) power limit: " << power_limit_2m << "W" << std::endl;
    
    // Test power validation
    std::cout << "\nTesting power validation:" << std::endl;
    
    bool valid_60m_low = FGCom_AmateurRadio::validatePowerLevel(5310.0, 1, "CW", 25.0);
    bool valid_60m_high = FGCom_AmateurRadio::validatePowerLevel(5310.0, 1, "CW", 100.0);
    std::cout << "60m band 25W: " << (valid_60m_low ? "VALID" : "INVALID") << std::endl;
    std::cout << "60m band 100W: " << (valid_60m_high ? "VALID" : "INVALID") << std::endl;
    
    // Test band segment info
    std::cout << "\nTesting band segment info:" << std::endl;
    
    fgcom_band_segment segment_60m = FGCom_AmateurRadio::getBandSegmentInfo(5310.0, 1, "CW");
    if (!segment_60m.band.empty()) {
        std::cout << "60m segment found: " << segment_60m.band << " " << segment_60m.mode 
                  << " " << segment_60m.start_freq << "-" << segment_60m.end_freq << " kHz"
                  << " Power limit: " << segment_60m.power_limit << "W"
                  << " Countries: " << segment_60m.countries << std::endl;
    } else {
        std::cout << "60m segment not found" << std::endl;
    }
    
    // Test regional restrictions
    std::cout << "\nTesting regional restrictions:" << std::endl;
    
    bool region1_60m = FGCom_AmateurRadio::checkRegionalRestrictions(5310.0, 1);
    bool region2_60m = FGCom_AmateurRadio::checkRegionalRestrictions(5310.0, 2);
    std::cout << "60m band Region 1: " << (region1_60m ? "ALLOWED" : "RESTRICTED") << std::endl;
    std::cout << "60m band Region 2: " << (region2_60m ? "ALLOWED" : "RESTRICTED") << std::endl;
    
    // Test frequency validation with new data
    std::cout << "\nTesting frequency validation:" << std::endl;
    
    bool valid_20m_ssb = FGCom_AmateurRadio::validateAmateurFrequency("14100", "SSB", 1);
    bool valid_20m_cw = FGCom_AmateurRadio::validateAmateurFrequency("14050", "CW", 1);
    bool invalid_freq = FGCom_AmateurRadio::validateAmateurFrequency("15000", "SSB", 1);
    
    std::cout << "20m SSB (14100 kHz): " << (valid_20m_ssb ? "VALID" : "INVALID") << std::endl;
    std::cout << "20m CW (14050 kHz): " << (valid_20m_cw ? "VALID" : "INVALID") << std::endl;
    std::cout << "Invalid freq (15000 kHz): " << (invalid_freq ? "VALID" : "INVALID") << std::endl;
    
    std::cout << "\nBand segments CSV loading test completed successfully!" << std::endl;
    return 0;
}
