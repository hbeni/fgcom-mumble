#include <iostream>
#include <memory>
#include <cassert>
#include <cmath>
#include <fstream>
#include <sys/stat.h>
#include "radio_model.h"
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"

/**
 * Test script for VHF/UHF antenna pattern integration
 * 
 * This script tests the new antenna pattern functionality in VHF and UHF radio models.
 */

void testVHFPatternIntegration() {
    std::cout << "Testing VHF Pattern Integration..." << std::endl;
    
    // Test antenna pattern mapping for VHF
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getVHFPattern("ground_station", 144.5);
    
    std::cout << "VHF Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "yagi_144mhz");
    assert(pattern_info.frequency_mhz == 144.5);
    assert(pattern_info.vehicle_type == "ground_station");
    
    std::cout << "✓ VHF pattern integration test passed" << std::endl;
    std::cout << std::endl;
}

void testUHFPatternIntegration() {
    std::cout << "Testing UHF Pattern Integration..." << std::endl;
    
    // Test antenna pattern mapping for UHF
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getUHFPattern("ground_station", 432.0);
    
    std::cout << "UHF Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "yagi_70cm");
    assert(pattern_info.frequency_mhz == 432.0);
    assert(pattern_info.vehicle_type == "ground_station");
    
    std::cout << "✓ UHF pattern integration test passed" << std::endl;
    std::cout << std::endl;
}

void testPropagationPhysics() {
    std::cout << "Testing Propagation Physics..." << std::endl;
    
    // Test free space path loss
    double fspl = FGCom_PropagationPhysics::calculateFreeSpacePathLoss(10.0, 150.0);
    std::cout << "Free Space Path Loss (10km, 150MHz): " << fspl << " dB" << std::endl;
    assert(fspl > 0.0);
    
    // Test atmospheric absorption
    double absorption = FGCom_PropagationPhysics::calculateAtmosphericAbsorption(1.0, 150.0, 0.0, 15.0, 70.0);
    std::cout << "Atmospheric Absorption (150MHz, 15C, 70%RH): " << absorption << " dB/km" << std::endl;
    assert(absorption >= 0.0);
    
    // Test total propagation loss
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        50.0, 150.0, 1000.0, 10.0, 15.0, 70.0, 0.0, 0.0
    );
    std::cout << "Total Propagation Loss (50km, 150MHz): " << total_loss << " dB" << std::endl;
    assert(total_loss > 0.0);
    
    std::cout << "✓ Propagation physics test passed" << std::endl;
    std::cout << std::endl;
}

void testPatternFileGeneration() {
    std::cout << "Testing Pattern File Generation..." << std::endl;
    
    // Check if generation scripts exist
    std::ifstream script_file("generate_vhf_uhf_patterns.sh");
    if (script_file.good()) {
        std::cout << "✓ VHF/UHF pattern generation script found" << std::endl;
    } else {
        std::cout << "⚠ VHF/UHF pattern generation script not found" << std::endl;
    }
    
    // Check if antenna directories exist
    std::vector<std::string> antenna_dirs = {
        "antenna_patterns/Ground-based/yagi_144mhz",
        "antenna_patterns/Ground-based/yagi_70cm",
        "antenna_patterns/Ground-based/dual_band_omni"
    };
    
    for (const auto& dir : antenna_dirs) {
        struct stat st;
        if (stat(dir.c_str(), &st) == 0) {
            std::cout << "✓ Directory exists: " << dir << std::endl;
        } else {
            std::cout << "⚠ Directory missing: " << dir << std::endl;
        }
    }
    
    std::cout << "✓ Pattern file generation test completed" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniIntegration() {
    std::cout << "Testing Dual-Band Omnidirectional Integration..." << std::endl;
    
    FGCom_AntennaPatternMapping mapping;
    
    // Test VHF pattern
    auto vhf_pattern = mapping.getVHFPattern("ground_station", 145.0);
    std::cout << "VHF Pattern: " << vhf_pattern.antenna_name << std::endl;
    assert(vhf_pattern.antenna_name == "dual_band_omni_vhf");
    
    // Test UHF pattern
    auto uhf_pattern = mapping.getUHFPattern("ground_station", 432.0);
    std::cout << "UHF Pattern: " << uhf_pattern.antenna_name << std::endl;
    assert(uhf_pattern.antenna_name == "dual_band_omni_uhf");
    
    std::cout << "✓ Dual-band omnidirectional integration test passed" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "=== VHF/UHF Antenna Pattern Integration Tests ===" << std::endl;
    std::cout << std::endl;
    
    testVHFPatternIntegration();
    testUHFPatternIntegration();
    testPropagationPhysics();
    testPatternFileGeneration();
    testDualBandOmniIntegration();
    
    std::cout << "=== All Tests Completed Successfully ===" << std::endl;
    return 0;
}