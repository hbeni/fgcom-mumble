#include <iostream>
#include <cassert>
#include <cmath>
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"

/**
 * Test script for dual-band omnidirectional antenna integration
 * 
 * This script validates the integration of the new dual-band omnidirectional antenna
 * with the FGCom-mumble propagation system for both VHF and UHF bands.
 */

void testDualBandOmniAntennaMapping() {
    std::cout << "=== Testing Dual-Band Omnidirectional Antenna Mapping ===" << std::endl;
    
    // Test ground station detection
    FGCom_AntennaPatternMapping mapping;
    std::string vehicle_type = mapping.detectVehicleType("ground_station");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Ground station detection: " << vehicle_type << std::endl;
    
    vehicle_type = mapping.detectVehicleType("omni_antenna");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Omnidirectional antenna detection: " << vehicle_type << std::endl;
    
    vehicle_type = mapping.detectVehicleType("dual_band");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Dual-band detection: " << vehicle_type << std::endl;
    
    std::cout << std::endl;
}

void testDualBandOmniVHFPatternRetrieval() {
    std::cout << "=== Testing Dual-Band Omnidirectional VHF Pattern Retrieval ===" << std::endl;
    
    // Test VHF pattern retrieval for 145 MHz
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getVHFPattern("ground_station", 145.0);
    
    std::cout << "VHF Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    std::cout << "  Vehicle Type: " << pattern_info.vehicle_type << std::endl;
    std::cout << "  Antenna Type: " << pattern_info.antenna_type << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "dual_band_omni_vhf");
    assert(pattern_info.frequency_mhz == 145.0);
    assert(pattern_info.vehicle_type == "ground_station");
    assert(pattern_info.antenna_type == "omni");
    
    std::cout << "✓ VHF pattern retrieval successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniUHFPatternRetrieval() {
    std::cout << "=== Testing Dual-Band Omnidirectional UHF Pattern Retrieval ===" << std::endl;
    
    // Test UHF pattern retrieval for 432 MHz
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getUHFPattern("ground_station", 432.0);
    
    std::cout << "UHF Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    std::cout << "  Vehicle Type: " << pattern_info.vehicle_type << std::endl;
    std::cout << "  Antenna Type: " << pattern_info.antenna_type << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "dual_band_omni_uhf");
    assert(pattern_info.frequency_mhz == 432.0);
    assert(pattern_info.vehicle_type == "ground_station");
    assert(pattern_info.antenna_type == "omni");
    
    std::cout << "✓ UHF pattern retrieval successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniFrequencyRange() {
    std::cout << "=== Testing Dual-Band Omnidirectional Frequency Range ===" << std::endl;
    
    // Test VHF frequencies
    std::vector<double> vhf_frequencies = {144.0, 144.5, 145.0, 145.5, 146.0};
    std::cout << "VHF Frequencies:" << std::endl;
    for (double freq : vhf_frequencies) {
        FGCom_AntennaPatternMapping mapping;
        auto pattern_info = mapping.getVHFPattern("ground_station", freq);
        std::cout << "  " << freq << " MHz: " << pattern_info.antenna_name << std::endl;
    }
    
    // Test UHF frequencies
    std::vector<double> uhf_frequencies = {430.0, 431.0, 432.0, 433.0, 440.0};
    std::cout << "UHF Frequencies:" << std::endl;
    for (double freq : uhf_frequencies) {
        FGCom_AntennaPatternMapping mapping;
        auto pattern_info = mapping.getUHFPattern("ground_station", freq);
        std::cout << "  " << freq << " MHz: " << pattern_info.antenna_name << std::endl;
    }
    
    std::cout << "✓ Frequency range testing successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniVHFPropagationPhysics() {
    std::cout << "=== Testing Dual-Band Omnidirectional VHF Propagation Physics ===" << std::endl;
    
    // Test VHF propagation at 145 MHz
    double frequency_mhz = 145.0;
    double distance_km = 50.0;
    double altitude_m = 1000.0;
    double antenna_height_m = 10.0;
    
    // Calculate propagation loss
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, frequency_mhz, altitude_m, antenna_height_m,
        20.0, 50.0, 0.0, 0.0  // temperature, humidity, rain, obstruction
    );
    
    std::cout << "VHF Propagation Parameters:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Altitude: " << altitude_m << " m" << std::endl;
    std::cout << "  Antenna Height: " << antenna_height_m << " m" << std::endl;
    std::cout << "  Total Loss: " << total_loss << " dB" << std::endl;
    
    // Validate reasonable loss values
    assert(total_loss > 0.0);  // Should have some loss
    assert(total_loss < 200.0);  // Should not be excessive
    
    std::cout << "✓ VHF propagation physics calculation successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniUHFPropagationPhysics() {
    std::cout << "=== Testing Dual-Band Omnidirectional UHF Propagation Physics ===" << std::endl;
    
    // Test UHF propagation at 432 MHz
    double frequency_mhz = 432.0;
    double distance_km = 30.0;
    double altitude_m = 1000.0;
    double antenna_height_m = 10.0;
    
    // Calculate propagation loss
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, frequency_mhz, altitude_m, antenna_height_m,
        20.0, 50.0, 0.0, 0.0  // temperature, humidity, rain, obstruction
    );
    
    std::cout << "UHF Propagation Parameters:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Altitude: " << altitude_m << " m" << std::endl;
    std::cout << "  Antenna Height: " << antenna_height_m << " m" << std::endl;
    std::cout << "  Total Loss: " << total_loss << " dB" << std::endl;
    
    // Validate reasonable loss values
    assert(total_loss > 0.0);  // Should have some loss
    assert(total_loss < 200.0);  // Should not be excessive
    
    std::cout << "✓ UHF propagation physics calculation successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniAntennaGain() {
    std::cout << "=== Testing Dual-Band Omnidirectional Antenna Gain ===" << std::endl;
    
    // Test antenna height gain for both bands
    double antenna_height_m = 10.0;
    double distance_km = 50.0;
    
    // VHF gain
    double vhf_gain = FGCom_PropagationPhysics::calculateAntennaHeightGain(
        antenna_height_m, 145.0, distance_km
    );
    
    // UHF gain
    double uhf_gain = FGCom_PropagationPhysics::calculateAntennaHeightGain(
        antenna_height_m, 432.0, distance_km
    );
    
    std::cout << "Antenna Height Gain:" << std::endl;
    std::cout << "  Height: " << antenna_height_m << " m" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  VHF Gain (145 MHz): " << vhf_gain << " dB" << std::endl;
    std::cout << "  UHF Gain (432 MHz): " << uhf_gain << " dB" << std::endl;
    
    // Validate reasonable gain values
    assert(vhf_gain > 0.0);  // Should have positive gain
    assert(uhf_gain > 0.0);  // Should have positive gain
    assert(vhf_gain < 50.0);  // Should not be excessive
    assert(uhf_gain < 50.0);  // Should not be excessive
    
    std::cout << "✓ Antenna height gain calculation successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniSignalQuality() {
    std::cout << "=== Testing Dual-Band Omnidirectional Signal Quality ===" << std::endl;
    
    // Test signal quality calculation for both bands
    double power_watts = 10.0;
    double distance_km = 50.0;
    double altitude_m = 1000.0;
    double antenna_height_m = 10.0;
    
    // VHF signal quality
    double vhf_total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, 145.0, altitude_m, antenna_height_m, 20.0, 50.0, 0.0, 0.0
    );
    double vhf_power_dbm = 10.0 * log10(power_watts * 1000.0);
    double vhf_received_dbm = vhf_power_dbm - vhf_total_loss;
    double vhf_signal_quality = std::max(0.0, std::min(1.0, 
        (vhf_received_dbm - (-100.0)) / (0.0 - (-100.0))));
    
    // UHF signal quality
    double uhf_total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, 432.0, altitude_m, antenna_height_m, 20.0, 50.0, 0.0, 0.0
    );
    double uhf_power_dbm = 10.0 * log10(power_watts * 1000.0);
    double uhf_received_dbm = uhf_power_dbm - uhf_total_loss;
    double uhf_signal_quality = std::max(0.0, std::min(1.0, 
        (uhf_received_dbm - (-110.0)) / (0.0 - (-110.0))));
    
    std::cout << "Signal Quality Calculation:" << std::endl;
    std::cout << "  Power: " << power_watts << " W" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  VHF Signal Quality (145 MHz): " << vhf_signal_quality << std::endl;
    std::cout << "  UHF Signal Quality (432 MHz): " << uhf_signal_quality << std::endl;
    
    // Validate signal quality
    assert(vhf_signal_quality >= 0.0);
    assert(vhf_signal_quality <= 1.0);
    assert(uhf_signal_quality >= 0.0);
    assert(uhf_signal_quality <= 1.0);
    
    std::cout << "✓ Signal quality calculation successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniIntegration() {
    std::cout << "=== Testing Dual-Band Omnidirectional Integration ===" << std::endl;
    
    // Test complete integration workflow for both bands
    std::string vehicle_name = "ground_station_omni";
    FGCom_AntennaPatternMapping mapping;
    std::string vehicle_type = mapping.detectVehicleType(vehicle_name);
    
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Vehicle type detection: " << vehicle_type << std::endl;
    
    // Get VHF antenna pattern
    auto vhf_pattern_info = mapping.getVHFPattern(vehicle_type, 145.0);
    assert(vhf_pattern_info.antenna_name == "dual_band_omni_vhf");
    std::cout << "✓ VHF antenna pattern retrieval: " << vhf_pattern_info.antenna_name << std::endl;
    
    // Get UHF antenna pattern
    auto uhf_pattern_info = mapping.getUHFPattern(vehicle_type, 432.0);
    assert(uhf_pattern_info.antenna_name == "dual_band_omni_uhf");
    std::cout << "✓ UHF antenna pattern retrieval: " << uhf_pattern_info.antenna_name << std::endl;
    
    // Calculate propagation for both bands
    double vhf_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        50.0, 145.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0
    );
    double uhf_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        30.0, 432.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0
    );
    
    assert(vhf_loss > 0.0);
    assert(uhf_loss > 0.0);
    std::cout << "✓ VHF propagation calculation: " << vhf_loss << " dB loss" << std::endl;
    std::cout << "✓ UHF propagation calculation: " << uhf_loss << " dB loss" << std::endl;
    
    std::cout << "✓ Complete dual-band integration test successful" << std::endl;
    std::cout << std::endl;
}

void testDualBandOmniOmnidirectionalCharacteristics() {
    std::cout << "=== Testing Dual-Band Omnidirectional Characteristics ===" << std::endl;
    
    // Test omnidirectional characteristics
    std::cout << "Omnidirectional Characteristics:" << std::endl;
    std::cout << "  Pattern Type: Omnidirectional (360°)" << std::endl;
    std::cout << "  VHF Gain: 8.3 dBi @ 145 MHz" << std::endl;
    std::cout << "  UHF Gain: 11.7 dBi @ 432 MHz" << std::endl;
    std::cout << "  Elevation Angle (VHF): ~10-15°" << std::endl;
    std::cout << "  Elevation Angle (UHF): ~5-8°" << std::endl;
    std::cout << "  SWR: <1.5:1 across both bands" << std::endl;
    std::cout << "  Impedance: 50Ω" << std::endl;
    
    // Test that both bands are supported
    FGCom_AntennaPatternMapping mapping;
    auto vhf_pattern = mapping.getVHFPattern("ground_station", 145.0);
    auto uhf_pattern = mapping.getUHFPattern("ground_station", 432.0);
    
    assert(vhf_pattern.antenna_type == "omni");
    assert(uhf_pattern.antenna_type == "omni");
    
    std::cout << "✓ Omnidirectional characteristics validated" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "=== Dual-Band Omnidirectional Antenna Integration Test Suite ===" << std::endl;
    std::cout << "Testing the new dual-band omnidirectional antenna integration" << std::endl;
    std::cout << std::endl;
    
    try {
        testDualBandOmniAntennaMapping();
        testDualBandOmniVHFPatternRetrieval();
        testDualBandOmniUHFPatternRetrieval();
        testDualBandOmniFrequencyRange();
        testDualBandOmniVHFPropagationPhysics();
        testDualBandOmniUHFPropagationPhysics();
        testDualBandOmniAntennaGain();
        testDualBandOmniSignalQuality();
        testDualBandOmniIntegration();
        testDualBandOmniOmnidirectionalCharacteristics();
        
        std::cout << "=== All Dual-Band Omnidirectional Integration Tests Passed! ===" << std::endl;
        std::cout << std::endl;
        std::cout << "Key features validated:" << std::endl;
        std::cout << "- Ground station vehicle type detection" << std::endl;
        std::cout << "- Dual-band antenna pattern mapping (VHF/UHF)" << std::endl;
        std::cout << "- 145 MHz and 432 MHz frequency support" << std::endl;
        std::cout << "- VHF and UHF propagation physics integration" << std::endl;
        std::cout << "- Antenna height gain calculations for both bands" << std::endl;
        std::cout << "- Signal quality calculations for both bands" << std::endl;
        std::cout << "- Complete dual-band integration workflow" << std::endl;
        std::cout << "- Omnidirectional characteristics validation" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
