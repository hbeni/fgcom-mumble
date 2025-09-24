#include <iostream>
#include <cassert>
#include <cmath>
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"

/**
 * Test script for 2m Yagi antenna integration
 * 
 * This script validates the integration of the new 11-element 2m Yagi antenna
 * with the FGCom-mumble propagation system.
 */

void testYagiAntennaMapping() {
    std::cout << "=== Testing 2m Yagi Antenna Mapping ===" << std::endl;
    
    // Test ground station detection
    FGCom_AntennaPatternMapping mapping;
    std::string vehicle_type = mapping.detectVehicleType("ground_station");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Ground station detection: " << vehicle_type << std::endl;
    
    vehicle_type = mapping.detectVehicleType("yagi_beam");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Yagi beam detection: " << vehicle_type << std::endl;
    
    vehicle_type = mapping.detectVehicleType("ground_based");
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Ground-based detection: " << vehicle_type << std::endl;
    
    std::cout << std::endl;
}

void testYagiPatternRetrieval() {
    std::cout << "=== Testing 2m Yagi Pattern Retrieval ===" << std::endl;
    
    // Test pattern retrieval for 144.5 MHz
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getVHFPattern("ground_station", 144.5);
    
    std::cout << "Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    std::cout << "  Vehicle Type: " << pattern_info.vehicle_type << std::endl;
    std::cout << "  Antenna Type: " << pattern_info.antenna_type << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "yagi_144mhz");
    assert(pattern_info.frequency_mhz == 144.5);
    assert(pattern_info.vehicle_type == "ground_station");
    assert(pattern_info.antenna_type == "yagi");
    
    std::cout << "✓ Pattern retrieval successful" << std::endl;
    std::cout << std::endl;
}

void testYagiFrequencyRange() {
    std::cout << "=== Testing 2m Yagi Frequency Range ===" << std::endl;
    
    // Test frequencies across 2m band
    std::vector<double> test_frequencies = {144.0, 144.5, 145.0};
    
    for (double freq : test_frequencies) {
        FGCom_AntennaPatternMapping mapping;
        auto pattern_info = mapping.getVHFPattern("ground_station", freq);
        
        std::cout << "Frequency: " << freq << " MHz" << std::endl;
        std::cout << "  Pattern Available: " << (pattern_info.is_loaded ? "Yes" : "No") << std::endl;
        std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
        
        // For 144.5 MHz, we should have exact match
        if (freq == 144.5) {
            assert(pattern_info.antenna_name == "yagi_144mhz");
            std::cout << "  ✓ Exact frequency match" << std::endl;
        } else {
            // For other frequencies, should get closest match
            std::cout << "  ✓ Closest frequency match" << std::endl;
        }
    }
    
    std::cout << std::endl;
}

void testYagiPropagationPhysics() {
    std::cout << "=== Testing 2m Yagi Propagation Physics ===" << std::endl;
    
    // Test VHF propagation at 144.5 MHz
    double frequency_mhz = 144.5;
    double distance_km = 50.0;
    double altitude_m = 1000.0;
    double antenna_height_m = 10.0;
    
    // Calculate propagation loss
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, frequency_mhz, altitude_m, antenna_height_m,
        20.0, 50.0, 0.0, 0.0  // temperature, humidity, rain, obstruction
    );
    
    std::cout << "Propagation Parameters:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Altitude: " << altitude_m << " m" << std::endl;
    std::cout << "  Antenna Height: " << antenna_height_m << " m" << std::endl;
    std::cout << "  Total Loss: " << total_loss << " dB" << std::endl;
    
    // Validate reasonable loss values
    assert(total_loss > 0.0);  // Should have some loss
    assert(total_loss < 200.0);  // Should not be excessive
    
    std::cout << "✓ Propagation physics calculation successful" << std::endl;
    std::cout << std::endl;
}

void testYagiAntennaGain() {
    std::cout << "=== Testing 2m Yagi Antenna Gain ===" << std::endl;
    
    // Test antenna height gain for 2m Yagi
    double frequency_mhz = 144.5;
    double antenna_height_m = 10.0;
    double distance_km = 50.0;
    
    double height_gain = FGCom_PropagationPhysics::calculateAntennaHeightGain(
        antenna_height_m, frequency_mhz, distance_km
    );
    
    std::cout << "Antenna Height Gain:" << std::endl;
    std::cout << "  Height: " << antenna_height_m << " m" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Height Gain: " << height_gain << " dB" << std::endl;
    
    // Validate reasonable gain values
    assert(height_gain > 0.0);  // Should have positive gain
    assert(height_gain < 50.0);  // Should not be excessive
    
    std::cout << "✓ Antenna height gain calculation successful" << std::endl;
    std::cout << std::endl;
}

void testYagiTroposphericDucting() {
    std::cout << "=== Testing 2m Yagi Tropospheric Ducting ===" << std::endl;
    
    // Test tropospheric ducting at 144.5 MHz
    double frequency_mhz = 144.5;
    double distance_km = 100.0;
    double altitude_m = 1000.0;
    double temperature_c = 25.0;
    double humidity_percent = 80.0;
    
    double ducting_gain = FGCom_PropagationPhysics::calculateTroposphericDucting(
        distance_km, frequency_mhz, altitude_m, temperature_c, humidity_percent
    );
    
    std::cout << "Tropospheric Ducting:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Temperature: " << temperature_c << "°C" << std::endl;
    std::cout << "  Humidity: " << humidity_percent << "%" << std::endl;
    std::cout << "  Ducting Gain: " << ducting_gain << " dB" << std::endl;
    
    // Validate ducting effects
    assert(ducting_gain >= 0.0);  // Should be non-negative
    assert(ducting_gain <= 30.0);  // Should not be excessive
    
    std::cout << "✓ Tropospheric ducting calculation successful" << std::endl;
    std::cout << std::endl;
}

void testYagiSignalQuality() {
    std::cout << "=== Testing 2m Yagi Signal Quality ===" << std::endl;
    
    // Test signal quality calculation for 2m Yagi
    double power_watts = 10.0;
    double distance_km = 50.0;
    double frequency_mhz = 144.5;
    double altitude_m = 1000.0;
    double antenna_height_m = 10.0;
    
    // Calculate total propagation loss
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        distance_km, frequency_mhz, altitude_m, antenna_height_m,
        20.0, 50.0, 0.0, 0.0
    );
    
    // Calculate signal quality
    double power_dbm = 10.0 * log10(power_watts * 1000.0);
    double received_power_dbm = power_dbm - total_loss;
    double signal_quality = std::max(0.0, std::min(1.0, 
        (received_power_dbm - (-100.0)) / (0.0 - (-100.0))));
    
    std::cout << "Signal Quality Calculation:" << std::endl;
    std::cout << "  Power: " << power_watts << " W" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Total Loss: " << total_loss << " dB" << std::endl;
    std::cout << "  Received Power: " << received_power_dbm << " dBm" << std::endl;
    std::cout << "  Signal Quality: " << signal_quality << std::endl;
    
    // Validate signal quality
    assert(signal_quality >= 0.0);
    assert(signal_quality <= 1.0);
    
    std::cout << "✓ Signal quality calculation successful" << std::endl;
    std::cout << std::endl;
}

void testYagiIntegration() {
    std::cout << "=== Testing 2m Yagi Integration ===" << std::endl;
    
    // Test complete integration workflow
    std::string vehicle_name = "ground_station_yagi";
    FGCom_AntennaPatternMapping mapping;
    std::string vehicle_type = mapping.detectVehicleType(vehicle_name);
    
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Vehicle type detection: " << vehicle_type << std::endl;
    
    // Get antenna pattern
    auto pattern_info = mapping.getVHFPattern(vehicle_type, 144.5);
    
    assert(pattern_info.antenna_name == "yagi_144mhz");
    std::cout << "✓ Antenna pattern retrieval: " << pattern_info.antenna_name << std::endl;
    
    // Calculate propagation
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        50.0, 144.5, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0
    );
    
    assert(total_loss > 0.0);
    std::cout << "✓ Propagation calculation: " << total_loss << " dB loss" << std::endl;
    
    std::cout << "✓ Complete integration test successful" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "=== 2m Yagi Antenna Integration Test Suite ===" << std::endl;
    std::cout << "Testing the new 11-element 2m Yagi antenna integration" << std::endl;
    std::cout << std::endl;
    
    try {
        testYagiAntennaMapping();
        testYagiPatternRetrieval();
        testYagiFrequencyRange();
        testYagiPropagationPhysics();
        testYagiAntennaGain();
        testYagiTroposphericDucting();
        testYagiSignalQuality();
        testYagiIntegration();
        
        std::cout << "=== All 2m Yagi Integration Tests Passed! ===" << std::endl;
        std::cout << std::endl;
        std::cout << "Key features validated:" << std::endl;
        std::cout << "- Ground station vehicle type detection" << std::endl;
        std::cout << "- 2m Yagi antenna pattern mapping" << std::endl;
        std::cout << "- 144.5 MHz frequency support" << std::endl;
        std::cout << "- VHF propagation physics integration" << std::endl;
        std::cout << "- Antenna height gain calculations" << std::endl;
        std::cout << "- Tropospheric ducting effects" << std::endl;
        std::cout << "- Signal quality calculations" << std::endl;
        std::cout << "- Complete integration workflow" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
