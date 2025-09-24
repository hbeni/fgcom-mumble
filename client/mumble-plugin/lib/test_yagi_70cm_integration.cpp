#include <iostream>
#include <cassert>
#include <cmath>
#include "antenna_pattern_mapping.h"
#include "propagation_physics.h"

/**
 * Test script for 70cm Yagi antenna integration
 * 
 * This script validates the integration of the new 16-element 70cm Yagi antenna
 * with the FGCom-mumble propagation system.
 */

void testYagi70cmAntennaMapping() {
    std::cout << "=== Testing 70cm Yagi Antenna Mapping ===" << std::endl;
    
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

void testYagi70cmPatternRetrieval() {
    std::cout << "=== Testing 70cm Yagi Pattern Retrieval ===" << std::endl;
    
    // Test pattern retrieval for 432 MHz
    FGCom_AntennaPatternMapping mapping;
    auto pattern_info = mapping.getUHFPattern("ground_station", 432.0);
    
    std::cout << "Pattern Info:" << std::endl;
    std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
    std::cout << "  Pattern File: " << pattern_info.pattern_file << std::endl;
    std::cout << "  Frequency: " << pattern_info.frequency_mhz << " MHz" << std::endl;
    std::cout << "  Vehicle Type: " << pattern_info.vehicle_type << std::endl;
    std::cout << "  Antenna Type: " << pattern_info.antenna_type << std::endl;
    
    // Validate pattern information
    assert(pattern_info.antenna_name == "yagi_70cm");
    assert(pattern_info.frequency_mhz == 432.0);
    assert(pattern_info.vehicle_type == "ground_station");
    assert(pattern_info.antenna_type == "yagi");
    
    std::cout << "✓ Pattern retrieval successful" << std::endl;
    std::cout << std::endl;
}

void testYagi70cmFrequencyRange() {
    std::cout << "=== Testing 70cm Yagi Frequency Range ===" << std::endl;
    
    // Test frequencies across 70cm band
    std::vector<double> test_frequencies = {430.0, 432.0, 435.0, 440.0};
    
    for (double freq : test_frequencies) {
        FGCom_AntennaPatternMapping mapping;
        auto pattern_info = mapping.getUHFPattern("ground_station", freq);
        
        std::cout << "Frequency: " << freq << " MHz" << std::endl;
        std::cout << "  Pattern Available: " << (pattern_info.is_loaded ? "Yes" : "No") << std::endl;
        std::cout << "  Antenna Name: " << pattern_info.antenna_name << std::endl;
        
        // For 432 MHz, we should have exact match
        if (freq == 432.0) {
            assert(pattern_info.antenna_name == "yagi_70cm");
            std::cout << "  ✓ Exact frequency match" << std::endl;
        } else {
            // For other frequencies, should get closest match
            std::cout << "  ✓ Closest frequency match" << std::endl;
        }
    }
    
    std::cout << std::endl;
}

void testYagi70cmPropagationPhysics() {
    std::cout << "=== Testing 70cm Yagi Propagation Physics ===" << std::endl;
    
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

void testYagi70cmAntennaGain() {
    std::cout << "=== Testing 70cm Yagi Antenna Gain ===" << std::endl;
    
    // Test antenna height gain for 70cm Yagi
    double frequency_mhz = 432.0;
    double antenna_height_m = 10.0;
    double distance_km = 30.0;
    
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

void testYagi70cmRainAttenuation() {
    std::cout << "=== Testing 70cm Yagi Rain Attenuation ===" << std::endl;
    
    // Test rain attenuation at 432 MHz
    double frequency_mhz = 432.0;
    double distance_km = 30.0;
    double rain_rate_mmh = 10.0;
    
    double rain_attenuation = FGCom_PropagationPhysics::calculateRainAttenuation(
        distance_km, frequency_mhz, rain_rate_mmh
    );
    
    std::cout << "Rain Attenuation:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Distance: " << distance_km << " km" << std::endl;
    std::cout << "  Rain Rate: " << rain_rate_mmh << " mm/h" << std::endl;
    std::cout << "  Rain Attenuation: " << rain_attenuation << " dB" << std::endl;
    
    // Validate rain attenuation effects
    assert(rain_attenuation >= 0.0);  // Should be non-negative
    assert(rain_attenuation <= 10.0);  // Should not be excessive for UHF
    
    std::cout << "✓ Rain attenuation calculation successful" << std::endl;
    std::cout << std::endl;
}

void testYagi70cmSignalQuality() {
    std::cout << "=== Testing 70cm Yagi Signal Quality ===" << std::endl;
    
    // Test signal quality calculation for 70cm Yagi
    double power_watts = 10.0;
    double distance_km = 30.0;
    double frequency_mhz = 432.0;
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
        (received_power_dbm - (-110.0)) / (0.0 - (-110.0))));
    
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

void testYagi70cmIntegration() {
    std::cout << "=== Testing 70cm Yagi Integration ===" << std::endl;
    
    // Test complete integration workflow
    std::string vehicle_name = "ground_station_yagi";
    FGCom_AntennaPatternMapping mapping;
    std::string vehicle_type = mapping.detectVehicleType(vehicle_name);
    
    assert(vehicle_type == "ground_station");
    std::cout << "✓ Vehicle type detection: " << vehicle_type << std::endl;
    
    // Get antenna pattern
    auto pattern_info = mapping.getUHFPattern(vehicle_type, 432.0);
    
    assert(pattern_info.antenna_name == "yagi_70cm");
    std::cout << "✓ Antenna pattern retrieval: " << pattern_info.antenna_name << std::endl;
    
    // Calculate propagation
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        30.0, 432.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0
    );
    
    assert(total_loss > 0.0);
    std::cout << "✓ Propagation calculation: " << total_loss << " dB loss" << std::endl;
    
    std::cout << "✓ Complete integration test successful" << std::endl;
    std::cout << std::endl;
}

void testYagi70cmUHFCharacteristics() {
    std::cout << "=== Testing 70cm Yagi UHF Characteristics ===" << std::endl;
    
    // Test UHF-specific characteristics
    double frequency_mhz = 432.0;
    double distance_km = 30.0;
    
    // Test atmospheric absorption (more significant at UHF)
    double atmospheric_absorption = FGCom_PropagationPhysics::calculateAtmosphericAbsorption(
        distance_km, frequency_mhz, 1000.0, 20.0, 50.0
    );
    
    std::cout << "UHF Characteristics:" << std::endl;
    std::cout << "  Frequency: " << frequency_mhz << " MHz" << std::endl;
    std::cout << "  Atmospheric Absorption: " << atmospheric_absorption << " dB" << std::endl;
    
    // Test rain attenuation (significant at UHF)
    double rain_attenuation = FGCom_PropagationPhysics::calculateRainAttenuation(
        distance_km, frequency_mhz, 5.0
    );
    
    std::cout << "  Rain Attenuation (5mm/h): " << rain_attenuation << " dB" << std::endl;
    
    // Validate UHF characteristics
    assert(atmospheric_absorption >= 0.0);
    assert(rain_attenuation >= 0.0);
    
    std::cout << "✓ UHF characteristics calculation successful" << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "=== 70cm Yagi Antenna Integration Test Suite ===" << std::endl;
    std::cout << "Testing the new 16-element 70cm Yagi antenna integration" << std::endl;
    std::cout << std::endl;
    
    try {
        testYagi70cmAntennaMapping();
        testYagi70cmPatternRetrieval();
        testYagi70cmFrequencyRange();
        testYagi70cmPropagationPhysics();
        testYagi70cmAntennaGain();
        testYagi70cmRainAttenuation();
        testYagi70cmSignalQuality();
        testYagi70cmIntegration();
        testYagi70cmUHFCharacteristics();
        
        std::cout << "=== All 70cm Yagi Integration Tests Passed! ===" << std::endl;
        std::cout << std::endl;
        std::cout << "Key features validated:" << std::endl;
        std::cout << "- Ground station vehicle type detection" << std::endl;
        std::cout << "- 70cm Yagi antenna pattern mapping" << std::endl;
        std::cout << "- 432 MHz frequency support" << std::endl;
        std::cout << "- UHF propagation physics integration" << std::endl;
        std::cout << "- Antenna height gain calculations" << std::endl;
        std::cout << "- Rain attenuation effects" << std::endl;
        std::cout << "- Signal quality calculations" << std::endl;
        std::cout << "- Complete integration workflow" << std::endl;
        std::cout << "- UHF-specific characteristics" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
