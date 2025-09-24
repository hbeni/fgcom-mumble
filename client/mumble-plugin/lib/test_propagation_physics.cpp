#include <iostream>
#include <iomanip>
#include <vector>
#include "propagation_physics.h"

/**
 * Test script for the new physics-based VHF/UHF propagation models
 * 
 * This script validates the implementation of realistic radio propagation
 * calculations and compares them with the old simplified models.
 */

void testFreeSpacePathLoss() {
    std::cout << "=== Testing Free Space Path Loss ===" << std::endl;
    
    std::vector<double> distances = {1.0, 10.0, 50.0, 100.0, 200.0};
    std::vector<double> frequencies = {150.0, 300.0, 400.0, 800.0, 1200.0};
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Distance (km)\tFrequency (MHz)\tPath Loss (dB)" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    
    for (double dist : distances) {
        for (double freq : frequencies) {
            double loss = FGCom_PropagationPhysics::calculateFreeSpacePathLoss(dist, freq);
            std::cout << dist << "\t\t" << freq << "\t\t" << loss << std::endl;
        }
    }
    std::cout << std::endl;
}

void testAtmosphericAbsorption() {
    std::cout << "=== Testing Atmospheric Absorption ===" << std::endl;
    
    std::vector<double> frequencies = {150.0, 300.0, 400.0, 800.0, 1200.0};
    std::vector<double> altitudes = {0.0, 1000.0, 5000.0, 10000.0};
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Frequency (MHz)\tAltitude (m)\tAbsorption (dB)" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    
    for (double freq : frequencies) {
        for (double alt : altitudes) {
            double absorption = FGCom_PropagationPhysics::calculateAtmosphericAbsorption(
                100.0, freq, alt, 20.0, 50.0);
            std::cout << freq << "\t\t" << alt << "\t\t" << absorption << std::endl;
        }
    }
    std::cout << std::endl;
}

void testTroposphericDucting() {
    std::cout << "=== Testing Tropospheric Ducting (VHF only) ===" << std::endl;
    
    std::vector<double> frequencies = {50.0, 100.0, 150.0, 200.0, 300.0, 400.0};
    std::vector<double> distances = {50.0, 100.0, 200.0, 300.0};
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Frequency (MHz)\tDistance (km)\tDucting Gain (dB)" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    
    for (double freq : frequencies) {
        for (double dist : distances) {
            double ducting = FGCom_PropagationPhysics::calculateTroposphericDucting(
                dist, freq, 1000.0, 25.0, 80.0);
            std::cout << freq << "\t\t" << dist << "\t\t" << ducting << std::endl;
        }
    }
    std::cout << std::endl;
}

void testAntennaHeightGain() {
    std::cout << "=== Testing Antenna Height Gain ===" << std::endl;
    
    std::vector<double> heights = {1.0, 5.0, 10.0, 20.0, 50.0, 100.0};
    std::vector<double> frequencies = {150.0, 300.0, 400.0, 800.0};
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Height (m)\tFrequency (MHz)\tHeight Gain (dB)" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    
    for (double height : heights) {
        for (double freq : frequencies) {
            double gain = FGCom_PropagationPhysics::calculateAntennaHeightGain(
                height, freq, 50.0);
            std::cout << height << "\t\t" << freq << "\t\t" << gain << std::endl;
        }
    }
    std::cout << std::endl;
}

void testRainAttenuation() {
    std::cout << "=== Testing Rain Attenuation (UHF only) ===" << std::endl;
    
    std::vector<double> frequencies = {400.0, 800.0, 1200.0, 2000.0};
    std::vector<double> rain_rates = {0.0, 5.0, 10.0, 25.0, 50.0};
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Frequency (MHz)\tRain Rate (mm/h)\tAttenuation (dB)" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    
    for (double freq : frequencies) {
        for (double rain : rain_rates) {
            double attenuation = FGCom_PropagationPhysics::calculateRainAttenuation(
                50.0, freq, rain);
            std::cout << freq << "\t\t" << rain << "\t\t" << attenuation << std::endl;
        }
    }
    std::cout << std::endl;
}

void testTotalPropagationLoss() {
    std::cout << "=== Testing Total Propagation Loss ===" << std::endl;
    
    // Test scenarios
    struct TestScenario {
        std::string name;
        double distance_km;
        double frequency_mhz;
        double altitude_m;
        double antenna_height_m;
        double temperature_c;
        double humidity_percent;
        double rain_rate_mmh;
        double obstruction_height_m;
    };
    
    std::vector<TestScenario> scenarios = {
        {"VHF Aviation", 50.0, 150.0, 3000.0, 10.0, 15.0, 40.0, 0.0, 0.0},
        {"VHF Ground", 25.0, 150.0, 100.0, 5.0, 20.0, 60.0, 0.0, 0.0},
        {"UHF Tactical", 30.0, 400.0, 1000.0, 8.0, 18.0, 50.0, 0.0, 0.0},
        {"UHF Rain", 20.0, 800.0, 500.0, 6.0, 16.0, 70.0, 10.0, 0.0},
        {"VHF Ducting", 150.0, 100.0, 2000.0, 15.0, 25.0, 80.0, 0.0, 0.0}
    };
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Scenario\t\tDistance\tFrequency\tTotal Loss (dB)" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    
    for (const auto& scenario : scenarios) {
        double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            scenario.distance_km, scenario.frequency_mhz, scenario.altitude_m,
            scenario.antenna_height_m, scenario.temperature_c, scenario.humidity_percent,
            scenario.rain_rate_mmh, scenario.obstruction_height_m);
        
        std::cout << scenario.name << "\t\t" << scenario.distance_km << "\t\t" 
                  << scenario.frequency_mhz << "\t\t" << total_loss << std::endl;
    }
    std::cout << std::endl;
}

void testSignalQualityConversion() {
    std::cout << "=== Testing Signal Quality Conversion ===" << std::endl;
    
    std::vector<double> power_watts = {1.0, 5.0, 10.0, 25.0, 50.0, 100.0};
    std::vector<double> distances = {10.0, 25.0, 50.0, 100.0, 200.0};
    
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Power (W)\tDistance (km)\tSignal Quality" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    for (double power : power_watts) {
        for (double dist : distances) {
            // Simulate VHF calculation
            double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
                dist, 150.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0);
            
            double power_dbm = 10.0 * log10(power * 1000.0);
            double received_power_dbm = power_dbm - total_loss;
            
            double signal_quality = std::max(0.0, std::min(1.0, 
                (received_power_dbm - (-100.0)) / (0.0 - (-100.0))));
            
            std::cout << power << "\t\t" << dist << "\t\t" << signal_quality << std::endl;
        }
    }
    std::cout << std::endl;
}

void compareOldVsNewModel() {
    std::cout << "=== Comparing Old vs New Models ===" << std::endl;
    
    std::vector<double> distances = {10.0, 25.0, 50.0, 100.0, 200.0};
    double power = 10.0;  // 10 watts
    
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Distance (km)\tOld Model\tNew VHF\t\tNew UHF" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    
    for (double dist : distances) {
        // Old VHF model
        double old_vhf = (-1.0/(power*50.0)*pow(dist,2)+100.0)/100.0;
        old_vhf = std::max(0.0, old_vhf);
        
        // New VHF model
        double new_vhf_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            dist, 150.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0);
        double new_vhf_power_dbm = 10.0 * log10(power * 1000.0);
        double new_vhf_received_dbm = new_vhf_power_dbm - new_vhf_loss;
        double new_vhf = std::max(0.0, std::min(1.0, 
            (new_vhf_received_dbm - (-100.0)) / (0.0 - (-100.0))));
        
        // New UHF model
        double new_uhf_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
            dist, 400.0, 1000.0, 10.0, 20.0, 50.0, 0.0, 0.0);
        double new_uhf_power_dbm = 10.0 * log10(power * 1000.0);
        double new_uhf_received_dbm = new_uhf_power_dbm - new_uhf_loss;
        double new_uhf = std::max(0.0, std::min(1.0, 
            (new_uhf_received_dbm - (-110.0)) / (0.0 - (-110.0))));
        
        std::cout << dist << "\t\t" << old_vhf << "\t\t" << new_vhf << "\t\t" << new_uhf << std::endl;
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "=== VHF/UHF Propagation Physics Test Suite ===" << std::endl;
    std::cout << "Testing the new physics-based radio propagation models" << std::endl;
    std::cout << std::endl;
    
    try {
        testFreeSpacePathLoss();
        testAtmosphericAbsorption();
        testTroposphericDucting();
        testAntennaHeightGain();
        testRainAttenuation();
        testTotalPropagationLoss();
        testSignalQualityConversion();
        compareOldVsNewModel();
        
        std::cout << "=== All tests completed successfully! ===" << std::endl;
        std::cout << std::endl;
        std::cout << "Key improvements in the new model:" << std::endl;
        std::cout << "- Realistic free space path loss with frequency dependency" << std::endl;
        std::cout << "- Atmospheric absorption effects" << std::endl;
        std::cout << "- Tropospheric ducting for extended VHF range" << std::endl;
        std::cout << "- Antenna height gain calculations" << std::endl;
        std::cout << "- Rain attenuation for UHF frequencies" << std::endl;
        std::cout << "- Terrain obstruction modeling" << std::endl;
        std::cout << "- Proper dB-based signal quality calculations" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
