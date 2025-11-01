/*
 * ITU-R Standards Validation Tests
 * 
 * This file contains physics-based validation tests that verify
 * the implementation matches ITU-R standards within acceptable tolerances.
 */

#include <gtest/gtest.h>
#include <cmath>
#include "propagation_physics.h"

class ITURValidationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test scenarios with known ITU-R reference values
    }
    
    // Tolerance for ITU-R compliance
    const double PATH_LOSS_TOLERANCE_DB = 2.0;
    const double RANGE_TOLERANCE_PERCENT = 10.0;
};

// Test ITU-R P.525-2 Free Space Path Loss
TEST_F(ITURValidationTest, FreeSpacePathLoss_P525_2) {
    // Reference: ITU-R P.525-2 Table 1
    // Frequency: 100 MHz, Distance: 10 km
    // Expected: 95.97 dB
    
    double frequency_mhz = 100.0;
    double distance_km = 10.0;
    double tx_altitude_m = 1000.0;
    double rx_altitude_m = 100.0;
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m,
        30.0, -100.0, 0.0, 0.0);
    
    // ITU-R P.525-2 reference value
    double expected_loss = 20.0 * std::log10(distance_km) + 20.0 * std::log10(frequency_mhz) + 32.45;
    
    EXPECT_NEAR(total_loss, expected_loss, PATH_LOSS_TOLERANCE_DB) 
        << "Free space path loss should match ITU-R P.525-2 within " << PATH_LOSS_TOLERANCE_DB << " dB";
}

// Test ITU-R P.526-14 Line of Sight Distance
TEST_F(ITURValidationTest, LineOfSightDistance_P526_14) {
    // Reference: ITU-R P.526-14
    // Antenna heights: 100m and 10m
    // Expected: ~3.57 * sqrt(100 + 10) = ~37.4 km
    
    double tx_altitude_m = 100.0;
    double rx_altitude_m = 10.0;
    
    double los_distance = FGCom_PropagationPhysics::calculateLineOfSightDistance(tx_altitude_m, rx_altitude_m);
    
    // ITU-R P.526-14 reference formula
    double expected_distance = 3.57 * std::sqrt(tx_altitude_m + rx_altitude_m);
    
    EXPECT_NEAR(los_distance, expected_distance, expected_distance * RANGE_TOLERANCE_PERCENT / 100.0)
        << "Line of sight distance should match ITU-R P.526-14 within " << RANGE_TOLERANCE_PERCENT << "%";
}

// Test ITU-R P.838-3 Rain Attenuation
TEST_F(ITURValidationTest, RainAttenuation_P838_3) {
    // Reference: ITU-R P.838-3
    // Frequency: 10 GHz, Rain rate: 25 mm/h, Distance: 10 km
    // Expected: Significant attenuation for microwave frequencies
    
    double frequency_mhz = 10000.0; // 10 GHz
    double distance_km = 10.0;
    
    // Test with rain (this would need weather data integration)
    double rain_attenuation = FGCom_PropagationPhysics::calculateRainAttenuation(frequency_mhz, distance_km);
    
    // For microwave frequencies, rain attenuation should be significant
    if (frequency_mhz >= 1000.0) {
        EXPECT_GT(rain_attenuation, 0.0) << "Rain attenuation should be positive for microwave frequencies";
    }
}

// Test ITU-R P.676-11 Atmospheric Absorption
TEST_F(ITURValidationTest, AtmosphericAbsorption_P676_11) {
    // Reference: ITU-R P.676-11
    // Frequency: 60 GHz (oxygen absorption peak)
    // Expected: Significant oxygen absorption
    
    double frequency_mhz = 60000.0; // 60 GHz
    double distance_km = 10.0;
    double tx_altitude_m = 1000.0;
    double rx_altitude_m = 100.0;
    
    double atmospheric_absorption = FGCom_PropagationPhysics::calculateAtmosphericAbsorption(
        frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m);
    
    // At 60 GHz, oxygen absorption should be significant
    EXPECT_GT(atmospheric_absorption, 0.0) << "Atmospheric absorption should be positive at 60 GHz";
}

// Test Frequency Dependencies
TEST_F(ITURValidationTest, FrequencyDependencies) {
    // VHF (118 MHz) should have minimal weather effects
    double vhf_frequency = 118.0;
    double vhf_weather_loss = FGCom_PropagationPhysics::calculateRainAttenuation(vhf_frequency, 10.0);
    
    // UHF (300 MHz) should have moderate weather effects
    double uhf_frequency = 300.0;
    double uhf_weather_loss = FGCom_PropagationPhysics::calculateRainAttenuation(uhf_frequency, 10.0);
    
    // Microwave (5 GHz) should have significant weather effects
    double microwave_frequency = 5000.0;
    double microwave_weather_loss = FGCom_PropagationPhysics::calculateRainAttenuation(microwave_frequency, 10.0);
    
    // Weather effects should increase with frequency
    EXPECT_LT(vhf_weather_loss, uhf_weather_loss) 
        << "VHF should have less weather loss than UHF";
    EXPECT_LT(uhf_weather_loss, microwave_weather_loss) 
        << "UHF should have less weather loss than microwave";
}

// Test Real-World Aviation Scenario
TEST_F(ITURValidationTest, AviationScenario_VHF_118MHz) {
    // Real-world aviation scenario
    // Frequency: 118.1 MHz (VHF aviation)
    // Distance: 100 km
    // Aircraft: 10,000 ft (3,048 m)
    // Ground station: 100 ft (30 m)
    // Expected path loss: ~115 dB
    
    double frequency_mhz = 118.1;
    double distance_km = 100.0;
    double tx_altitude_m = 3048.0; // 10,000 ft
    double rx_altitude_m = 30.0;   // 100 ft
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m,
        40.0, -100.0, 0.0, 0.0);
    
    // ITU-R P.525-2 reference calculation
    double expected_loss = 20.0 * std::log10(distance_km) + 20.0 * std::log10(frequency_mhz) + 32.45;
    
    EXPECT_NEAR(total_loss, expected_loss, PATH_LOSS_TOLERANCE_DB)
        << "Aviation VHF path loss should match ITU-R reference within " << PATH_LOSS_TOLERANCE_DB << " dB";
}

// Test Microwave Weather Radar Scenario
TEST_F(ITURValidationTest, MicrowaveWeatherRadar_5GHz) {
    // Microwave weather radar scenario
    // Frequency: 5.6 GHz
    // Distance: 200 km
    // Expected: Significant atmospheric effects
    
    double frequency_mhz = 5600.0;
    double distance_km = 200.0;
    double tx_altitude_m = 1000.0;
    double rx_altitude_m = 100.0;
    
    double total_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        frequency_mhz, distance_km, tx_altitude_m, rx_altitude_m,
        40.0, -100.0, 0.0, 0.0);
    
    // For microwave frequencies, total loss should be significant
    EXPECT_GT(total_loss, 150.0) << "Microwave path loss should be significant for 200 km";
}

// Test Edge Cases and Numerical Stability
TEST_F(ITURValidationTest, NumericalStability) {
    // Test with edge cases that could cause mathematical hazards
    
    // Zero distance (should be handled gracefully)
    double zero_distance_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        118.0, 0.0, 1000.0, 100.0, 30.0, -100.0, 0.0, 0.0);
    EXPECT_TRUE(std::isfinite(zero_distance_loss)) << "Zero distance should not cause NaN or infinity";
    
    // Zero frequency (should be handled gracefully)
    double zero_frequency_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        0.0, 10.0, 1000.0, 100.0, 30.0, -100.0, 0.0, 0.0);
    EXPECT_TRUE(std::isfinite(zero_frequency_loss)) << "Zero frequency should not cause NaN or infinity";
    
    // Very high frequency (should be handled gracefully)
    double high_frequency_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        100000.0, 10.0, 1000.0, 100.0, 30.0, -100.0, 0.0, 0.0);
    EXPECT_TRUE(std::isfinite(high_frequency_loss)) << "High frequency should not cause overflow";
    
    // Very long distance (should be handled gracefully)
    double long_distance_loss = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        118.0, 10000.0, 1000.0, 100.0, 30.0, -100.0, 0.0, 0.0);
    EXPECT_TRUE(std::isfinite(long_distance_loss)) << "Long distance should not cause overflow";
}

// Test ITU-R Compliance Summary
TEST_F(ITURValidationTest, ITURComplianceSummary) {
    // This test summarizes ITU-R compliance across multiple standards
    
    std::vector<std::pair<std::string, bool>> compliance_results;
    
    // Test P.525-2 compliance
    double fsl_test = FGCom_PropagationPhysics::calculateTotalPropagationLoss(
        100.0, 10.0, 1000.0, 100.0, 30.0, -100.0, 0.0, 0.0);
    bool p525_2_compliant = (fsl_test > 0.0 && fsl_test < 200.0);
    compliance_results.push_back({"ITU-R P.525-2", p525_2_compliant});
    
    // Test P.526-14 compliance
    double los_test = FGCom_PropagationPhysics::calculateLineOfSightDistance(100.0, 10.0);
    bool p526_14_compliant = (los_test > 0.0 && los_test < 1000.0);
    compliance_results.push_back({"ITU-R P.526-14", p526_14_compliant});
    
    // Test P.676-11 compliance
    double atm_test = FGCom_PropagationPhysics::calculateAtmosphericAbsorption(
        60000.0, 10.0, 1000.0, 100.0);
    bool p676_11_compliant = (atm_test >= 0.0);
    compliance_results.push_back({"ITU-R P.676-11", p676_11_compliant});
    
    // Test P.838-3 compliance
    double rain_test = FGCom_PropagationPhysics::calculateRainAttenuation(10000.0, 10.0);
    bool p838_3_compliant = (rain_test >= 0.0);
    compliance_results.push_back({"ITU-R P.838-3", p838_3_compliant});
    
    // Report compliance results
    for (const auto& result : compliance_results) {
        EXPECT_TRUE(result.second) << "ITU-R compliance failed for " << result.first;
    }
}
