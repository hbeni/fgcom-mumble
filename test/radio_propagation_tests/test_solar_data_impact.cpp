#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <cmath>
#include <chrono>
#include <vector>
#include <algorithm>

// Solar data impact on radio propagation tests
// This test demonstrates how solar activity affects radio propagation

class SolarDataImpactTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize solar data test environment
        solar_flux_quiet = 70.0;  // Quiet sun conditions
        solar_flux_active = 200.0; // Active sun conditions
        solar_flux_storm = 300.0;  // Solar storm conditions
        
        // Ionospheric parameters
        f0f2_quiet = 8.0;    // MHz - quiet conditions
        f0f2_active = 12.0;   // MHz - active conditions
        f0f2_storm = 6.0;     // MHz - storm conditions (absorption)
        
        // Frequency bands for testing
        hf_freq = 7.0;        // MHz - HF band (below F0F2 for skywave)
        vhf_freq = 144.0;    // MHz - VHF band
        uhf_freq = 440.0;    // MHz - UHF band
    }
    
    double solar_flux_quiet, solar_flux_active, solar_flux_storm;
    double f0f2_quiet, f0f2_active, f0f2_storm;
    double hf_freq, vhf_freq, uhf_freq;
};

// Test solar flux impact on HF propagation
TEST_F(SolarDataImpactTest, SolarFluxImpactOnHF) {
    // Calculate MUF (Maximum Usable Frequency) based on solar flux
    auto calculate_muf = [](double solar_flux, double f0f2) {
        // Simplified MUF calculation based on solar flux
        return f0f2 * sqrt(1 + (solar_flux - 70.0) / 100.0);
    };
    
    double muf_quiet = calculate_muf(solar_flux_quiet, f0f2_quiet);
    double muf_active = calculate_muf(solar_flux_active, f0f2_active);
    double muf_storm = calculate_muf(solar_flux_storm, f0f2_storm);
    
    // Active sun should increase MUF
    EXPECT_GT(muf_active, muf_quiet) << "Active sun should increase MUF";
    
    // Storm conditions can decrease MUF due to absorption
    EXPECT_LT(muf_storm, muf_active) << "Storm conditions may decrease MUF";
    
    // HF frequency should be usable under active conditions
    EXPECT_GT(muf_active, hf_freq) << "HF should be usable under active sun";
    
    std::cout << "MUF Quiet: " << muf_quiet << " MHz" << std::endl;
    std::cout << "MUF Active: " << muf_active << " MHz" << std::endl;
    std::cout << "MUF Storm: " << muf_storm << " MHz" << std::endl;
}

// Test solar activity impact on propagation range
TEST_F(SolarDataImpactTest, SolarActivityRangeImpact) {
    // Calculate propagation range based on solar conditions
    auto calculate_range = [](double frequency, double solar_flux, double f0f2) {
        // Simplified range calculation
        double base_range = 1000.0; // km
        
        if (frequency < f0f2) {
            // Skywave propagation possible - solar activity increases range
            double solar_factor = 1.0 + (solar_flux - 70.0) / 100.0; // More sensitive to solar flux
            return base_range * solar_factor;
        } else {
            // Line of sight only
            return base_range * 0.1; // Much shorter range
        }
    };
    
    double range_quiet = calculate_range(hf_freq, solar_flux_quiet, f0f2_quiet);
    double range_active = calculate_range(hf_freq, solar_flux_active, f0f2_active);
    double range_storm = calculate_range(hf_freq, solar_flux_storm, f0f2_storm);
    
    // Active sun should increase HF range
    EXPECT_GT(range_active, range_quiet) << "Active sun should increase HF range";
    
    // Storm conditions may reduce range due to absorption
    EXPECT_LT(range_storm, range_active) << "Storm may reduce range";
    
    std::cout << "HF Range Quiet: " << range_quiet << " km" << std::endl;
    std::cout << "HF Range Active: " << range_active << " km" << std::endl;
    std::cout << "HF Range Storm: " << range_storm << " km" << std::endl;
}

// Test solar storm impact on signal absorption
TEST_F(SolarDataImpactTest, SolarStormAbsorption) {
    // Calculate absorption based on solar storm conditions
    auto calculate_absorption = [](double frequency, double solar_flux) {
        // D-layer absorption increases with solar activity
        double absorption_db = 0.0;
        
        if (frequency < 30.0) { // HF frequencies most affected
            absorption_db = (solar_flux - 70.0) * 0.2; // dB - more sensitive to solar flux
        }
        
        return std::max(0.0, absorption_db);
    };
    
    double absorption_quiet = calculate_absorption(hf_freq, solar_flux_quiet);
    double absorption_active = calculate_absorption(hf_freq, solar_flux_active);
    double absorption_storm = calculate_absorption(hf_freq, solar_flux_storm);
    
    // Higher solar flux should increase absorption
    EXPECT_GT(absorption_active, absorption_quiet) << "Active sun increases absorption";
    EXPECT_GT(absorption_storm, absorption_active) << "Storm increases absorption";
    
    std::cout << "Absorption Quiet: " << absorption_quiet << " dB" << std::endl;
    std::cout << "Absorption Active: " << absorption_active << " dB" << std::endl;
    std::cout << "Absorption Storm: " << absorption_storm << " dB" << std::endl;
}

// Test frequency-dependent solar impact
TEST_F(SolarDataImpactTest, FrequencyDependentSolarImpact) {
    // Test how solar activity affects different frequency bands
    auto get_solar_impact = [](double frequency, double solar_flux) {
        double impact = 0.0;
        
        if (frequency < 30.0) { // HF band
            impact = (solar_flux - 70.0) * 0.5; // Strong impact
        } else if (frequency < 300.0) { // VHF band
            impact = (solar_flux - 70.0) * 0.1; // Moderate impact
        } else { // UHF and above
            impact = (solar_flux - 70.0) * 0.01; // Minimal impact
        }
        
        return impact;
    };
    
    double hf_impact = get_solar_impact(hf_freq, solar_flux_active);
    double vhf_impact = get_solar_impact(vhf_freq, solar_flux_active);
    double uhf_impact = get_solar_impact(uhf_freq, solar_flux_active);
    
    // HF should be most affected by solar activity
    EXPECT_GT(hf_impact, vhf_impact) << "HF more affected than VHF";
    EXPECT_GT(vhf_impact, uhf_impact) << "VHF more affected than UHF";
    
    std::cout << "Solar Impact HF: " << hf_impact << std::endl;
    std::cout << "Solar Impact VHF: " << vhf_impact << std::endl;
    std::cout << "Solar Impact UHF: " << uhf_impact << std::endl;
}

// Test solar cycle impact on propagation
TEST_F(SolarDataImpactTest, SolarCycleImpact) {
    // Simulate different phases of solar cycle
    std::vector<double> solar_cycle_flux = {50.0, 70.0, 120.0, 200.0, 150.0, 80.0, 60.0};
    std::vector<std::string> cycle_phases = {"Minimum", "Rising", "Maximum", "Peak", "Declining", "Low", "Minimum"};
    
    auto calculate_propagation_quality = [](double solar_flux, double frequency) {
        double quality = 1.0;
        
        if (frequency < 30.0) { // HF band
            // HF propagation improves with solar activity (up to a point)
            if (solar_flux < 150.0) {
                quality = 0.5 + (solar_flux - 50.0) / 200.0;
            } else {
                // Too much activity can cause absorption
                quality = 1.0 - (solar_flux - 150.0) / 300.0;
            }
        } else {
            // Higher frequencies less affected
            quality = 0.8 + (solar_flux - 50.0) / 1000.0;
        }
        
        return std::max(0.0, std::min(1.0, quality));
    };
    
    for (size_t i = 0; i < solar_cycle_flux.size(); ++i) {
        double quality_hf = calculate_propagation_quality(solar_cycle_flux[i], hf_freq);
        double quality_vhf = calculate_propagation_quality(solar_cycle_flux[i], vhf_freq);
        
        std::cout << "Solar Cycle Phase: " << cycle_phases[i] 
                  << " (Flux: " << solar_cycle_flux[i] << ")"
                  << " - HF Quality: " << quality_hf
                  << " - VHF Quality: " << quality_vhf << std::endl;
    }
    
    // Verify that HF propagation quality varies with solar cycle
    double quality_min = calculate_propagation_quality(50.0, hf_freq);
    double quality_max = calculate_propagation_quality(200.0, hf_freq);
    
    EXPECT_NE(quality_min, quality_max) << "Solar cycle should affect HF propagation";
}

// Test solar data integration with propagation models
TEST_F(SolarDataImpactTest, SolarDataIntegration) {
    // Simulate real-time solar data integration
    struct SolarData {
        double solar_flux;
        double f0f2;
        double k_index;
        double a_index;
        std::chrono::system_clock::time_point timestamp;
    };
    
    auto get_current_solar_data = []() -> SolarData {
        SolarData data;
        data.solar_flux = 120.0; // Current solar flux
        data.f0f2 = 10.0;        // Current F0F2
        data.k_index = 3.0;      // Current K-index
        data.a_index = 15.0;     // Current A-index
        data.timestamp = std::chrono::system_clock::now();
        return data;
    };
    
    auto calculate_propagation_with_solar = [](double frequency, const SolarData& solar) {
        double range = 1000.0; // Base range in km
        
        // Adjust for solar flux
        if (frequency < 30.0) { // HF band
            range *= (1.0 + (solar.solar_flux - 70.0) / 200.0);
        }
        
        // Adjust for geomagnetic activity
        if (solar.k_index > 5.0) {
            range *= 0.8; // Reduce range during high K-index
        }
        
        // Adjust for F0F2
        if (frequency > solar.f0f2) {
            range *= 0.1; // Much reduced range above F0F2
        }
        
        return range;
    };
    
    SolarData current_solar = get_current_solar_data();
    double hf_range = calculate_propagation_with_solar(hf_freq, current_solar);
    double vhf_range = calculate_propagation_with_solar(vhf_freq, current_solar);
    
    EXPECT_GT(hf_range, 0.0) << "HF range should be positive";
    EXPECT_GT(vhf_range, 0.0) << "VHF range should be positive";
    
    std::cout << "Current Solar Data:" << std::endl;
    std::cout << "  Solar Flux: " << current_solar.solar_flux << std::endl;
    std::cout << "  F0F2: " << current_solar.f0f2 << " MHz" << std::endl;
    std::cout << "  K-Index: " << current_solar.k_index << std::endl;
    std::cout << "  A-Index: " << current_solar.a_index << std::endl;
    std::cout << "  HF Range: " << hf_range << " km" << std::endl;
    std::cout << "  VHF Range: " << vhf_range << " km" << std::endl;
}

// Performance test for solar data calculations
TEST_F(SolarDataImpactTest, SolarDataPerformance) {
    const int iterations = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        double solar_flux = 70.0 + (i % 200); // Vary solar flux
        double frequency = 10.0 + (i % 50);   // Vary frequency
        
        // Calculate solar impact
        double impact = (solar_flux - 70.0) * 0.1;
        double range = 1000.0 * (1.0 + impact);
        
        // Simulate some processing
        range = std::sqrt(range * range + impact * impact);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / iterations;
    
    std::cout << "Solar data calculation performance: " 
              << avg_time << " microseconds per calculation" << std::endl;
    
    // Performance should be reasonable
    EXPECT_LT(avg_time, 10.0) << "Solar data calculations should be fast";
}

// Additional test for solar data edge cases
TEST_F(SolarDataImpactTest, SolarDataEdgeCases) {
    // Test extreme solar conditions
    double extreme_quiet = 50.0;  // Very quiet sun
    double extreme_active = 300.0; // Very active sun
    
    auto calculate_muf_extreme = [](double solar_flux, double f0f2) {
        return f0f2 * sqrt(1 + (solar_flux - 70.0) / 100.0);
    };
    
    double muf_extreme_quiet = calculate_muf_extreme(extreme_quiet, 6.0);
    double muf_extreme_active = calculate_muf_extreme(extreme_active, 15.0);
    
    // Even extreme conditions should produce valid results
    EXPECT_GT(muf_extreme_quiet, 0.0) << "Extreme quiet should produce valid MUF";
    EXPECT_GT(muf_extreme_active, 0.0) << "Extreme active should produce valid MUF";
    
    std::cout << "Extreme Quiet MUF: " << muf_extreme_quiet << " MHz" << std::endl;
    std::cout << "Extreme Active MUF: " << muf_extreme_active << " MHz" << std::endl;
}
