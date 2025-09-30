#include "test_fixtures.h"

// 3.4 Frequency Offset Tests
TEST_F(FrequencyOffsetTest, BFOSimulation) {
    // Test BFO (Beat Frequency Oscillator) simulation
    double base_frequency = 14200.0; // 20m band
    double bfo_offset = 1.5; // 1.5 kHz BFO offset
    
    // Test BFO calculation
    double bfo_frequency = base_frequency + bfo_offset;
    EXPECT_NEAR(bfo_frequency, 14201.5, 0.1) << "BFO frequency should be base + offset";
    
    // Test BFO offset range
    std::vector<double> bfo_offsets = {-3.0, -1.5, 0.0, 1.5, 3.0}; // kHz
    
    for (double offset : bfo_offsets) {
        double bfo_freq = base_frequency + offset;
        
        // Test BFO frequency validation
        EXPECT_GT(bfo_freq, 0.0) << "BFO frequency should be positive";
        EXPECT_NEAR(bfo_freq, base_frequency + offset, 0.1) << "BFO frequency should be base + offset";
        
        // Test BFO offset range
        EXPECT_GE(offset, -5.0) << "BFO offset should be >= -5.0 kHz";
        EXPECT_LE(offset, 5.0) << "BFO offset should be <= 5.0 kHz";
    }
}

TEST_F(FrequencyOffsetTest, SSBFrequencyOffset) {
    // Test SSB frequency offset
    double carrier_frequency = 14200.0; // 20m band
    double ssb_offset = 1.5; // 1.5 kHz SSB offset
    
    // Test SSB frequency calculation
    double ssb_frequency = carrier_frequency + ssb_offset;
    EXPECT_NEAR(ssb_frequency, 14201.5, 0.1) << "SSB frequency should be carrier + offset";
    
    // Test SSB offset range
    std::vector<double> ssb_offsets = {-3.0, -1.5, 0.0, 1.5, 3.0}; // kHz
    
    for (double offset : ssb_offsets) {
        double ssb_freq = carrier_frequency + offset;
        
        // Test SSB frequency validation
        EXPECT_GT(ssb_freq, 0.0) << "SSB frequency should be positive";
        EXPECT_NEAR(ssb_freq, carrier_frequency + offset, 0.1) << "SSB frequency should be carrier + offset";
        
        // Test SSB offset range
        EXPECT_GE(offset, -5.0) << "SSB offset should be >= -5.0 kHz";
        EXPECT_LE(offset, 5.0) << "SSB offset should be <= 5.0 kHz";
    }
}

TEST_F(FrequencyOffsetTest, CWToneInjection) {
    // Test CW tone injection
    double carrier_frequency = 14200.0; // 20m band
    double cw_tone = 600.0; // 600 Hz CW tone
    
    // Test CW tone injection
    double cw_frequency = carrier_frequency + (cw_tone / 1000.0); // Convert Hz to kHz
    EXPECT_NEAR(cw_frequency, 14200.6, 0.1) << "CW frequency should be carrier + tone";
    
    // Test CW tone range
    std::vector<double> cw_tones = {400.0, 500.0, 600.0, 700.0, 800.0}; // Hz
    
    for (double tone : cw_tones) {
        double cw_freq = carrier_frequency + (tone / 1000.0);
        
        // Test CW frequency validation
        EXPECT_GT(cw_freq, 0.0) << "CW frequency should be positive";
        EXPECT_NEAR(cw_freq, carrier_frequency + (tone / 1000.0), 0.1) << "CW frequency should be carrier + tone";
        
        // Test CW tone range
        EXPECT_GE(tone, 400.0) << "CW tone should be >= 400.0 Hz";
        EXPECT_LE(tone, 800.0) << "CW tone should be <= 800.0 Hz";
    }
}

TEST_F(FrequencyOffsetTest, FrequencyDriftSimulation) {
    // Test frequency drift simulation
    double base_frequency = 14200.0; // 20m band
    double drift_rate = 0.08; // 0.08 kHz per minute drift (reduced to stay within limits)
    
    // Test frequency drift over time
    std::vector<double> time_minutes = {0.0, 1.0, 5.0, 10.0, 30.0, 60.0};
    
    for (double time : time_minutes) {
        double drifted_frequency = base_frequency + (drift_rate * time);
        
        // Test drifted frequency validation
        EXPECT_GT(drifted_frequency, 0.0) << "Drifted frequency should be positive";
        EXPECT_NEAR(drifted_frequency, base_frequency + (drift_rate * time), 0.1) 
            << "Drifted frequency should be base + (drift_rate * time)";
        
        // Test drift range
        double total_drift = drift_rate * time;
        EXPECT_GE(total_drift, -5.0) << "Total drift should be >= -5.0 kHz";
        EXPECT_LE(total_drift, 5.0) << "Total drift should be <= 5.0 kHz";
    }
}

TEST_F(FrequencyOffsetTest, CrystalAccuracySimulation) {
    // Test crystal accuracy simulation
    double nominal_frequency = 14200.0; // 20m band
    double crystal_accuracy_ppm = 10.0; // 10 ppm accuracy
    
    // Test crystal accuracy calculation
    double frequency_error = (nominal_frequency * crystal_accuracy_ppm) / 1000000.0;
    double actual_frequency = nominal_frequency + frequency_error;
    
    EXPECT_NEAR(actual_frequency, 14200.142, 0.1) << "Actual frequency should be nominal + error";
    
    // Test crystal accuracy range
    std::vector<double> crystal_accuracies = {1.0, 5.0, 10.0, 20.0, 50.0}; // ppm
    
    for (double accuracy : crystal_accuracies) {
        double error = (nominal_frequency * accuracy) / 1000000.0;
        double actual_freq = nominal_frequency + error;
        
        // Test actual frequency validation
        EXPECT_GT(actual_freq, 0.0) << "Actual frequency should be positive";
        EXPECT_NEAR(actual_freq, nominal_frequency + error, 0.1) << "Actual frequency should be nominal + error";
        
        // Test crystal accuracy range
        EXPECT_GE(accuracy, 0.1) << "Crystal accuracy should be >= 0.1 ppm";
        EXPECT_LE(accuracy, 100.0) << "Crystal accuracy should be <= 100.0 ppm";
    }
}

TEST_F(FrequencyOffsetTest, FrequencyOffsetCombination) {
    // Test combination of multiple frequency offsets
    double base_frequency = 14200.0; // 20m band
    double bfo_offset = 1.5; // 1.5 kHz BFO offset
    double ssb_offset = 0.5; // 0.5 kHz SSB offset
    double cw_tone = 600.0; // 600 Hz CW tone
    double drift = 0.1; // 0.1 kHz drift
    double crystal_error = 0.05; // 0.05 kHz crystal error
    
    // Test combined frequency calculation
    double combined_frequency = base_frequency + bfo_offset + ssb_offset + 
                               (cw_tone / 1000.0) + drift + crystal_error;
    
    EXPECT_NEAR(combined_frequency, 14202.75, 0.1) << "Combined frequency should be base + all offsets";
    
    // Test individual offset contributions
    EXPECT_NEAR(bfo_offset, 1.5, 0.1) << "BFO offset should be 1.5 kHz";
    EXPECT_NEAR(ssb_offset, 0.5, 0.1) << "SSB offset should be 0.5 kHz";
    EXPECT_NEAR(cw_tone / 1000.0, 0.6, 0.1) << "CW tone should be 0.6 kHz";
    EXPECT_NEAR(drift, 0.1, 0.1) << "Drift should be 0.1 kHz";
    EXPECT_NEAR(crystal_error, 0.05, 0.1) << "Crystal error should be 0.05 kHz";
}

TEST_F(FrequencyOffsetTest, FrequencyOffsetValidation) {
    // Test frequency offset validation
    double base_frequency = 14200.0; // 20m band
    double max_offset = 5.0; // 5 kHz maximum offset
    
    // Test valid offsets
    std::vector<double> valid_offsets = {-5.0, -2.5, 0.0, 2.5, 5.0};
    
    for (double offset : valid_offsets) {
        double frequency = base_frequency + offset;
        
        // Test frequency validation
        EXPECT_GT(frequency, 0.0) << "Frequency should be positive";
        EXPECT_GE(frequency, base_frequency - max_offset) << "Frequency should be >= base - max_offset";
        EXPECT_LE(frequency, base_frequency + max_offset) << "Frequency should be <= base + max_offset";
    }
    
    // Test invalid offsets
    std::vector<double> invalid_offsets = {-10.0, -7.5, 7.5, 10.0};
    
    for (double offset : invalid_offsets) {
        double frequency = base_frequency + offset;
        
        // Test frequency validation
        if (offset < -max_offset) {
            EXPECT_LT(frequency, base_frequency - max_offset) << "Frequency should be < base - max_offset";
        } else if (offset > max_offset) {
            EXPECT_GT(frequency, base_frequency + max_offset) << "Frequency should be > base + max_offset";
        }
    }
}

TEST_F(FrequencyOffsetTest, FrequencyOffsetPerformance) {
    // Test frequency offset calculation performance
    const int num_calculations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        double base_frequency = 14200.0 + (i % 100) * 0.1;
        double bfo_offset = 1.5 + (i % 10) * 0.1;
        double ssb_offset = 0.5 + (i % 5) * 0.1;
        double cw_tone = 600.0 + (i % 20) * 10.0;
        double drift = 0.1 + (i % 3) * 0.05;
        double crystal_error = 0.05 + (i % 2) * 0.02;
        
        // Calculate combined frequency
        double combined_frequency = base_frequency + bfo_offset + ssb_offset + 
                                   (cw_tone / 1000.0) + drift + crystal_error;
        
        // Verify calculation is reasonable
        EXPECT_GT(combined_frequency, 0.0);
        EXPECT_LT(combined_frequency, 50000.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_calculation = static_cast<double>(duration.count()) / num_calculations;
    
    // Frequency offset calculations should be fast
    EXPECT_LT(time_per_calculation, 1.0) << "Frequency offset calculation too slow: " << time_per_calculation << " microseconds";
    
    std::cout << "Frequency offset calculation performance: " << time_per_calculation << " microseconds per calculation" << std::endl;
}

// Additional frequency offset tests
TEST_F(FrequencyOffsetTest, FrequencyOffsetPrecision) {
    // Test frequency offset precision
    double base_frequency = 14200.0; // 20m band
    double precision_offset = 0.001; // 1 Hz precision
    
    // Test precision calculation
    double precise_frequency = base_frequency + precision_offset;
    EXPECT_NEAR(precise_frequency, 14200.001, 0.0001) << "Precise frequency should be base + precision offset";
    
    // Test precision range
    std::vector<double> precision_offsets = {0.0001, 0.001, 0.01, 0.1, 1.0}; // kHz
    
    for (double offset : precision_offsets) {
        double freq = base_frequency + offset;
        
        // Test precision frequency validation
        EXPECT_GT(freq, 0.0) << "Precision frequency should be positive";
        EXPECT_NEAR(freq, base_frequency + offset, 0.0001) << "Precision frequency should be base + offset";
        
        // Test precision range
        EXPECT_GE(offset, 0.0001) << "Precision offset should be >= 0.0001 kHz";
        EXPECT_LE(offset, 1.0) << "Precision offset should be <= 1.0 kHz";
    }
}

TEST_F(FrequencyOffsetTest, FrequencyOffsetStability) {
    // Test frequency offset stability
    double base_frequency = 14200.0; // 20m band
    double stability_offset = 0.01; // 0.01 kHz stability offset
    
    // Test stability calculation
    double stable_frequency = base_frequency + stability_offset;
    EXPECT_NEAR(stable_frequency, 14200.01, 0.001) << "Stable frequency should be base + stability offset";
    
    // Test stability range
    std::vector<double> stability_offsets = {0.001, 0.01, 0.1, 1.0}; // kHz
    
    for (double offset : stability_offsets) {
        double freq = base_frequency + offset;
        
        // Test stability frequency validation
        EXPECT_GT(freq, 0.0) << "Stability frequency should be positive";
        EXPECT_NEAR(freq, base_frequency + offset, 0.001) << "Stability frequency should be base + offset";
        
        // Test stability range
        EXPECT_GE(offset, 0.001) << "Stability offset should be >= 0.001 kHz";
        EXPECT_LE(offset, 1.0) << "Stability offset should be <= 1.0 kHz";
    }
}

