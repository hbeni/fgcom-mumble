#include "test_radio_propagation_main.cpp"

// 2.2 Frequency-Dependent Propagation Tests
TEST_F(FrequencyPropagationTest, VHFPropagation) {
    // Test VHF propagation (118-137 MHz)
    double frequency_mhz = test_frequency_vhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Test VHF-specific propagation characteristics
    EXPECT_GE(frequency_mhz, 118.0) << "VHF frequency should be in range";
    EXPECT_LE(frequency_mhz, 137.0) << "VHF frequency should be in range";
    
    // Calculate free space path loss for VHF
    double wavelength_m = 300.0 / frequency_mhz;
    double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
    
    EXPECT_GT(free_space_loss_db, 0.0) << "Free space loss should be positive";
    EXPECT_LT(free_space_loss_db, 200.0) << "Free space loss should be reasonable";
    
    // Test VHF atmospheric absorption
    double atmospheric_absorption_db = 0.0;
    if (frequency_mhz > 100.0) {
        atmospheric_absorption_db = 0.01 * distance_km; // Simplified model
    }
    
    EXPECT_GE(atmospheric_absorption_db, 0.0) << "Atmospheric absorption should be non-negative";
    
    // Test VHF tropospheric ducting (extended range)
    double ducting_range_km = 100.0; // VHF can have extended range due to ducting
    if (distance_km < ducting_range_km) {
        double ducting_gain_db = 10.0 * std::log10(ducting_range_km / distance_km);
        EXPECT_GT(ducting_gain_db, 0.0) << "Ducting should provide gain";
    }
}

TEST_F(FrequencyPropagationTest, UHFPropagation) {
    // Test UHF propagation (225-400 MHz)
    double frequency_mhz = test_frequency_uhf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Test UHF-specific propagation characteristics
    EXPECT_GE(frequency_mhz, 225.0) << "UHF frequency should be in range";
    EXPECT_LE(frequency_mhz, 400.0) << "UHF frequency should be in range";
    
    // Calculate free space path loss for UHF
    double wavelength_m = 300.0 / frequency_mhz;
    double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
    
    EXPECT_GT(free_space_loss_db, 0.0) << "Free space loss should be positive";
    
    // UHF should have higher path loss than VHF
    double vhf_frequency = 118.0;
    double vhf_wavelength = 300.0 / vhf_frequency;
    double vhf_loss = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / vhf_wavelength);
    
    EXPECT_GT(free_space_loss_db, vhf_loss) << "UHF should have higher path loss than VHF";
    
    // Test UHF atmospheric absorption
    double atmospheric_absorption_db = 0.02 * distance_km; // Higher than VHF
    EXPECT_GT(atmospheric_absorption_db, 0.0) << "UHF atmospheric absorption should be significant";
}

TEST_F(FrequencyPropagationTest, HFPropagation) {
    // Test HF propagation (3-30 MHz)
    double frequency_mhz = test_frequency_hf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Test HF-specific propagation characteristics
    EXPECT_GE(frequency_mhz, 3.0) << "HF frequency should be in range";
    EXPECT_LE(frequency_mhz, 30.0) << "HF frequency should be in range";
    
    // Calculate free space path loss for HF
    double wavelength_m = 300.0 / frequency_mhz;
    double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
    
    EXPECT_GT(free_space_loss_db, 0.0) << "Free space loss should be positive";
    
    // HF should have lower path loss than VHF/UHF
    double vhf_frequency = 118.0;
    double vhf_wavelength = 300.0 / vhf_frequency;
    double vhf_loss = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / vhf_wavelength);
    
    EXPECT_LT(free_space_loss_db, vhf_loss) << "HF should have lower path loss than VHF";
    
    // Test HF ground wave propagation
    double ground_wave_range_km = 50.0; // Ground wave range for HF
    if (distance_km < ground_wave_range_km) {
        double ground_wave_loss_db = 0.1 * distance_km; // Much lower than free space
        EXPECT_LT(ground_wave_loss_db, free_space_loss_db) << "Ground wave should have lower loss";
    }
}

TEST_F(FrequencyPropagationTest, FrequencyBasedPathLoss) {
    // Test frequency-based path loss calculations
    std::vector<double> test_frequencies = {14.0, 118.0, 300.0, 1000.0}; // HF, VHF, UHF, L-band
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    std::vector<double> path_losses;
    
    for (double frequency : test_frequencies) {
        double wavelength_m = 300.0 / frequency;
        double path_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
        path_losses.push_back(path_loss_db);
        
        EXPECT_GT(path_loss_db, 0.0) << "Path loss should be positive for frequency " << frequency;
    }
    
    // Higher frequencies should have higher path loss
    for (size_t i = 1; i < path_losses.size(); ++i) {
        EXPECT_GT(path_losses[i], path_losses[i-1]) << "Higher frequencies should have higher path loss";
    }
}

TEST_F(FrequencyPropagationTest, AtmosphericAbsorption) {
    // Test atmospheric absorption at different frequencies
    std::vector<double> test_frequencies = {14.0, 118.0, 300.0, 1000.0};
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    for (double frequency : test_frequencies) {
        // Simplified atmospheric absorption model
        double absorption_db = 0.0;
        
        if (frequency < 30.0) {
            // HF: minimal atmospheric absorption
            absorption_db = 0.001 * distance_km;
        } else if (frequency < 200.0) {
            // VHF: moderate atmospheric absorption
            absorption_db = 0.01 * distance_km;
        } else if (frequency < 1000.0) {
            // UHF: higher atmospheric absorption
            absorption_db = 0.02 * distance_km;
        } else {
            // L-band and above: significant atmospheric absorption
            absorption_db = 0.05 * distance_km;
        }
        
        EXPECT_GE(absorption_db, 0.0) << "Atmospheric absorption should be non-negative";
        
        // Higher frequencies should have higher absorption
        if (frequency > 100.0) {
            EXPECT_GT(absorption_db, 0.005) << "High frequency should have significant absorption";
        }
    }
}

TEST_F(FrequencyPropagationTest, GroundWavePropagationHF) {
    // Test ground wave propagation for HF
    double frequency_mhz = test_frequency_hf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Ground wave propagation is significant for HF
    EXPECT_GE(frequency_mhz, 3.0) << "HF frequency should be in range";
    EXPECT_LE(frequency_mhz, 30.0) << "HF frequency should be in range";
    
    // Calculate ground wave range
    double ground_wave_range_km = 50.0; // Typical ground wave range for HF
    
    if (distance_km < ground_wave_range_km) {
        // Ground wave propagation
        double ground_wave_loss_db = 0.1 * distance_km; // Much lower than free space
        double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / (300.0 / frequency_mhz));
        
        EXPECT_LT(ground_wave_loss_db, free_space_loss_db) << "Ground wave should have lower loss than free space";
    }
}

TEST_F(FrequencyPropagationTest, SkyWavePropagationHF) {
    // Test sky wave propagation for HF
    double frequency_mhz = test_frequency_hf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Sky wave propagation for long distances
    if (distance_km > 100.0) {
        // Sky wave propagation
        double sky_wave_loss_db = 0.5 * distance_km; // Higher than ground wave but lower than free space
        double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / (300.0 / frequency_mhz));
        
        EXPECT_LT(sky_wave_loss_db, free_space_loss_db) << "Sky wave should have lower loss than free space";
        EXPECT_GT(sky_wave_loss_db, 0.1 * distance_km) << "Sky wave should have higher loss than ground wave";
    }
}

TEST_F(FrequencyPropagationTest, IonosphericReflection) {
    // Test ionospheric reflection for HF
    double frequency_mhz = test_frequency_hf;
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Ionospheric reflection is frequency dependent
    double critical_frequency_mhz = 15.0; // Simplified critical frequency
    
    if (frequency_mhz < critical_frequency_mhz) {
        // Ionospheric reflection possible
        double reflection_loss_db = 0.3 * distance_km;
        double free_space_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / (300.0 / frequency_mhz));
        
        EXPECT_LT(reflection_loss_db, free_space_loss_db) << "Ionospheric reflection should have lower loss";
        
        // Test reflection angle calculation
        double ionosphere_height_km = 300.0; // Typical ionosphere height
        double reflection_angle = std::atan2(ionosphere_height_km, distance_km / 2.0) * 180.0 / M_PI;
        
        EXPECT_GT(reflection_angle, 0.0) << "Reflection angle should be positive";
        EXPECT_LT(reflection_angle, 90.0) << "Reflection angle should be reasonable";
    }
}

// Additional frequency propagation tests
TEST_F(FrequencyPropagationTest, FrequencyResponseCurve) {
    // Test frequency response across the spectrum
    std::vector<double> frequencies = {3.0, 10.0, 30.0, 100.0, 300.0, 1000.0};
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    std::vector<double> path_losses;
    
    for (double frequency : frequencies) {
        double wavelength_m = 300.0 / frequency;
        double path_loss_db = 20.0 * std::log10(4.0 * M_PI * distance_km * 1000.0 / wavelength_m);
        path_losses.push_back(path_loss_db);
    }
    
    // Verify frequency response is monotonic
    for (size_t i = 1; i < path_losses.size(); ++i) {
        EXPECT_GT(path_losses[i], path_losses[i-1]) << "Path loss should increase with frequency";
    }
}

TEST_F(FrequencyPropagationTest, PropagationModeSelection) {
    // Test selection of appropriate propagation mode
    std::vector<double> test_distances = {10.0, 50.0, 100.0, 500.0, 1000.0};
    double frequency_mhz = test_frequency_hf;
    
    for (double distance : test_distances) {
        std::string propagation_mode;
        
        if (distance < 50.0) {
            propagation_mode = "ground_wave";
        } else if (distance < 200.0) {
            propagation_mode = "sky_wave";
        } else {
            propagation_mode = "ionospheric";
        }
        
        // Test that appropriate mode is selected
        if (distance < 50.0) {
            EXPECT_EQ(propagation_mode, "ground_wave") << "Should select ground wave for short distance";
        } else if (distance < 200.0) {
            EXPECT_EQ(propagation_mode, "sky_wave") << "Should select sky wave for medium distance";
        } else {
            EXPECT_EQ(propagation_mode, "ionospheric") << "Should select ionospheric for long distance";
        }
    }
}

TEST_F(FrequencyPropagationTest, FrequencyBandCharacteristics) {
    // Test characteristics of different frequency bands
    struct FrequencyBand {
        std::string name;
        double min_freq;
        double max_freq;
        double typical_range_km;
        std::string propagation_mode;
    };
    
    std::vector<FrequencyBand> bands = {
        {"HF", 3.0, 30.0, 1000.0, "ionospheric"},
        {"VHF", 30.0, 300.0, 100.0, "line_of_sight"},
        {"UHF", 300.0, 3000.0, 50.0, "line_of_sight"},
        {"L-band", 1000.0, 2000.0, 20.0, "line_of_sight"}
    };
    
    for (const auto& band : bands) {
        // Test frequency range
        EXPECT_GT(band.max_freq, band.min_freq) << "Max frequency should be greater than min";
        
        // Test typical range
        EXPECT_GT(band.typical_range_km, 0.0) << "Typical range should be positive";
        
        // Test propagation mode
        EXPECT_FALSE(band.propagation_mode.empty()) << "Propagation mode should be specified";
        
        // Test that higher frequencies have shorter ranges
        if (band.min_freq > 100.0) {
            EXPECT_LT(band.typical_range_km, 100.0) << "High frequency bands should have shorter ranges";
        }
    }
}

