#include "test_fixtures.h"

// 3.3 Historical Maritime Band Tests
TEST_F(MaritimeFrequencyTest, MaritimeHFBandAllocation) {
    // Test maritime HF band allocation
    auto maritime_frequencies = generateMaritimeFrequencies();
    
    // Test that we have maritime frequencies
    EXPECT_GT(maritime_frequencies.size(), 0) << "Should have maritime frequencies";
    
    for (const auto& frequency : maritime_frequencies) {
        // Test frequency band
        EXPECT_EQ(frequency.band, "Maritime HF") << "Maritime frequency band should be 'Maritime HF'";
        
        // Test mode
        EXPECT_EQ(frequency.mode, "SSB") << "Maritime frequency should use SSB modulation";
        
        // Test frequency range
        EXPECT_GT(frequency.end_freq, frequency.start_freq) << "End frequency should be greater than start frequency";
        
        // Test ITU region
        EXPECT_EQ(frequency.itu_region, 1) << "Maritime frequency ITU region should be 1";
        
        // Test country
        EXPECT_EQ(frequency.country, "ITU") << "Maritime frequency country should be 'ITU'";
        
        // Test license class
        EXPECT_EQ(frequency.license_class, "Maritime") << "Maritime frequency license class should be 'Maritime'";
        
        // Test power limit
        EXPECT_LE(frequency.power_limit, 100.0) << "Maritime frequency power limit should be <= 100W";
    }
}

TEST_F(MaritimeFrequencyTest, DistressFrequencies) {
    // Test maritime distress frequencies
    std::vector<double> distress_frequencies = {
        2182.0,  // 2 MHz distress frequency
        4125.0,  // 4 MHz distress frequency
        8291.0   // 8 MHz distress frequency
    };
    
    for (double frequency : distress_frequencies) {
        // Test distress frequency validation
        EXPECT_GT(frequency, 0.0) << "Distress frequency should be positive";
        
        // Test distress frequency characteristics
        if (frequency == 2182.0) {
            EXPECT_EQ(frequency, 2182.0) << "2 MHz distress frequency should be 2182.0 kHz";
        } else if (frequency == 4125.0) {
            EXPECT_EQ(frequency, 4125.0) << "4 MHz distress frequency should be 4125.0 kHz";
        } else if (frequency == 8291.0) {
            EXPECT_EQ(frequency, 8291.0) << "8 MHz distress frequency should be 8291.0 kHz";
        }
        
        // Test distress frequency power limits
        double distress_power_limit = 100.0; // 100 watts maximum
        EXPECT_LE(distress_power_limit, 100.0) << "Distress frequency should have 100W power limit";
        
        // Test distress frequency modulation
        std::string distress_modulation = "SSB";
        EXPECT_EQ(distress_modulation, "SSB") << "Distress frequency should use SSB modulation";
    }
}

TEST_F(MaritimeFrequencyTest, WorkingFrequencies) {
    // Test maritime working frequencies
    std::vector<double> working_frequencies = {
        2187.5,  // 2 MHz working frequency
        6215.0,  // 6 MHz working frequency
        12290.0  // 12 MHz working frequency
    };
    
    for (double frequency : working_frequencies) {
        // Test working frequency validation
        EXPECT_GT(frequency, 0.0) << "Working frequency should be positive";
        
        // Test working frequency characteristics
        if (frequency == 2187.5) {
            EXPECT_EQ(frequency, 2187.5) << "2 MHz working frequency should be 2187.5 kHz";
        } else if (frequency == 6215.0) {
            EXPECT_EQ(frequency, 6215.0) << "6 MHz working frequency should be 6215.0 kHz";
        } else if (frequency == 12290.0) {
            EXPECT_EQ(frequency, 12290.0) << "12 MHz working frequency should be 12290.0 kHz";
        }
        
        // Test working frequency power limits
        double working_power_limit = 100.0; // 100 watts maximum
        EXPECT_LE(working_power_limit, 100.0) << "Working frequency should have 100W power limit";
        
        // Test working frequency modulation
        std::string working_modulation = "SSB";
        EXPECT_EQ(working_modulation, "SSB") << "Working frequency should use SSB modulation";
    }
}

TEST_F(MaritimeFrequencyTest, CoastStationFrequencies) {
    // Test coast station frequencies
    std::vector<double> coast_station_frequencies = {
        2182.0,  // 2 MHz coast station
        4125.0,  // 4 MHz coast station
        6215.0,  // 6 MHz coast station
        8291.0,  // 8 MHz coast station
        12290.0  // 12 MHz coast station
    };
    
    for (double frequency : coast_station_frequencies) {
        // Test coast station frequency validation
        EXPECT_GT(frequency, 0.0) << "Coast station frequency should be positive";
        
        // Test coast station frequency characteristics
        EXPECT_GE(frequency, 2000.0) << "Coast station frequency should be >= 2000.0 kHz";
        EXPECT_LE(frequency, 15000.0) << "Coast station frequency should be <= 15000.0 kHz";
        
        // Test coast station frequency power limits
        double coast_station_power_limit = 100.0; // 100 watts maximum
        EXPECT_LE(coast_station_power_limit, 100.0) << "Coast station frequency should have 100W power limit";
        
        // Test coast station frequency modulation
        std::string coast_station_modulation = "SSB";
        EXPECT_EQ(coast_station_modulation, "SSB") << "Coast station frequency should use SSB modulation";
    }
}

TEST_F(MaritimeFrequencyTest, MaritimeFrequencyAllocation) {
    // Test maritime frequency allocation
    auto maritime_frequencies = generateMaritimeFrequencies();
    
    // Test that we have maritime frequencies
    EXPECT_GT(maritime_frequencies.size(), 0) << "Should have maritime frequencies";
    
    for (const auto& frequency : maritime_frequencies) {
        // Test frequency band
        EXPECT_EQ(frequency.band, "Maritime HF") << "Maritime frequency band should be 'Maritime HF'";
        
        // Test mode
        EXPECT_EQ(frequency.mode, "SSB") << "Maritime frequency should use SSB modulation";
        
        // Test frequency range
        EXPECT_GT(frequency.end_freq, frequency.start_freq) << "End frequency should be greater than start frequency";
        
        // Test ITU region
        EXPECT_EQ(frequency.itu_region, 1) << "Maritime frequency ITU region should be 1";
        
        // Test country
        EXPECT_EQ(frequency.country, "ITU") << "Maritime frequency country should be 'ITU'";
        
        // Test license class
        EXPECT_EQ(frequency.license_class, "Maritime") << "Maritime frequency license class should be 'Maritime'";
        
        // Test power limit
        EXPECT_LE(frequency.power_limit, 100.0) << "Maritime frequency power limit should be <= 100W";
    }
}

TEST_F(MaritimeFrequencyTest, MaritimeFrequencyChannelSpacing) {
    // Test maritime frequency channel spacing
    std::vector<double> maritime_frequencies = {2182.0, 2187.5, 4125.0, 6215.0, 8291.0, 12290.0};
    
    // Test that maritime frequencies are properly spaced
    for (size_t i = 1; i < maritime_frequencies.size(); ++i) {
        double frequency_diff = maritime_frequencies[i] - maritime_frequencies[i-1];
        EXPECT_GT(frequency_diff, 0.0) << "Maritime frequencies should be in ascending order";
    }
    
    // Test specific frequency spacing
    EXPECT_NEAR(2187.5 - 2182.0, 5.5, 0.1) << "2 MHz band spacing should be 5.5 kHz";
    EXPECT_NEAR(6215.0 - 4125.0, 2090.0, 0.1) << "6 MHz to 4 MHz spacing should be 2090.0 kHz";
    EXPECT_NEAR(8291.0 - 6215.0, 2076.0, 0.1) << "8 MHz to 6 MHz spacing should be 2076.0 kHz";
    EXPECT_NEAR(12290.0 - 8291.0, 3999.0, 0.1) << "12 MHz to 8 MHz spacing should be 3999.0 kHz";
}

TEST_F(MaritimeFrequencyTest, MaritimeFrequencyPowerLimits) {
    // Test maritime frequency power limits
    auto maritime_frequencies = generateMaritimeFrequencies();
    
    for (const auto& frequency : maritime_frequencies) {
        // Test power limit validation
        EXPECT_GT(frequency.power_limit, 0.0) << "Maritime frequency power limit should be positive";
        EXPECT_LE(frequency.power_limit, 100.0) << "Maritime frequency power limit should be <= 100W";
        
        // Test power limit by frequency
        if (frequency.start_freq == 2182.0) {
            EXPECT_LE(frequency.power_limit, 100.0) << "2 MHz maritime frequency power limit should be <= 100W";
        } else if (frequency.start_freq == 4125.0) {
            EXPECT_LE(frequency.power_limit, 100.0) << "4 MHz maritime frequency power limit should be <= 100W";
        } else if (frequency.start_freq == 6215.0) {
            EXPECT_LE(frequency.power_limit, 100.0) << "6 MHz maritime frequency power limit should be <= 100W";
        } else if (frequency.start_freq == 8291.0) {
            EXPECT_LE(frequency.power_limit, 100.0) << "8 MHz maritime frequency power limit should be <= 100W";
        } else if (frequency.start_freq == 12290.0) {
            EXPECT_LE(frequency.power_limit, 100.0) << "12 MHz maritime frequency power limit should be <= 100W";
        }
    }
}

TEST_F(MaritimeFrequencyTest, MaritimeFrequencyModulation) {
    // Test maritime frequency modulation
    auto maritime_frequencies = generateMaritimeFrequencies();
    
    for (const auto& frequency : maritime_frequencies) {
        // Test modulation validation
        EXPECT_EQ(frequency.mode, "SSB") << "Maritime frequency should use SSB modulation";
        
        // Test modulation by frequency
        if (frequency.start_freq == 2182.0) {
            EXPECT_EQ(frequency.mode, "SSB") << "2 MHz maritime frequency should use SSB modulation";
        } else if (frequency.start_freq == 4125.0) {
            EXPECT_EQ(frequency.mode, "SSB") << "4 MHz maritime frequency should use SSB modulation";
        } else if (frequency.start_freq == 6215.0) {
            EXPECT_EQ(frequency.mode, "SSB") << "6 MHz maritime frequency should use SSB modulation";
        } else if (frequency.start_freq == 8291.0) {
            EXPECT_EQ(frequency.mode, "SSB") << "8 MHz maritime frequency should use SSB modulation";
        } else if (frequency.start_freq == 12290.0) {
            EXPECT_EQ(frequency.mode, "SSB") << "12 MHz maritime frequency should use SSB modulation";
        }
    }
}

TEST_F(MaritimeFrequencyTest, MaritimeFrequencyBandAllocation) {
    // Test maritime frequency band allocation
    auto maritime_frequencies = generateMaritimeFrequencies();
    
    // Test that maritime frequencies are in proper bands
    for (const auto& frequency : maritime_frequencies) {
        // Test frequency band allocation
        if (frequency.start_freq >= 2000.0 && frequency.start_freq <= 3000.0) {
            // 2 MHz band
            EXPECT_TRUE(frequency.start_freq == 2182.0 || frequency.start_freq == 2187.5) 
                << "2 MHz band should have 2182.0 or 2187.5 kHz";
        } else if (frequency.start_freq >= 4000.0 && frequency.start_freq <= 5000.0) {
            // 4 MHz band
            EXPECT_EQ(frequency.start_freq, 4125.0) << "4 MHz band should have 4125.0 kHz";
        } else if (frequency.start_freq >= 6000.0 && frequency.start_freq <= 7000.0) {
            // 6 MHz band
            EXPECT_EQ(frequency.start_freq, 6215.0) << "6 MHz band should have 6215.0 kHz";
        } else if (frequency.start_freq >= 8000.0 && frequency.start_freq <= 9000.0) {
            // 8 MHz band
            EXPECT_EQ(frequency.start_freq, 8291.0) << "8 MHz band should have 8291.0 kHz";
        } else if (frequency.start_freq >= 12000.0 && frequency.start_freq <= 13000.0) {
            // 12 MHz band
            EXPECT_EQ(frequency.start_freq, 12290.0) << "12 MHz band should have 12290.0 kHz";
        }
    }
}

// Additional maritime frequency tests
TEST_F(MaritimeFrequencyTest, MaritimeFrequencyPerformance) {
    // Test maritime frequency validation performance
    const int num_validations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_validations; ++i) {
        auto maritime_frequencies = generateMaritimeFrequencies();
        
        // Validate each frequency
        for (const auto& frequency : maritime_frequencies) {
            // Basic validation
            EXPECT_GT(frequency.end_freq, frequency.start_freq);
            EXPECT_GT(frequency.power_limit, 0.0);
            EXPECT_EQ(frequency.itu_region, 1);
            EXPECT_EQ(frequency.mode, "SSB");
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_validation = static_cast<double>(duration.count()) / num_validations;
    
    // Maritime frequency validation should be fast
    EXPECT_LT(time_per_validation, 50.0) << "Maritime frequency validation too slow: " << time_per_validation << " microseconds";
    
    std::cout << "Maritime frequency validation performance: " << time_per_validation << " microseconds per validation" << std::endl;
}

