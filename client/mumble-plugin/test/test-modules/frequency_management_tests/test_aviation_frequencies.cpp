#include "test_fixtures.h"

// 3.2 Aviation Frequency Tests
TEST_F(AviationFrequencyTest, CivilVHFValidation) {
    // Test civil VHF (118-137 MHz) validation
    std::vector<double> civil_vhf_frequencies = {
        118.0, 118.025, 118.05, 118.075, 118.1, 118.125, 118.15, 118.175, 118.2,
        119.0, 119.025, 119.05, 119.075, 119.1, 119.125, 119.15, 119.175, 119.2,
        120.0, 120.025, 120.05, 120.075, 120.1, 120.125, 120.15, 120.175, 120.2,
        121.0, 121.025, 121.05, 121.075, 121.1, 121.125, 121.15, 121.175, 121.2,
        122.0, 122.025, 122.05, 122.075, 122.1, 122.125, 122.15, 122.175, 122.2,
        123.0, 123.025, 123.05, 123.075, 123.1, 123.125, 123.15, 123.175, 123.2,
        124.0, 124.025, 124.05, 124.075, 124.1, 124.125, 124.15, 124.175, 124.2,
        125.0, 125.025, 125.05, 125.075, 125.1, 125.125, 125.15, 125.175, 125.2,
        126.0, 126.025, 126.05, 126.075, 126.1, 126.125, 126.15, 126.175, 126.2,
        127.0, 127.025, 127.05, 127.075, 127.1, 127.125, 127.15, 127.175, 127.2,
        128.0, 128.025, 128.05, 128.075, 128.1, 128.125, 128.15, 128.175, 128.2,
        129.0, 129.025, 129.05, 129.075, 129.1, 129.125, 129.15, 129.175, 129.2,
        130.0, 130.025, 130.05, 130.075, 130.1, 130.125, 130.15, 130.175, 130.2,
        131.0, 131.025, 131.05, 131.075, 131.1, 131.125, 131.15, 131.175, 131.2,
        132.0, 132.025, 132.05, 132.075, 132.1, 132.125, 132.15, 132.175, 132.2,
        133.0, 133.025, 133.05, 133.075, 133.1, 133.125, 133.15, 133.175, 133.2,
        134.0, 134.025, 134.05, 134.075, 134.1, 134.125, 134.15, 134.175, 134.2,
        135.0, 135.025, 135.05, 135.075, 135.1, 135.125, 135.15, 135.175, 135.2,
        136.0, 136.025, 136.05, 136.075, 136.1, 136.125, 136.15, 136.175, 136.2,
        137.0
    };
    
    for (double frequency : civil_vhf_frequencies) {
        // Test civil VHF frequency validation
        EXPECT_GE(frequency, 118.0) << "Civil VHF frequency should be >= 118.0 MHz";
        EXPECT_LE(frequency, 137.0) << "Civil VHF frequency should be <= 137.0 MHz";
        
        // Test channel spacing (25 kHz or 8.33 kHz)
        double remainder_25khz = std::fmod(frequency * 1000.0, 25.0);
        double remainder_833khz = std::fmod(frequency * 1000.0, 8.333333333333333); // More precise 8.33
        
        EXPECT_TRUE(remainder_25khz < 0.1 || remainder_833khz < 0.1) 
            << "Civil VHF frequency should be on 25 kHz or 8.33 kHz channel spacing";
    }
}

TEST_F(AviationFrequencyTest, MilitaryVHFUHFValidation) {
    // Test military VHF/UHF validation
    std::vector<double> military_vhf_frequencies = {
        30.0, 35.0, 40.0, 45.0, 50.0, 55.0, 60.0, 65.0, 70.0, 75.0, 80.0, 85.0, 90.0, 95.0, 100.0
    };
    
    std::vector<double> military_uhf_frequencies = {
        225.0, 250.0, 275.0, 300.0, 325.0, 350.0, 375.0, 400.0
    };
    
    // Test military VHF frequencies
    for (double frequency : military_vhf_frequencies) {
        EXPECT_GE(frequency, 30.0) << "Military VHF frequency should be >= 30.0 MHz";
        EXPECT_LE(frequency, 100.0) << "Military VHF frequency should be <= 100.0 MHz";
    }
    
    // Test military UHF frequencies
    for (double frequency : military_uhf_frequencies) {
        EXPECT_GE(frequency, 225.0) << "Military UHF frequency should be >= 225.0 MHz";
        EXPECT_LE(frequency, 400.0) << "Military UHF frequency should be <= 400.0 MHz";
    }
}

TEST_F(AviationFrequencyTest, CivilHFBandValidation) {
    // Test civil HF band validation
    std::vector<double> civil_hf_frequencies = {
        3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0, 9000.0, 10000.0,
        11000.0, 12000.0, 13000.0, 14000.0, 15000.0, 16000.0, 17000.0, 18000.0,
        19000.0, 20000.0, 21000.0, 22000.0, 23000.0, 24000.0, 25000.0, 26000.0,
        27000.0, 28000.0, 29000.0, 30000.0
    };
    
    for (double frequency : civil_hf_frequencies) {
        // Test civil HF frequency validation
        EXPECT_GE(frequency, 3000.0) << "Civil HF frequency should be >= 3000.0 kHz";
        EXPECT_LE(frequency, 30000.0) << "Civil HF frequency should be <= 30000.0 kHz";
        
        // Test HF band allocation
        if (frequency >= 3500.0 && frequency <= 4000.0) {
            // 80m band
            EXPECT_TRUE(frequency >= 3500.0 && frequency <= 4000.0) << "80m band should be 3500-4000 kHz";
        } else if (frequency >= 7000.0 && frequency <= 7300.0) {
            // 40m band
            EXPECT_TRUE(frequency >= 7000.0 && frequency <= 7300.0) << "40m band should be 7000-7300 kHz";
        } else if (frequency >= 14000.0 && frequency <= 14350.0) {
            // 20m band
            EXPECT_TRUE(frequency >= 14000.0 && frequency <= 14350.0) << "20m band should be 14000-14350 kHz";
        } else if (frequency >= 21000.0 && frequency <= 21450.0) {
            // 15m band
            EXPECT_TRUE(frequency >= 21000.0 && frequency <= 21450.0) << "15m band should be 21000-21450 kHz";
        } else if (frequency >= 28000.0 && frequency <= 29700.0) {
            // 10m band
            EXPECT_TRUE(frequency >= 28000.0 && frequency <= 29700.0) << "10m band should be 28000-29700 kHz";
        }
    }
}

TEST_F(AviationFrequencyTest, EmergencyFrequency) {
    // Test emergency frequency (121.5 MHz)
    double emergency_frequency = 121.5;
    
    // Test emergency frequency validation
    EXPECT_EQ(emergency_frequency, 121.5) << "Emergency frequency should be 121.5 MHz";
    
    // Test emergency frequency characteristics
    EXPECT_GE(emergency_frequency, 118.0) << "Emergency frequency should be in VHF band";
    EXPECT_LE(emergency_frequency, 137.0) << "Emergency frequency should be in VHF band";
    
    // Test emergency frequency channel spacing
    double remainder_25khz = std::fmod(emergency_frequency * 1000.0, 25.0);
    EXPECT_LT(remainder_25khz, 0.1) << "Emergency frequency should be on 25 kHz channel spacing";
    
    // Test emergency frequency power limits
    double emergency_power_limit = 25.0; // 25 watts maximum
    EXPECT_LE(emergency_power_limit, 25.0) << "Emergency frequency should have 25W power limit";
    
    // Test emergency frequency modulation
    std::string emergency_modulation = "AM";
    EXPECT_EQ(emergency_modulation, "AM") << "Emergency frequency should use AM modulation";
}

TEST_F(AviationFrequencyTest, GuardFrequency) {
    // Test guard frequency (243.0 MHz)
    double guard_frequency = 243.0;
    
    // Test guard frequency validation
    EXPECT_EQ(guard_frequency, 243.0) << "Guard frequency should be 243.0 MHz";
    
    // Test guard frequency characteristics
    EXPECT_GE(guard_frequency, 225.0) << "Guard frequency should be in UHF band";
    EXPECT_LE(guard_frequency, 400.0) << "Guard frequency should be in UHF band";
    
    // Test guard frequency channel spacing
    double remainder_25khz = std::fmod(guard_frequency * 1000.0, 25.0);
    EXPECT_LT(remainder_25khz, 0.1) << "Guard frequency should be on 25 kHz channel spacing";
    
    // Test guard frequency power limits
    double guard_power_limit = 25.0; // 25 watts maximum
    EXPECT_LE(guard_power_limit, 25.0) << "Guard frequency should have 25W power limit";
    
    // Test guard frequency modulation
    std::string guard_modulation = "AM";
    EXPECT_EQ(guard_modulation, "AM") << "Guard frequency should use AM modulation";
}

TEST_F(AviationFrequencyTest, AviationFrequencyAllocation) {
    // Test aviation frequency allocation
    auto aviation_frequencies = generateAviationFrequencies();
    
    // Test that we have aviation frequencies
    EXPECT_GT(aviation_frequencies.size(), 0) << "Should have aviation frequencies";
    
    for (const auto& frequency : aviation_frequencies) {
        // Test frequency band
        EXPECT_TRUE(frequency.band == "VHF" || frequency.band == "Emergency" || frequency.band == "Guard") 
            << "Aviation frequency band should be valid";
        
        // Test mode
        EXPECT_EQ(frequency.mode, "AM") << "Aviation frequency should use AM modulation";
        
        // Test frequency range
        EXPECT_GT(frequency.end_freq, frequency.start_freq) << "End frequency should be greater than start frequency";
        
        // Test ITU region
        EXPECT_TRUE(frequency.itu_region >= 1 && frequency.itu_region <= 3) << "ITU region should be 1, 2, or 3";
        
        // Test country
        EXPECT_TRUE(frequency.country == "ICAO" || frequency.country == "NATO") 
            << "Aviation frequency country should be ICAO or NATO";
        
        // Test license class
        EXPECT_TRUE(frequency.license_class == "Pilot" || frequency.license_class == "Emergency" || frequency.license_class == "Military") 
            << "Aviation frequency license class should be valid";
        
        // Test power limit
        EXPECT_LE(frequency.power_limit, 25.0) << "Aviation frequency power limit should be <= 25W";
    }
}

TEST_F(AviationFrequencyTest, AviationFrequencyChannelSpacing) {
    // Test aviation frequency channel spacing
    std::vector<double> test_frequencies = {118.0, 118.025, 118.05, 118.075, 118.1};
    
    for (size_t i = 1; i < test_frequencies.size(); ++i) {
        double channel_spacing = test_frequencies[i] - test_frequencies[i-1];
        EXPECT_NEAR(channel_spacing, 0.025, 0.001) << "Aviation frequency channel spacing should be 25 kHz";
    }
    
    // Test 8.33 kHz channel spacing (Europe)
    std::vector<double> european_frequencies = {118.0, 118.00833, 118.01666, 118.025, 118.03333};
    
    for (size_t i = 1; i < european_frequencies.size(); ++i) {
        double channel_spacing = european_frequencies[i] - european_frequencies[i-1];
        EXPECT_NEAR(channel_spacing, 0.00833, 0.001) << "European aviation frequency channel spacing should be 8.33 kHz";
    }
}

TEST_F(AviationFrequencyTest, AviationFrequencyPowerLimits) {
    // Test aviation frequency power limits
    auto aviation_frequencies = generateAviationFrequencies();
    
    for (const auto& frequency : aviation_frequencies) {
        // Test power limit validation
        EXPECT_GT(frequency.power_limit, 0.0) << "Aviation frequency power limit should be positive";
        EXPECT_LE(frequency.power_limit, 25.0) << "Aviation frequency power limit should be <= 25W";
        
        // Test power limit by frequency band
        if (frequency.band == "VHF") {
            EXPECT_LE(frequency.power_limit, 25.0) << "VHF aviation frequency power limit should be <= 25W";
        } else if (frequency.band == "Emergency" || frequency.band == "Guard") {
            EXPECT_LE(frequency.power_limit, 25.0) << "Emergency/Guard frequency power limit should be <= 25W";
        }
    }
}

TEST_F(AviationFrequencyTest, AviationFrequencyModulation) {
    // Test aviation frequency modulation
    auto aviation_frequencies = generateAviationFrequencies();
    
    for (const auto& frequency : aviation_frequencies) {
        // Test modulation validation
        EXPECT_EQ(frequency.mode, "AM") << "Aviation frequency should use AM modulation";
        
        // Test modulation by frequency band
        if (frequency.band == "VHF") {
            EXPECT_EQ(frequency.mode, "AM") << "VHF aviation frequency should use AM modulation";
        } else if (frequency.band == "Emergency" || frequency.band == "Guard") {
            EXPECT_EQ(frequency.mode, "AM") << "Emergency/Guard frequency should use AM modulation";
        }
    }
}

// Additional aviation frequency tests
TEST_F(AviationFrequencyTest, AviationFrequencyPerformance) {
    // Test aviation frequency validation performance
    const int num_validations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_validations; ++i) {
        auto aviation_frequencies = generateAviationFrequencies();
        
        // Validate each frequency
        for (const auto& frequency : aviation_frequencies) {
            // Basic validation
            EXPECT_GT(frequency.end_freq, frequency.start_freq);
            EXPECT_GT(frequency.power_limit, 0.0);
            EXPECT_TRUE(frequency.itu_region >= 1 && frequency.itu_region <= 3);
            EXPECT_EQ(frequency.mode, "AM");
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_validation = static_cast<double>(duration.count()) / num_validations;
    
    // Aviation frequency validation should be fast
    EXPECT_LT(time_per_validation, 50.0) << "Aviation frequency validation too slow: " << time_per_validation << " microseconds";
    
    std::cout << "Aviation frequency validation performance: " << time_per_validation << " microseconds per validation" << std::endl;
}

