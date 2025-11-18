#include "test_fixtures.h"

// 3.1 Band Segment Validation Tests
TEST_F(BandSegmentValidationTest, AmateurRadioBandSegments) {
    // Test amateur radio band segments (280+ allocations)
    auto band_segments = generateAmateurBandSegments();
    
    // Test that we have multiple band segments
    EXPECT_GT(band_segments.size(), 0) << "Should have amateur radio band segments";
    
    // Test each band segment
    for (const auto& segment : band_segments) {
        // Test band designation
        EXPECT_FALSE(segment.band.empty()) << "Band designation should not be empty";
        EXPECT_TRUE(segment.band == "160m" || segment.band == "80m" || segment.band == "40m" || 
                   segment.band == "20m" || segment.band == "2m" || segment.band == "70cm") 
                   << "Band should be valid amateur radio band";
        
        // Test mode validation
        EXPECT_FALSE(segment.mode.empty()) << "Mode should not be empty";
        EXPECT_TRUE(segment.mode == "CW" || segment.mode == "SSB" || segment.mode == "USB" || 
                   segment.mode == "FM" || segment.mode == "NFM" || segment.mode == "AM" || 
                   segment.mode == "Digital") 
                   << "Mode should be valid amateur radio mode";
        
        // Test frequency range
        EXPECT_GT(segment.end_freq, segment.start_freq) << "End frequency should be greater than start frequency";
        EXPECT_GT(segment.start_freq, 0.0) << "Start frequency should be positive";
        EXPECT_GT(segment.end_freq, 0.0) << "End frequency should be positive";
        
        // Test ITU region
        EXPECT_TRUE(segment.itu_region >= 1 && segment.itu_region <= 3) << "ITU region should be 1, 2, or 3";
        
        // Test country
        EXPECT_FALSE(segment.country.empty()) << "Country should not be empty";
        
        // Test license class
        EXPECT_FALSE(segment.license_class.empty()) << "License class should not be empty";
        EXPECT_TRUE(segment.license_class == "Foundation" || segment.license_class == "Intermediate" || 
                   segment.license_class == "Full" || segment.license_class == "Extra") 
                   << "License class should be valid";
        
        // Test power limit
        EXPECT_GT(segment.power_limit, 0.0) << "Power limit should be positive";
        EXPECT_LE(segment.power_limit, 1500.0) << "Power limit should be reasonable";
    }
}

TEST_F(BandSegmentValidationTest, ITURegionDetection) {
    // Test ITU region detection (1, 2, 3)
    std::vector<int> test_regions = {1, 2, 3};
    
    for (int region : test_regions) {
        // Test region validation
        EXPECT_TRUE(region >= 1 && region <= 3) << "ITU region should be 1, 2, or 3";
        
        // Test region-specific band segments
        auto band_segments = generateAmateurBandSegments();
        int region_count = 0;
        
        for (const auto& segment : band_segments) {
            if (segment.itu_region == region) {
                region_count++;
            }
        }
        
        EXPECT_GT(region_count, 0) << "Should have band segments for ITU region " << region;
    }
}

TEST_F(BandSegmentValidationTest, CountrySpecificRegulations) {
    // Test country-specific regulations
    std::vector<std::string> test_countries = {"UK", "USA", "Germany", "Canada", "Australia"};
    
    for (const std::string& country : test_countries) {
        // Test country-specific band segments
        auto band_segments = generateAmateurBandSegments();
        int country_count = 0;
        
        for (const auto& segment : band_segments) {
            if (segment.country == country) {
                country_count++;
                
                // Test country-specific power limits
                if (country == "UK") {
                    EXPECT_LE(segment.power_limit, 100.0) << "UK should have lower power limits";
                } else if (country == "USA") {
                    EXPECT_LE(segment.power_limit, 1500.0) << "USA should have higher power limits";
                }
            }
        }
        
        EXPECT_GT(country_count, 0) << "Should have band segments for country " << country;
    }
}

TEST_F(BandSegmentValidationTest, LicenseClassRequirements) {
    // Test license class requirements
    std::vector<std::string> license_classes = {"Foundation", "Intermediate", "Full", "Extra"};
    
    for (const std::string& license_class : license_classes) {
        // Test license class validation
        EXPECT_FALSE(license_class.empty()) << "License class should not be empty";
        
        // Test license class-specific band segments
        auto band_segments = generateAmateurBandSegments();
        int license_count = 0;
        
        for (const auto& segment : band_segments) {
            if (segment.license_class == license_class) {
                license_count++;
                
                // Test license class-specific power limits
                if (license_class == "Foundation") {
                    EXPECT_LE(segment.power_limit, 10.0) << "Foundation license should have low power limits";
                } else if (license_class == "Intermediate") {
                    EXPECT_LE(segment.power_limit, 100.0) << "Intermediate license should have medium power limits";
                } else if (license_class == "Full" || license_class == "Extra") {
                    EXPECT_LE(segment.power_limit, 1500.0) << "Full/Extra license should have high power limits";
                }
            }
        }
        
        EXPECT_GT(license_count, 0) << "Should have band segments for license class " << license_class;
    }
}

TEST_F(BandSegmentValidationTest, PowerLimitEnforcement) {
    // Test power limit enforcement
    auto band_segments = generateAmateurBandSegments();
    
    for (const auto& segment : band_segments) {
        // Test power limit validation
        EXPECT_GT(segment.power_limit, 0.0) << "Power limit should be positive";
        EXPECT_LE(segment.power_limit, 1500.0) << "Power limit should be reasonable";
        
        // Test power limit by license class
        if (segment.license_class == "Foundation") {
            EXPECT_LE(segment.power_limit, 10.0) << "Foundation license should have low power limits";
        } else if (segment.license_class == "Intermediate") {
            EXPECT_LE(segment.power_limit, 100.0) << "Intermediate license should have medium power limits";
        } else if (segment.license_class == "Full" || segment.license_class == "Extra") {
            EXPECT_LE(segment.power_limit, 1500.0) << "Full/Extra license should have high power limits";
        }
        
        // Test power limit by country
        if (segment.country == "UK") {
            EXPECT_LE(segment.power_limit, 100.0) << "UK should have lower power limits";
        } else if (segment.country == "USA") {
            EXPECT_LE(segment.power_limit, 1500.0) << "USA should have higher power limits";
        }
    }
}

TEST_F(BandSegmentValidationTest, ModeValidation) {
    // Test mode validation (CW, SSB modes, FM, AM, Digital)
    std::vector<std::string> valid_modes = {"CW", "SSB", "USB", "FM", "NFM", "AM", "Digital"};
    auto band_segments = generateAmateurBandSegments();
    
    for (const auto& segment : band_segments) {
        // Test mode validation
        EXPECT_FALSE(segment.mode.empty()) << "Mode should not be empty";
        
        bool valid_mode = false;
        for (const std::string& valid_mode_str : valid_modes) {
            if (segment.mode == valid_mode_str) {
                valid_mode = true;
                break;
            }
        }
        EXPECT_TRUE(valid_mode) << "Mode should be valid: " << segment.mode;
        
        // Test mode-specific frequency ranges
        if (segment.mode == "CW") {
            // CW typically has narrower frequency ranges
            EXPECT_LE(segment.end_freq - segment.start_freq, 100.0) << "CW should have narrow frequency range";
        } else if (segment.mode == "SSB") {
            // SSB typically has wider frequency ranges
            EXPECT_GE(segment.end_freq - segment.start_freq, 50.0) << "SSB should have wider frequency range";
        }
    }
}

TEST_F(BandSegmentValidationTest, OutOfBandRejection) {
    // Test out-of-band rejection
    std::vector<double> out_of_band_frequencies = {
        100.0,    // Below amateur bands
        2000.0,  // Above 160m band
        5000.0,  // Above 80m band
        8000.0,  // Above 40m band
        15000.0, // Above 20m band
        200.0,   // Above 2m band
        500.0    // Above 70cm band
    };
    
    auto band_segments = generateAmateurBandSegments();
    
    for (double frequency : out_of_band_frequencies) {
        bool in_band = false;
        
        for (const auto& segment : band_segments) {
            if (frequency >= segment.start_freq && frequency <= segment.end_freq) {
                in_band = true;
                break;
            }
        }
        
        EXPECT_FALSE(in_band) << "Frequency " << frequency << " should be out of band";
    }
}

// Additional band segment validation tests
TEST_F(BandSegmentValidationTest, FrequencyRangeValidation) {
    // Test frequency range validation
    auto band_segments = generateAmateurBandSegments();
    
    for (const auto& segment : band_segments) {
        // Test frequency range validity
        EXPECT_GT(segment.end_freq, segment.start_freq) << "End frequency should be greater than start frequency";
        EXPECT_GT(segment.start_freq, 0.0) << "Start frequency should be positive";
        EXPECT_GT(segment.end_freq, 0.0) << "End frequency should be positive";
        
        // Test band-specific frequency ranges
        if (segment.band == "160m") {
            EXPECT_GE(segment.start_freq, 1800.0) << "160m band should start at 1800 kHz";
            EXPECT_LE(segment.end_freq, 2000.0) << "160m band should end at 2000 kHz";
        } else if (segment.band == "80m") {
            EXPECT_GE(segment.start_freq, 3500.0) << "80m band should start at 3500 kHz";
            EXPECT_LE(segment.end_freq, 4000.0) << "80m band should end at 4000 kHz";
        } else if (segment.band == "40m") {
            EXPECT_GE(segment.start_freq, 7000.0) << "40m band should start at 7000 kHz";
            EXPECT_LE(segment.end_freq, 7300.0) << "40m band should end at 7300 kHz";
        } else if (segment.band == "20m") {
            EXPECT_GE(segment.start_freq, 14000.0) << "20m band should start at 14000 kHz";
            EXPECT_LE(segment.end_freq, 14350.0) << "20m band should end at 14350 kHz";
        } else if (segment.band == "2m") {
            EXPECT_GE(segment.start_freq, 144.0) << "2m band should start at 144 MHz";
            EXPECT_LE(segment.end_freq, 148.0) << "2m band should end at 148 MHz";
        } else if (segment.band == "70cm") {
            EXPECT_GE(segment.start_freq, 430.0) << "70cm band should start at 430 MHz";
            EXPECT_LE(segment.end_freq, 440.0) << "70cm band should end at 440 MHz";
        }
    }
}

TEST_F(BandSegmentValidationTest, BandSegmentOverlapDetection) {
    // Test band segment overlap detection
    auto band_segments = generateAmateurBandSegments();
    
    // Check for overlapping segments within the same band and mode
    for (size_t i = 0; i < band_segments.size(); ++i) {
        for (size_t j = i + 1; j < band_segments.size(); ++j) {
            const auto& seg1 = band_segments[i];
            const auto& seg2 = band_segments[j];
            
            // Check for overlap in same band, mode, and region
            if (seg1.band == seg2.band && seg1.mode == seg2.mode && seg1.itu_region == seg2.itu_region) {
                bool overlap = (seg1.start_freq < seg2.end_freq && seg2.start_freq < seg1.end_freq);
                
                if (overlap) {
                    // Overlapping segments should have different license classes or countries
                    EXPECT_TRUE(seg1.license_class != seg2.license_class || seg1.country != seg2.country) 
                        << "Overlapping segments should have different license classes or countries";
                }
            }
        }
    }
}

TEST_F(BandSegmentValidationTest, BandSegmentPerformance) {
    // Test band segment validation performance
    const int num_validations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_validations; ++i) {
        auto band_segments = generateAmateurBandSegments();
        
        // Validate each segment
        for (const auto& segment : band_segments) {
            // Basic validation
            EXPECT_GT(segment.end_freq, segment.start_freq);
            EXPECT_GT(segment.power_limit, 0.0);
            EXPECT_TRUE(segment.itu_region >= 1 && segment.itu_region <= 3);
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_validation = static_cast<double>(duration.count()) / num_validations;
    
    // Band segment validation should be fast (adjusted for Valgrind overhead)
    EXPECT_LT(time_per_validation, 200.0) << "Band segment validation too slow: " << time_per_validation << " microseconds";
    
    std::cout << "Band segment validation performance: " << time_per_validation << " microseconds per validation" << std::endl;
}

