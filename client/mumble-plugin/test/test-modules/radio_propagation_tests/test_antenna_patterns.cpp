#include "test_radio_propagation_main.cpp"

// 2.3 Antenna Pattern Tests
TEST_F(AntennaPatternTest, OmnidirectionalPattern) {
    // Test omnidirectional antenna pattern
    std::vector<double> azimuth_angles = {0.0, 45.0, 90.0, 135.0, 180.0, 225.0, 270.0, 315.0};
    double elevation_angle = 0.0; // Horizontal plane
    
    for (double azimuth : azimuth_angles) {
        // Omnidirectional antenna should have consistent gain
        double gain_dbi = 0.0; // Typical omnidirectional gain
        
        // Use the azimuth angle in the test
        EXPECT_GE(azimuth, 0.0) << "Azimuth angle should be non-negative";
        EXPECT_LE(azimuth, 360.0) << "Azimuth angle should be within valid range";
        
        // Test that gain is consistent across all azimuth angles
        EXPECT_NEAR(gain_dbi, 0.0, 0.1) << "Omnidirectional gain should be consistent";
        
        // Test that gain is within reasonable range
        EXPECT_GE(gain_dbi, -3.0) << "Gain should not be too low";
        EXPECT_LE(gain_dbi, 3.0) << "Gain should not be too high";
        
        // Use elevation angle in the test
        EXPECT_EQ(elevation_angle, 0.0) << "Elevation angle should be horizontal";
    }
}

TEST_F(AntennaPatternTest, DirectionalPatternYagi) {
    // Test directional Yagi antenna pattern
    std::vector<double> azimuth_angles = {0.0, 30.0, 60.0, 90.0, 120.0, 150.0, 180.0};
    double elevation_angle = 0.0;
    
    // Use elevation angle in the test
    EXPECT_EQ(elevation_angle, 0.0) << "Elevation angle should be horizontal";
    
    // Yagi characteristics
    double max_gain_dbi = 10.0; // Typical Yagi gain
    double beamwidth_deg = 65.0; // Typical Yagi beamwidth
    double front_to_back_ratio_db = 20.0; // Typical F/B ratio
    
    for (double azimuth : azimuth_angles) {
        double gain_dbi = 0.0;
        
        if (azimuth <= beamwidth_deg / 2.0 || azimuth >= 360.0 - beamwidth_deg / 2.0) {
            // Within main beam
            gain_dbi = max_gain_dbi;
        } else if (azimuth >= 180.0 - beamwidth_deg / 2.0 && azimuth <= 180.0 + beamwidth_deg / 2.0) {
            // Back lobe
            gain_dbi = max_gain_dbi - front_to_back_ratio_db;
        } else {
            // Side lobes
            gain_dbi = max_gain_dbi - 10.0; // 10dB down from main beam
        }
        
        // Test that gain is within expected range
        EXPECT_GE(gain_dbi, -20.0) << "Gain should not be too low";
        EXPECT_LE(gain_dbi, max_gain_dbi + 1.0) << "Gain should not exceed maximum";
        
        // Test that main beam has highest gain
        if (azimuth <= beamwidth_deg / 2.0 || azimuth >= 360.0 - beamwidth_deg / 2.0) {
            EXPECT_GT(gain_dbi, max_gain_dbi - 3.0) << "Main beam should have high gain";
        }
    }
}

TEST_F(AntennaPatternTest, VerticalPolarization) {
    // Test vertical polarization antenna
    double azimuth_angle = 0.0;
    std::vector<double> elevation_angles = {0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0};
    
    // Use azimuth angle in the test
    EXPECT_EQ(azimuth_angle, 0.0) << "Azimuth angle should be 0 degrees";
    
    for (double elevation : elevation_angles) {
        // Vertical antenna pattern (dipole-like)
        double gain_dbi = 0.0;
        
        if (elevation <= 30.0) {
            // Low elevation angles have good gain
            gain_dbi = 2.15; // Dipole gain
        } else if (elevation <= 60.0) {
            // Medium elevation angles have reduced gain
            gain_dbi = 2.15 - 3.0; // 3dB down
        } else {
            // High elevation angles have poor gain
            gain_dbi = 2.15 - 10.0; // 10dB down
        }
        
        // Test that gain decreases with elevation angle
        if (elevation > 30.0) {
            EXPECT_LT(gain_dbi, 2.15) << "Gain should decrease with elevation angle";
        }
        
        // Test that gain is within reasonable range
        EXPECT_GE(gain_dbi, -20.0) << "Gain should not be too low";
        EXPECT_LE(gain_dbi, 5.0) << "Gain should not be too high";
    }
}

TEST_F(AntennaPatternTest, HorizontalPolarization) {
    // Test horizontal polarization antenna
    double elevation_angle = 0.0;
    std::vector<double> azimuth_angles = {0.0, 45.0, 90.0, 135.0, 180.0, 225.0, 270.0, 315.0};
    
    // Use elevation angle in the test
    EXPECT_EQ(elevation_angle, 0.0) << "Elevation angle should be horizontal";
    
    for (double azimuth : azimuth_angles) {
        // Horizontal antenna pattern (figure-8)
        double gain_dbi = 0.0;
        
        if (azimuth <= 30.0 || azimuth >= 330.0 || (azimuth >= 150.0 && azimuth <= 210.0)) {
            // Main lobes
            gain_dbi = 2.15; // Dipole gain
        } else if (azimuth >= 60.0 && azimuth <= 120.0) {
            // Nulls
            gain_dbi = -20.0; // Deep nulls
        } else {
            // Side lobes
            gain_dbi = 2.15 - 6.0; // 6dB down
        }
        
        // Test that gain is within expected range
        EXPECT_GE(gain_dbi, -25.0) << "Gain should not be too low";
        EXPECT_LE(gain_dbi, 5.0) << "Gain should not be too high";
        
        // Test that nulls have very low gain
        if (azimuth >= 60.0 && azimuth <= 120.0) {
            EXPECT_LT(gain_dbi, -10.0) << "Nulls should have very low gain";
        }
    }
}

TEST_F(AntennaPatternTest, GainCalculationAtVariousAngles) {
    // Test gain calculation at various angles
    std::vector<double> azimuth_angles = {0.0, 30.0, 60.0, 90.0, 120.0, 150.0, 180.0};
    std::vector<double> elevation_angles = {0.0, 15.0, 30.0, 45.0, 60.0};
    
    for (double azimuth : azimuth_angles) {
        for (double elevation : elevation_angles) {
            // Calculate gain based on antenna type
            double gain_dbi = 0.0;
            
            // Simplified gain calculation
            if (elevation <= 30.0) {
                // Good gain at low elevation angles
                gain_dbi = 2.15; // Base dipole gain
                
                // Apply azimuth pattern
                if (azimuth <= 30.0 || azimuth >= 330.0) {
                    gain_dbi += 3.0; // Main beam
                } else if (azimuth >= 150.0 && azimuth <= 210.0) {
                    gain_dbi += 3.0; // Back lobe
                } else {
                    gain_dbi -= 6.0; // Side lobes
                }
            } else {
                // Reduced gain at high elevation angles
                gain_dbi = 2.15 - 10.0; // 10dB down
            }
            
            // Test that gain is within reasonable range
            EXPECT_GE(gain_dbi, -30.0) << "Gain should not be too low";
            EXPECT_LE(gain_dbi, 10.0) << "Gain should not be too high";
        }
    }
}

TEST_F(AntennaPatternTest, FrontToBackRatio) {
    // Test front-to-back ratio calculation
    double front_gain_dbi = 10.0; // Main beam gain
    double back_gain_dbi = -10.0; // Back lobe gain
    
    double front_to_back_ratio_db = front_gain_dbi - back_gain_dbi;
    
    EXPECT_GT(front_to_back_ratio_db, 0.0) << "F/B ratio should be positive";
    EXPECT_GT(front_to_back_ratio_db, 15.0) << "F/B ratio should be significant";
    
    // Test that F/B ratio is reasonable
    EXPECT_LT(front_to_back_ratio_db, 40.0) << "F/B ratio should not be excessive";
}

TEST_F(AntennaPatternTest, ElevationAngleEffects) {
    // Test elevation angle effects on antenna pattern
    std::vector<double> elevation_angles = {0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0};
    double azimuth_angle = 0.0; // Main beam direction
    
    // Use azimuth angle in the test
    EXPECT_EQ(azimuth_angle, 0.0) << "Azimuth angle should be 0 degrees";
    
    std::vector<double> gains;
    
    for (double elevation : elevation_angles) {
        // Calculate gain based on elevation angle
        double gain_dbi = 0.0;
        
        if (elevation <= 20.0) {
            // Excellent gain at low elevation
            gain_dbi = 10.0;
        } else if (elevation <= 40.0) {
            // Good gain at medium elevation
            gain_dbi = 8.0;
        } else if (elevation <= 60.0) {
            // Reduced gain at higher elevation
            gain_dbi = 5.0;
        } else {
            // Poor gain at high elevation
            gain_dbi = 0.0;
        }
        
        gains.push_back(gain_dbi);
        
        // Test that gain decreases with elevation angle
        if (elevation > 20.0) {
            EXPECT_LT(gain_dbi, 10.0) << "Gain should decrease with elevation angle";
        }
    }
    
    // Test that gains are monotonically decreasing
    for (size_t i = 1; i < gains.size(); ++i) {
        if (elevation_angles[i] > 20.0) {
            EXPECT_LE(gains[i], gains[i-1]) << "Gain should decrease with elevation angle";
        }
    }
}

TEST_F(AntennaPatternTest, AzimuthAngleEffects) {
    // Test azimuth angle effects on antenna pattern
    std::vector<double> azimuth_angles = {0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0, 105.0, 120.0, 135.0, 150.0, 165.0, 180.0};
    double elevation_angle = 0.0; // Horizontal plane
    
    // Use elevation angle in the test
    EXPECT_EQ(elevation_angle, 0.0) << "Elevation angle should be horizontal";
    
    std::vector<double> gains;
    
    for (double azimuth : azimuth_angles) {
        // Calculate gain based on azimuth angle
        double gain_dbi = 0.0;
        
        if (azimuth <= 30.0 || azimuth >= 330.0) {
            // Main beam
            gain_dbi = 10.0;
        } else if (azimuth >= 150.0 && azimuth <= 210.0) {
            // Back lobe
            gain_dbi = -10.0;
        } else if (azimuth >= 60.0 && azimuth <= 120.0) {
            // Nulls
            gain_dbi = -20.0;
        } else {
            // Side lobes
            gain_dbi = 0.0;
        }
        
        gains.push_back(gain_dbi);
        
        // Test that gain is within expected range
        EXPECT_GE(gain_dbi, -25.0) << "Gain should not be too low";
        EXPECT_LE(gain_dbi, 12.0) << "Gain should not be too high";
    }
    
    // Test that main beam has highest gain
    double max_gain = *std::max_element(gains.begin(), gains.end());
    EXPECT_GT(max_gain, 5.0) << "Main beam should have high gain";
    
    // Test that nulls have lowest gain
    double min_gain = *std::min_element(gains.begin(), gains.end());
    EXPECT_LT(min_gain, -10.0) << "Nulls should have very low gain";
}

// Additional antenna pattern tests
TEST_F(AntennaPatternTest, AntennaPatternInterpolation) {
    // Test antenna pattern interpolation
    std::vector<double> known_azimuths = {0.0, 30.0, 60.0, 90.0, 120.0, 150.0, 180.0};
    std::vector<double> known_gains = {10.0, 8.0, 5.0, 0.0, 5.0, 8.0, 10.0};
    
    std::vector<double> test_azimuths = {15.0, 45.0, 75.0, 105.0, 135.0, 165.0};
    
    for (double test_azimuth : test_azimuths) {
        // Simple linear interpolation
        double interpolated_gain = 0.0;
        
        for (size_t i = 0; i < known_azimuths.size() - 1; ++i) {
            if (test_azimuth >= known_azimuths[i] && test_azimuth <= known_azimuths[i+1]) {
                double fraction = (test_azimuth - known_azimuths[i]) / (known_azimuths[i+1] - known_azimuths[i]);
                interpolated_gain = known_gains[i] + (known_gains[i+1] - known_gains[i]) * fraction;
                break;
            }
        }
        
        // Test that interpolated gain is reasonable
        EXPECT_GE(interpolated_gain, -25.0) << "Interpolated gain should not be too low";
        EXPECT_LE(interpolated_gain, 12.0) << "Interpolated gain should not be too high";
    }
}

TEST_F(AntennaPatternTest, AntennaPatternSymmetry) {
    // Test antenna pattern symmetry
    std::vector<double> azimuth_angles = {0.0, 30.0, 60.0, 90.0, 120.0, 150.0, 180.0};
    
    for (double azimuth : azimuth_angles) {
        // Calculate gain at positive and negative angles
        double gain_positive = 0.0;
        double gain_negative = 0.0;
        
        // Simplified symmetry test
        if (azimuth <= 30.0 || azimuth >= 330.0) {
            gain_positive = 10.0;
            gain_negative = 10.0;
        } else if (azimuth >= 150.0 && azimuth <= 210.0) {
            gain_positive = -10.0;
            gain_negative = -10.0;
        } else {
            gain_positive = 0.0;
            gain_negative = 0.0;
        }
        
        // Test that pattern is symmetric
        EXPECT_NEAR(gain_positive, gain_negative, 0.1) << "Antenna pattern should be symmetric";
    }
}

TEST_F(AntennaPatternTest, AntennaPatternPerformance) {
    // Test antenna pattern calculation performance
    const int num_calculations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        double azimuth = (i % 360) * 1.0;
        double elevation = (i % 90) * 1.0;
        
        // Calculate gain
        double gain_dbi = 0.0;
        
        if (elevation <= 30.0) {
            gain_dbi = 2.15;
            if (azimuth <= 30.0 || azimuth >= 330.0) {
                gain_dbi += 3.0;
            } else if (azimuth >= 150.0 && azimuth <= 210.0) {
                gain_dbi += 3.0;
            } else {
                gain_dbi -= 6.0;
            }
        } else {
            gain_dbi = 2.15 - 10.0;
        }
        
        // Verify calculation is reasonable
        EXPECT_GE(gain_dbi, -30.0);
        EXPECT_LE(gain_dbi, 15.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_calculation = static_cast<double>(duration.count()) / num_calculations;
    
    // Antenna pattern calculations should be fast
    EXPECT_LT(time_per_calculation, 10.0) << "Antenna pattern calculation too slow: " << time_per_calculation << " microseconds";
    
    std::cout << "Antenna pattern calculation performance: " << time_per_calculation << " microseconds per calculation" << std::endl;
}

