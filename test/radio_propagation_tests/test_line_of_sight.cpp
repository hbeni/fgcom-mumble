#include "test_radio_propagation_main.cpp"

// 2.1 Line-of-Sight Tests
TEST_F(LineOfSightTest, DirectLOSCalculation) {
    // Test direct line-of-sight calculation between two points
    double distance = tx_coord.calculateDistance(rx_coord);
    
    // Calculate expected LOS clearance
    double height_diff = rx_coord.altitude - tx_coord.altitude;
    double expected_clearance_angle = std::atan2(height_diff, distance * 1000.0) * 180.0 / M_PI;
    
    // Test with clear LOS (no obstructions) - angle should be negative when RX is below TX
    EXPECT_LT(expected_clearance_angle, 0.0) << "RX is below TX, so clearance angle should be negative";
    
    // Test distance calculation accuracy
    EXPECT_NEAR(distance, 5.0, 0.5) << "Distance calculation should be accurate";
}

TEST_F(LineOfSightTest, TerrainObstructionDetection) {
    // Test terrain obstruction detection
    auto terrain_profile = generateObstructedProfile(tx_coord, rx_coord, 10, 200.0); // 200m obstruction
    
    // Check if obstruction is detected
    bool obstruction_detected = false;
    double max_obstruction_height = 0.0;
    
    for (const auto& point : terrain_profile) {
        if (point.altitude > max_obstruction_height) {
            max_obstruction_height = point.altitude;
        }
        
        // Check if point obstructs LOS
        double fraction = (point.latitude - tx_coord.latitude) / (rx_coord.latitude - tx_coord.latitude);
        double expected_altitude = tx_coord.altitude + (rx_coord.altitude - tx_coord.altitude) * fraction;
        
        if (point.altitude > expected_altitude + 10.0) { // 10m threshold
            obstruction_detected = true;
        }
    }
    
    EXPECT_TRUE(obstruction_detected) << "Terrain obstruction should be detected";
    EXPECT_GT(max_obstruction_height, 150.0) << "Obstruction height should be significant";
}

TEST_F(LineOfSightTest, EarthCurvatureEffects) {
    // Test earth curvature effects on LOS
    double distance_km = tx_coord.calculateDistance(rx_coord);
    
    // Calculate earth curvature correction
    double earth_radius_km = 6371.0;
    double curvature_correction = (distance_km * distance_km) / (2.0 * earth_radius_km);
    
    // Test with different altitudes
    std::vector<double> test_altitudes = {10.0, 50.0, 100.0, 500.0, 1000.0};
    
    for (double altitude : test_altitudes) {
        // Calculate effective antenna height considering earth curvature
        double effective_height = altitude - curvature_correction;
        
        EXPECT_GT(effective_height, 0.0) << "Effective height should be positive";
        EXPECT_LT(effective_height, altitude) << "Effective height should be less than actual height";
    }
}

TEST_F(LineOfSightTest, AltitudeBasedRangeCalculation) {
    // Test altitude-based range calculation
    std::vector<double> test_altitudes = {10.0, 50.0, 100.0, 500.0, 1000.0};
    double frequency_mhz = test_frequency_vhf;
    
    for (double altitude : test_altitudes) {
        // Calculate radio horizon distance
        double horizon_distance = 3.57 * std::sqrt(altitude); // km
        
        // Calculate Fresnel zone radius
        double wavelength_m = 300.0 / frequency_mhz;
        double fresnel_radius = std::sqrt(wavelength_m * horizon_distance * 1000.0 / 2.0);
        
        // Test that higher altitudes give longer ranges
        EXPECT_GT(horizon_distance, 0.0) << "Horizon distance should be positive";
        EXPECT_GT(fresnel_radius, 0.0) << "Fresnel radius should be positive";
        
        // Higher altitudes should give longer ranges
        if (altitude > 50.0) {
            EXPECT_GT(horizon_distance, 25.0) << "High altitude should give long range";
        }
    }
}

TEST_F(LineOfSightTest, FresnelZoneClearance) {
    // Test Fresnel zone clearance calculations
    double distance_km = tx_coord.calculateDistance(rx_coord);
    double frequency_mhz = test_frequency_vhf;
    
    // Calculate Fresnel zone radius
    double wavelength_m = 300.0 / frequency_mhz;
    double fresnel_radius = std::sqrt(wavelength_m * distance_km * 1000.0 / 2.0);
    
    // Test Fresnel zone clearance requirements
    double required_clearance = fresnel_radius * 0.6; // 60% clearance for good signal
    
    EXPECT_GT(fresnel_radius, 0.0) << "Fresnel radius should be positive";
    EXPECT_GT(required_clearance, 0.0) << "Required clearance should be positive";
    
    // Test with different frequencies
    std::vector<double> test_frequencies = {118.0, 300.0, 14.0};
    
    for (double freq : test_frequencies) {
        double wavelength = 300.0 / freq;
        double fresnel = std::sqrt(wavelength * distance_km * 1000.0 / 2.0);
        
        EXPECT_GT(fresnel, 0.0) << "Fresnel radius should be positive for frequency " << freq;
        
        // Higher frequencies should have smaller Fresnel zones
        if (freq > 100.0) {
            EXPECT_LT(fresnel, 100.0) << "High frequency should have reasonable Fresnel zone";
        }
    }
}

TEST_F(LineOfSightTest, MultipleObstructionHandling) {
    // Test handling of multiple obstructions
    auto profile = generateTerrainProfile(tx_coord, rx_coord, 20);
    
    // Add multiple obstructions
    profile[5].altitude = 150.0;   // First obstruction
    profile[10].altitude = 200.0;  // Second obstruction
    profile[15].altitude = 120.0;  // Third obstruction
    
    // Test obstruction detection
    int obstruction_count = 0;
    double max_obstruction = 0.0;
    
    for (size_t i = 0; i < profile.size(); ++i) {
        const auto& point = profile[i];
        
        // Calculate expected altitude at this point
        double fraction = static_cast<double>(i) / (profile.size() - 1);
        double expected_altitude = tx_coord.altitude + (rx_coord.altitude - tx_coord.altitude) * fraction;
        
        if (point.altitude > expected_altitude + 10.0) {
            obstruction_count++;
            max_obstruction = std::max(max_obstruction, point.altitude);
        }
    }
    
    EXPECT_GE(obstruction_count, 3) << "Should detect multiple obstructions";
    EXPECT_GT(max_obstruction, 180.0) << "Should identify highest obstruction";
}

// Additional line-of-sight tests
TEST_F(LineOfSightTest, LOSWithDifferentDistances) {
    // Test LOS with different distances
    std::vector<double> test_distances = {1.0, 5.0, 10.0, 50.0, 100.0}; // km
    
    for (double distance : test_distances) {
        // Create test coordinates at specified distance
        Coordinate test_rx = rx_coord;
        test_rx.latitude = tx_coord.latitude + (distance / 111.0); // Rough km to degrees
        
        double actual_distance = tx_coord.calculateDistance(test_rx);
        
        // Test distance calculation (allow for conversion errors)
        EXPECT_NEAR(actual_distance, distance, 1.5) << "Distance calculation should be accurate";
        
        // Test LOS clearance at different distances
        double height_diff = test_rx.altitude - tx_coord.altitude;
        double clearance_angle = std::atan2(height_diff, distance * 1000.0) * 180.0 / M_PI;
        
        EXPECT_GT(clearance_angle, -90.0) << "Clearance angle should be reasonable";
        EXPECT_LT(clearance_angle, 90.0) << "Clearance angle should be reasonable";
    }
}

TEST_F(LineOfSightTest, LOSWithDifferentAltitudes) {
    // Test LOS with different altitude combinations
    std::vector<std::pair<double, double>> altitude_pairs = {
        {10.0, 10.0},   // Same altitude
        {10.0, 100.0},  // Different altitudes
        {100.0, 10.0},  // Reversed altitudes
        {500.0, 1000.0}, // High altitudes
        {0.0, 2000.0}   // Ground to high altitude
    };
    
    for (const auto& pair : altitude_pairs) {
        Coordinate test_tx = tx_coord;
        Coordinate test_rx = rx_coord;
        test_tx.altitude = pair.first;
        test_rx.altitude = pair.second;
        
        double distance = test_tx.calculateDistance(test_rx);
        double height_diff = test_rx.altitude - test_tx.altitude;
        double clearance_angle = std::atan2(height_diff, distance * 1000.0) * 180.0 / M_PI;
        
        // Test that clearance angle is calculated correctly
        EXPECT_GT(clearance_angle, -90.0) << "Clearance angle should be reasonable";
        EXPECT_LT(clearance_angle, 90.0) << "Clearance angle should be reasonable";
        
        // Test that higher altitudes give better clearance
        if (pair.first > 100.0 && pair.second > 100.0) {
            EXPECT_GT(std::abs(clearance_angle), 0.1) << "High altitudes should give good clearance";
        }
    }
}

TEST_F(LineOfSightTest, LOSPerformanceTest) {
    // Test LOS calculation performance
    const int num_calculations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        // Generate random test coordinates
        Coordinate test_tx = tx_coord;
        Coordinate test_rx = rx_coord;
        test_tx.latitude += (i % 100) * 0.001;
        test_rx.longitude += (i % 100) * 0.001;
        
        double distance = test_tx.calculateDistance(test_rx);
        double height_diff = test_rx.altitude - test_tx.altitude;
        double clearance_angle = std::atan2(height_diff, distance * 1000.0) * 180.0 / M_PI;
        
        // Verify calculation is reasonable
        EXPECT_GT(distance, 0.0);
        EXPECT_GT(clearance_angle, -90.0);
        EXPECT_LT(clearance_angle, 90.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_calculation = static_cast<double>(duration.count()) / num_calculations;
    
    // LOS calculations should be fast
    EXPECT_LT(time_per_calculation, 100.0) << "LOS calculation too slow: " << time_per_calculation << " microseconds";
    
    std::cout << "LOS calculation performance: " << time_per_calculation << " microseconds per calculation" << std::endl;
}

TEST_F(LineOfSightTest, LOSWithTerrainProfile) {
    // Test LOS with detailed terrain profile
    auto terrain_profile = generateTerrainProfile(tx_coord, rx_coord, 100);
    
    // Add realistic terrain variations
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<double> dis(0.0, 20.0); // 20m standard deviation
    
    for (auto& point : terrain_profile) {
        point.altitude += dis(gen);
        point.altitude = std::max(0.0, point.altitude); // Ensure non-negative
    }
    
    // Test LOS analysis
    bool los_clear = true;
    double max_obstruction = 0.0;
    
    for (size_t i = 0; i < terrain_profile.size(); ++i) {
        const auto& point = terrain_profile[i];
        
        // Calculate expected altitude at this point
        double fraction = static_cast<double>(i) / (terrain_profile.size() - 1);
        double expected_altitude = tx_coord.altitude + (rx_coord.altitude - tx_coord.altitude) * fraction;
        
        if (point.altitude > expected_altitude + 10.0) {
            los_clear = false;
            max_obstruction = std::max(max_obstruction, point.altitude);
        }
    }
    
    // Test that terrain profile analysis works
    if (!los_clear) {
        EXPECT_GT(max_obstruction, 0.0) << "Should identify obstruction height";
    }
    
    // Test that profile has reasonable characteristics
    EXPECT_GT(terrain_profile.size(), 50) << "Terrain profile should have sufficient points";
}
