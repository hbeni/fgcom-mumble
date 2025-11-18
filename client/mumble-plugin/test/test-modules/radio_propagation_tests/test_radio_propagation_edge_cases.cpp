#include "test_radio_propagation_main.cpp"

// Radio Propagation Edge Case Tests
// These tests cover extreme conditions, boundary values, and error states

TEST_F(RadioPropagationTest, ExtremeDistanceValues) {
    // Test with extreme distance values
    std::vector<double> extreme_distances = {
        0.0,                    // Zero distance
        -1.0,                   // Negative distance
        1.0,                    // 1 meter
        1000.0,                 // 1 kilometer
        1000000.0,              // 1000 kilometers
        1000000000.0,           // 1 million kilometers
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::epsilon(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    };
    
    for (double distance : extreme_distances) {
        EXPECT_NO_THROW({
            // Test distance-based path loss calculation
            double path_loss = calculatePathLoss(distance, 100.0e6); // 100 MHz
            
            // Verify path loss is reasonable
            if (std::isfinite(distance) && distance > 0.0) {
                EXPECT_GT(path_loss, 0.0) << "Path loss should be positive for distance: " << distance;
                EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable for distance: " << distance;
            } else {
                // For invalid distances, path loss should be handled gracefully
                EXPECT_TRUE(std::isfinite(path_loss) || path_loss == 0.0) << "Path loss should be finite or zero for invalid distance: " << distance;
            }
        }) << "Radio propagation should handle extreme distance: " << distance;
    }
}

TEST_F(RadioPropagationTest, ExtremeFrequencyValues) {
    // Test with extreme frequency values
    std::vector<double> extreme_frequencies = {
        0.0,                    // Zero frequency
        -1.0,                   // Negative frequency
        1.0,                    // 1 Hz
        1000.0,                 // 1 kHz
        1000000.0,              // 1 MHz
        1000000000.0,           // 1 GHz
        1000000000000.0,        // 1 THz
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::epsilon(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    };
    
    for (double frequency : extreme_frequencies) {
        EXPECT_NO_THROW({
            // Test frequency-dependent propagation
            double path_loss = calculatePathLoss(1000.0, frequency); // 1 km distance
            
            // Verify path loss is reasonable
            if (std::isfinite(frequency) && frequency > 0.0) {
                EXPECT_GT(path_loss, 0.0) << "Path loss should be positive for frequency: " << frequency;
                EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable for frequency: " << frequency;
            } else {
                // For invalid frequencies, path loss should be handled gracefully
                EXPECT_TRUE(std::isfinite(path_loss) || path_loss == 0.0) << "Path loss should be finite or zero for invalid frequency: " << frequency;
            }
        }) << "Radio propagation should handle extreme frequency: " << frequency;
    }
}

TEST_F(RadioPropagationTest, ExtremeCoordinateValues) {
    // Test with extreme coordinate values
    std::vector<std::pair<double, double>> extreme_coordinates = {
        {0.0, 0.0},             // Origin
        {-180.0, -90.0},        // Minimum longitude/latitude
        {180.0, 90.0},          // Maximum longitude/latitude
        {-181.0, -91.0},        // Beyond minimum
        {181.0, 91.0},          // Beyond maximum
        {std::numeric_limits<double>::max(), std::numeric_limits<double>::max()},
        {std::numeric_limits<double>::min(), std::numeric_limits<double>::min()},
        {std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::quiet_NaN()},
        {std::numeric_limits<double>::infinity(), std::numeric_limits<double>::infinity()},
        {-std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity()}
    };
    
    for (const auto& coords : extreme_coordinates) {
        double lon = coords.first;
        double lat = coords.second;
        
        EXPECT_NO_THROW({
            // Test coordinate-based calculations
            double distance = calculateDistance(lon, lat, 0.0, 0.0);
            
            // Verify distance is reasonable
            if (std::isfinite(lon) && std::isfinite(lat) && 
                lon >= -180.0 && lon <= 180.0 && 
                lat >= -90.0 && lat <= 90.0) {
                EXPECT_GE(distance, 0.0) << "Distance should be non-negative for coordinates: " << lon << ", " << lat;
                EXPECT_LT(distance, 20000000.0) << "Distance should be reasonable for coordinates: " << lon << ", " << lat;
            } else {
                // For invalid coordinates, distance should be handled gracefully
                EXPECT_TRUE(std::isfinite(distance) || distance == 0.0) << "Distance should be finite or zero for invalid coordinates: " << lon << ", " << lat;
            }
        }) << "Radio propagation should handle extreme coordinates: " << lon << ", " << lat;
    }
}

TEST_F(RadioPropagationTest, ExtremeAltitudeValues) {
    // Test with extreme altitude values
    std::vector<double> extreme_altitudes = {
        0.0,                    // Sea level
        -100.0,                 // Below sea level
        100.0,                  // 100 meters
        1000.0,                 // 1 kilometer
        10000.0,                // 10 kilometers
        100000.0,               // 100 kilometers
        1000000.0,              // 1000 kilometers
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::epsilon(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    };
    
    for (double altitude : extreme_altitudes) {
        EXPECT_NO_THROW({
            // Test altitude-based propagation
            double range = calculateLineOfSightRange(altitude);
            
            // Verify range is reasonable
            if (std::isfinite(altitude) && altitude >= 0.0) {
                EXPECT_GT(range, 0.0) << "Range should be positive for altitude: " << altitude;
                EXPECT_LT(range, 1000000.0) << "Range should be reasonable for altitude: " << altitude;
            } else {
                // For invalid altitudes, range should be handled gracefully
                EXPECT_TRUE(std::isfinite(range) || range == 0.0) << "Range should be finite or zero for invalid altitude: " << altitude;
            }
        }) << "Radio propagation should handle extreme altitude: " << altitude;
    }
}

TEST_F(RadioPropagationTest, ExtremeWeatherConditions) {
    // Test with extreme weather conditions
    std::vector<double> extreme_temperatures = {
        -100.0,                 // Very cold
        0.0,                    // Freezing
        50.0,                   // Hot
        100.0,                  // Very hot
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    };
    
    std::vector<double> extreme_humidity = {
        0.0,                    // No humidity
        50.0,                   // Normal humidity
        100.0,                  // Maximum humidity
        150.0,                  // Beyond maximum
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    };
    
    for (double temperature : extreme_temperatures) {
        for (double humidity : extreme_humidity) {
            EXPECT_NO_THROW({
                // Test weather-dependent propagation
                double atmospheric_loss = calculateAtmosphericLoss(temperature, humidity, 100.0e6); // 100 MHz
                
                // Verify atmospheric loss is reasonable
                if (std::isfinite(temperature) && std::isfinite(humidity)) {
                    EXPECT_GE(atmospheric_loss, 0.0) << "Atmospheric loss should be non-negative for temp: " << temperature << ", humidity: " << humidity;
                    EXPECT_LT(atmospheric_loss, 100.0) << "Atmospheric loss should be reasonable for temp: " << temperature << ", humidity: " << humidity;
                } else {
                    // For invalid weather conditions, loss should be handled gracefully
                    EXPECT_TRUE(std::isfinite(atmospheric_loss) || atmospheric_loss == 0.0) << "Atmospheric loss should be finite or zero for invalid weather: " << temperature << ", " << humidity;
                }
            }) << "Radio propagation should handle extreme weather: " << temperature << ", " << humidity;
        }
    }
}

TEST_F(RadioPropagationTest, ConcurrentPropagationCalculations) {
    // Test concurrent propagation calculations
    std::atomic<bool> test_running{true};
    std::atomic<int> calculation_count{0};
    std::vector<std::thread> threads;
    
    // Start multiple threads making calculations
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&, i]() {
            while (test_running.load()) {
                try {
                    // Make different calculations
                    switch (i % 4) {
                        case 0: {
                            double distance = 1000.0 + (i % 1000);
                            double frequency = 100.0e6 + (i % 1000) * 1e6;
                            double path_loss = calculatePathLoss(distance, frequency);
                            EXPECT_GT(path_loss, 0.0) << "Path loss should be positive";
                            break;
                        }
                        case 1: {
                            double lon = -180.0 + (i % 360);
                            double lat = -90.0 + (i % 180);
                            double distance = calculateDistance(lon, lat, 0.0, 0.0);
                            EXPECT_GE(distance, 0.0) << "Distance should be non-negative";
                            break;
                        }
                        case 2: {
                            double altitude = 100.0 + (i % 1000);
                            double range = calculateLineOfSightRange(altitude);
                            EXPECT_GT(range, 0.0) << "Range should be positive";
                            break;
                        }
                        case 3: {
                            double temperature = -50.0 + (i % 100);
                            double humidity = (i % 100);
                            double loss = calculateAtmosphericLoss(temperature, humidity, 100.0e6);
                            EXPECT_GE(loss, 0.0) << "Atmospheric loss should be non-negative";
                            break;
                        }
                    }
                    calculation_count++;
                } catch (const std::exception& e) {
                    // Log but don't fail the test
                    std::cerr << "Propagation calculation exception: " << e.what() << std::endl;
                }
            }
        });
    }
    
    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    test_running = false;
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_GT(calculation_count.load(), 0) << "Should have made some calculations";
}

TEST_F(RadioPropagationTest, MemoryPressureConditions) {
    // Test under memory pressure conditions
    std::vector<std::vector<double>> memory_blocks;
    
    // Allocate memory to simulate pressure
    for (int i = 0; i < 20; ++i) {
        memory_blocks.emplace_back(100000, 0.5); // 100k values each
    }
    
    EXPECT_NO_THROW({
        // Make calculations under memory pressure
        for (int i = 0; i < 1000; ++i) {
            double distance = 1000.0 + (i % 1000);
            double frequency = 100.0e6 + (i % 1000) * 1e6;
            double path_loss = calculatePathLoss(distance, frequency);
            
            EXPECT_GT(path_loss, 0.0) << "Path loss should be positive under memory pressure";
            EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable under memory pressure";
        }
    }) << "Radio propagation should work under memory pressure";
}

TEST_F(RadioPropagationTest, BoundaryValuePrecision) {
    // Test boundary value precision
    std::vector<double> boundary_distances = {
        0.0, 0.001, -0.001,     // Zero distance boundaries
        1000.0, 999.999, 1000.001  // 1km boundaries
    };
    
    std::vector<double> boundary_frequencies = {
        0.0, 0.001, -0.001,     // Zero frequency boundaries
        100.0e6, 99.999e6, 100.001e6  // 100MHz boundaries
    };
    
    for (double distance : boundary_distances) {
        for (double frequency : boundary_frequencies) {
            EXPECT_NO_THROW({
                double path_loss = calculatePathLoss(distance, frequency);
                
                if (distance > 0.0 && frequency > 0.0) {
                    EXPECT_GT(path_loss, 0.0) << "Path loss should be positive for distance: " << distance << ", frequency: " << frequency;
                    EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable for distance: " << distance << ", frequency: " << frequency;
                } else {
                    EXPECT_TRUE(std::isfinite(path_loss) || path_loss == 0.0) << "Path loss should be finite or zero for boundary values";
                }
            }) << "Radio propagation should handle boundary values: " << distance << ", " << frequency;
        }
    }
}

TEST_F(RadioPropagationTest, ResourceExhaustionScenarios) {
    // Test resource exhaustion scenarios
    std::vector<std::unique_ptr<RadioPropagation>> temp_instances;
    
    EXPECT_NO_THROW({
        // Try to create many instances (should fail gracefully)
        for (int i = 0; i < 1000; ++i) {
            try {
                // This should fail for singleton, but not crash
                auto instance = std::make_unique<RadioPropagation>();
                temp_instances.push_back(std::move(instance));
            } catch (const std::exception& e) {
                // Expected for singleton pattern
            }
        }
        
        // Verify main instance still works
        double path_loss = calculatePathLoss(1000.0, 100.0e6);
        EXPECT_GT(path_loss, 0.0) << "Path loss should be positive after resource exhaustion";
        EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable after resource exhaustion";
    }) << "Radio propagation should handle resource exhaustion gracefully";
}

TEST_F(RadioPropagationTest, ExceptionHandling) {
    // Test exception handling
    for (int i = 0; i < 100; ++i) {
        try {
            // Make some calculations
            double distance = 1000.0 + (i % 1000);
            double frequency = 100.0e6 + (i % 1000) * 1e6;
            double path_loss = calculatePathLoss(distance, frequency);
            
            // Verify result is reasonable
            EXPECT_GT(path_loss, 0.0) << "Path loss should be positive";
            EXPECT_LT(path_loss, 1000.0) << "Path loss should be reasonable";
        } catch (const std::exception& e) {
            // If an exception occurs, verify system is still functional
            double test_path_loss = calculatePathLoss(1000.0, 100.0e6);
            EXPECT_GT(test_path_loss, 0.0) << "System should still work after exception";
        }
    }
}
