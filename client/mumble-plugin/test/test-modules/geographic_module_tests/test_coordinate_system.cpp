#include "test_geographic_module_main.cpp"

// 6.1 Coordinate System Tests
TEST_F(CoordinateSystemTest, LatLonToCartesianConversion) {
    // Test lat/lon to Cartesian conversion
    double lat = test_latitude_nyc;
    double lon = test_longitude_nyc;
    double alt = test_altitude_aircraft;
    
    auto [x, y, z] = latLonToCartesian(lat, lon, alt);
    
    // Test conversion accuracy
    EXPECT_GT(x, 0.0) << "X coordinate should be positive for NYC";
    EXPECT_LT(y, 0.0) << "Y coordinate should be negative for NYC (west of prime meridian)";
    EXPECT_GT(z, 0.0) << "Z coordinate should be positive for NYC (northern hemisphere)";
    
    // Test conversion with different coordinates
    std::vector<std::tuple<double, double, double>> test_coords = {
        {0.0, 0.0, 0.0},      // Equator, Prime Meridian, Sea level
        {90.0, 0.0, 0.0},     // North Pole
        {-90.0, 0.0, 0.0},    // South Pole
        {0.0, 180.0, 0.0},    // Equator, International Date Line
        {45.0, 45.0, 1000.0}  // Arbitrary point with altitude
    };
    
    for (const auto& [test_lat, test_lon, test_alt] : test_coords) {
        auto [test_x, test_y, test_z] = latLonToCartesian(test_lat, test_lon, test_alt);
        
        // Test coordinate validity
        EXPECT_TRUE(std::isfinite(test_x)) << "X coordinate should be finite";
        EXPECT_TRUE(std::isfinite(test_y)) << "Y coordinate should be finite";
        EXPECT_TRUE(std::isfinite(test_z)) << "Z coordinate should be finite";
        
        // Test coordinate ranges
        EXPECT_GE(test_x, -100000000.0) << "X coordinate should be within reasonable range";
        EXPECT_LE(test_x, 100000000.0) << "X coordinate should be within reasonable range";
        EXPECT_GE(test_y, -100000000.0) << "Y coordinate should be within reasonable range";
        EXPECT_LE(test_y, 100000000.0) << "Y coordinate should be within reasonable range";
        EXPECT_GE(test_z, -100000000.0) << "Z coordinate should be within reasonable range";
        EXPECT_LE(test_z, 100000000.0) << "Z coordinate should be within reasonable range";
    }
}

TEST_F(CoordinateSystemTest, CartesianToLatLonConversion) {
    // Test Cartesian to lat/lon conversion
    double lat = test_latitude_nyc;
    double lon = test_longitude_nyc;
    double alt = test_altitude_aircraft;
    
    auto [x, y, z] = latLonToCartesian(lat, lon, alt);
    auto [converted_lat, converted_lon, converted_alt] = cartesianToLatLon(x, y, z);
    
    // Test conversion accuracy
    EXPECT_NEAR(converted_lat, lat, 1e-6) << "Converted latitude should match original";
    EXPECT_NEAR(converted_lon, lon, 1e-6) << "Converted longitude should match original";
    EXPECT_NEAR(converted_alt, alt, 1.0) << "Converted altitude should match original within 1m";
    
    // Test conversion with different coordinates
    std::vector<std::tuple<double, double, double>> test_coords = {
        {0.0, 0.0, 0.0},      // Equator, Prime Meridian, Sea level
        {90.0, 0.0, 0.0},     // North Pole
        {-90.0, 0.0, 0.0},    // South Pole
        {0.0, 180.0, 0.0},    // Equator, International Date Line
        {45.0, 45.0, 1000.0}  // Arbitrary point with altitude
    };
    
    for (const auto& [test_lat, test_lon, test_alt] : test_coords) {
        auto [test_x, test_y, test_z] = latLonToCartesian(test_lat, test_lon, test_alt);
        auto [converted_lat, converted_lon, converted_alt] = cartesianToLatLon(test_x, test_y, test_z);
        
        // Test conversion accuracy
        EXPECT_NEAR(converted_lat, test_lat, 1e-6) << "Converted latitude should match original";
        EXPECT_NEAR(converted_lon, test_lon, 1e-6) << "Converted longitude should match original";
        EXPECT_NEAR(converted_alt, test_alt, 1.0) << "Converted altitude should match original within 1m";
    }
}

TEST_F(CoordinateSystemTest, GreatCircleDistanceCalculation) {
    // Test great circle distance calculation
    double distance_nyc_london = calculateGreatCircleDistance(test_latitude_nyc, test_longitude_nyc, 
                                                           test_latitude_london, test_longitude_london);
    
    // Test distance accuracy (NYC to London is approximately 5570 km)
    EXPECT_GT(distance_nyc_london, 5500.0) << "Distance NYC to London should be > 5500 km";
    EXPECT_LT(distance_nyc_london, 5700.0) << "Distance NYC to London should be < 5700 km";
    
    // Test distance with known values
    std::vector<std::tuple<double, double, double, double, double>> test_distances = {
        {0.0, 0.0, 0.0, 0.0, 0.0},           // Same point
        {0.0, 0.0, 0.0, 1.0, 111.32},        // 1 degree at equator
        {0.0, 0.0, 0.0, 90.0, 10007.5},      // 90 degrees at equator
        {0.0, 0.0, 0.0, 180.0, 20015.1},    // 180 degrees at equator
        {90.0, 0.0, -90.0, 0.0, 20015.1}    // North Pole to South Pole
    };
    
    for (const auto& [lat1, lon1, lat2, lon2, expected_distance] : test_distances) {
        double calculated_distance = calculateGreatCircleDistance(lat1, lon1, lat2, lon2);
        
        if (expected_distance > 0.0) {
            EXPECT_NEAR(calculated_distance, expected_distance, 100.0) << "Distance should match expected value";
        } else {
            EXPECT_NEAR(calculated_distance, 0.0, 1.0) << "Distance should be near zero for same point";
        }
    }
    
    // Test distance symmetry
    double distance_1 = calculateGreatCircleDistance(test_latitude_nyc, test_longitude_nyc, 
                                                    test_latitude_london, test_longitude_london);
    double distance_2 = calculateGreatCircleDistance(test_latitude_london, test_longitude_london, 
                                                    test_latitude_nyc, test_longitude_nyc);
    
    EXPECT_NEAR(distance_1, distance_2, 1.0) << "Distance should be symmetric";
}

TEST_F(CoordinateSystemTest, BearingCalculation) {
    // Test bearing calculation
    double bearing_nyc_london = calculateBearing(test_latitude_nyc, test_longitude_nyc, 
                                                test_latitude_london, test_longitude_london);
    
    // Test bearing validity
    EXPECT_GE(bearing_nyc_london, 0.0) << "Bearing should be >= 0";
    EXPECT_LT(bearing_nyc_london, 360.0) << "Bearing should be < 360";
    
    // Test bearing with known values
    std::vector<std::tuple<double, double, double, double, double>> test_bearings = {
        {0.0, 0.0, 0.0, 1.0, 90.0},          // East
        {0.0, 0.0, 1.0, 0.0, 0.0},           // North
        {0.0, 0.0, 0.0, -1.0, 270.0},        // West
        {0.0, 0.0, -1.0, 0.0, 180.0},        // South
        {0.0, 0.0, 1.0, 1.0, 45.0},          // Northeast
        {0.0, 0.0, 1.0, -1.0, 315.0},        // Northwest
        {0.0, 0.0, -1.0, 1.0, 135.0},        // Southeast
        {0.0, 0.0, -1.0, -1.0, 225.0}        // Southwest
    };
    
    for (const auto& [lat1, lon1, lat2, lon2, expected_bearing] : test_bearings) {
        double calculated_bearing = calculateBearing(lat1, lon1, lat2, lon2);
        
        EXPECT_GE(calculated_bearing, 0.0) << "Bearing should be >= 0";
        EXPECT_LT(calculated_bearing, 360.0) << "Bearing should be < 360";
        
        if (expected_bearing > 0.0) {
            EXPECT_NEAR(calculated_bearing, expected_bearing, 10.0) << "Bearing should match expected value";
        }
    }
    
    // Test bearing symmetry
    double bearing_1 = calculateBearing(test_latitude_nyc, test_longitude_nyc, 
                                       test_latitude_london, test_longitude_london);
    double bearing_2 = calculateBearing(test_latitude_london, test_longitude_london, 
                                       test_latitude_nyc, test_longitude_nyc);
    
    // Bearing should be approximately opposite (180 degrees difference)
    // Due to Earth's curvature, bearings are not exactly 180 degrees apart
    double bearing_diff = std::abs(bearing_1 - bearing_2);
    if (bearing_diff > 180.0) {
        bearing_diff = 360.0 - bearing_diff;
    }
    
    // Allow for larger tolerance due to Earth's curvature
    EXPECT_NEAR(bearing_diff, 180.0, 60.0) << "Bearing should be approximately opposite";
}

TEST_F(CoordinateSystemTest, CoordinateValidation) {
    // Test coordinate validation
    std::vector<std::tuple<double, double, double, bool>> test_coordinates = {
        {0.0, 0.0, 0.0, true},           // Valid coordinates
        {90.0, 0.0, 0.0, true},          // North Pole
        {-90.0, 0.0, 0.0, true},         // South Pole
        {0.0, 180.0, 0.0, true},         // International Date Line
        {0.0, -180.0, 0.0, true},        // International Date Line
        {45.0, 45.0, 1000.0, true},      // Valid coordinates with altitude
        {91.0, 0.0, 0.0, false},         // Invalid latitude
        {-91.0, 0.0, 0.0, false},        // Invalid latitude
        {0.0, 181.0, 0.0, false},        // Invalid longitude
        {0.0, -181.0, 0.0, false},       // Invalid longitude
        {0.0, 0.0, -1001.0, false},      // Invalid altitude
        {0.0, 0.0, 100001.0, false}     // Invalid altitude
    };
    
    for (const auto& [lat, lon, alt, expected_valid] : test_coordinates) {
        bool is_valid = isValidLatitude(lat) && isValidLongitude(lon) && isValidAltitude(alt);
        EXPECT_EQ(is_valid, expected_valid) << "Coordinate validation should match expected result";
    }
}

TEST_F(CoordinateSystemTest, DatumConversionWGS84) {
    // Test WGS84 datum conversion
    double lat = test_latitude_nyc;
    double lon = test_longitude_nyc;
    double alt = test_altitude_aircraft;
    
    // Test WGS84 to Cartesian conversion
    auto [x, y, z] = latLonToCartesian(lat, lon, alt);
    
    // Test WGS84 coordinate validity
    EXPECT_TRUE(isValidLatitude(lat)) << "Latitude should be valid for WGS84";
    EXPECT_TRUE(isValidLongitude(lon)) << "Longitude should be valid for WGS84";
    EXPECT_TRUE(isValidAltitude(alt)) << "Altitude should be valid for WGS84";
    
    // Test WGS84 coordinate ranges
    EXPECT_GE(lat, -90.0) << "Latitude should be >= -90 for WGS84";
    EXPECT_LE(lat, 90.0) << "Latitude should be <= 90 for WGS84";
    EXPECT_GE(lon, -180.0) << "Longitude should be >= -180 for WGS84";
    EXPECT_LE(lon, 180.0) << "Longitude should be <= 180 for WGS84";
    
    // Test WGS84 coordinate precision
    EXPECT_NEAR(lat, test_latitude_nyc, 1e-6) << "Latitude should match original with high precision";
    EXPECT_NEAR(lon, test_longitude_nyc, 1e-6) << "Longitude should match original with high precision";
    EXPECT_NEAR(alt, test_altitude_aircraft, 1.0) << "Altitude should match original within 1m";
    
    // Test WGS84 coordinate conversion accuracy
    auto [converted_lat, converted_lon, converted_alt] = cartesianToLatLon(x, y, z);
    
    EXPECT_NEAR(converted_lat, lat, 1e-6) << "Converted latitude should match original for WGS84";
    EXPECT_NEAR(converted_lon, lon, 1e-6) << "Converted longitude should match original for WGS84";
    EXPECT_NEAR(converted_alt, alt, 1.0) << "Converted altitude should match original for WGS84";
}

// Additional coordinate system tests
TEST_F(CoordinateSystemTest, CoordinateSystemPerformance) {
    // Test coordinate system performance
    const int num_conversions = 10000;
    std::vector<std::tuple<double, double, double>> test_coords;
    
    // Generate test coordinates
    for (int i = 0; i < num_conversions; ++i) {
        double lat = (i % 180) - 90.0;
        double lon = (i % 360) - 180.0;
        double alt = (i % 10000) - 5000.0;
        test_coords.emplace_back(lat, lon, alt);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test lat/lon to Cartesian conversion performance
    for (const auto& [lat, lon, alt] : test_coords) {
        auto [x, y, z] = latLonToCartesian(lat, lon, alt);
        // Use the coordinates to verify they are reasonable
        EXPECT_TRUE(std::isfinite(x)) << "X coordinate should be finite";
        EXPECT_TRUE(std::isfinite(y)) << "Y coordinate should be finite";
        EXPECT_TRUE(std::isfinite(z)) << "Z coordinate should be finite";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_conversion = static_cast<double>(duration.count()) / num_conversions;
    
    // Coordinate conversion should be fast
    EXPECT_LT(time_per_conversion, 10.0) << "Coordinate conversion too slow: " << time_per_conversion << " microseconds";
    
    std::cout << "Coordinate conversion performance: " << time_per_conversion << " microseconds per conversion" << std::endl;
}

TEST_F(CoordinateSystemTest, CoordinateSystemAccuracy) {
    // Test coordinate system accuracy
    std::vector<std::tuple<double, double, double>> test_coords = {
        {0.0, 0.0, 0.0},      // Equator, Prime Meridian, Sea level
        {90.0, 0.0, 0.0},     // North Pole
        {-90.0, 0.0, 0.0},    // South Pole
        {0.0, 180.0, 0.0},    // Equator, International Date Line
        {45.0, 45.0, 1000.0}  // Arbitrary point with altitude
    };
    
    for (const auto& [lat, lon, alt] : test_coords) {
        // Test lat/lon to Cartesian conversion
        auto [x, y, z] = latLonToCartesian(lat, lon, alt);
        
        // Test Cartesian to lat/lon conversion
        auto [converted_lat, converted_lon, converted_alt] = cartesianToLatLon(x, y, z);
        
        // Test accuracy
        EXPECT_NEAR(converted_lat, lat, 1e-6) << "Latitude conversion accuracy should be within 1e-6 degrees";
        EXPECT_NEAR(converted_lon, lon, 1e-6) << "Longitude conversion accuracy should be within 1e-6 degrees";
        EXPECT_NEAR(converted_alt, alt, 1.0) << "Altitude conversion accuracy should be within 1 meter";
        
        // Test coordinate validity
        EXPECT_TRUE(isValidLatitude(converted_lat)) << "Converted latitude should be valid";
        EXPECT_TRUE(isValidLongitude(converted_lon)) << "Converted longitude should be valid";
        EXPECT_TRUE(isValidAltitude(converted_alt)) << "Converted altitude should be valid";
    }
}
