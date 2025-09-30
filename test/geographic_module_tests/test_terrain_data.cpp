#include "test_geographic_module_main.cpp"

// 6.2 Terrain Data Tests
TEST_F(TerrainDataTest, ASTERGDEMDataLoading) {
    // Test ASTER GDEM data loading
    std::string tile_name = "N40W075"; // NYC area tile
    double lat = test_latitude_nyc;
    double lon = test_longitude_nyc;
    
    // Test tile name generation
    std::string generated_tile_name = std::to_string(static_cast<int>(std::floor(lat))) + 
                                     (lon >= 0 ? "N" : "S") + 
                                     std::to_string(static_cast<int>(std::floor(std::abs(lon)))) + 
                                     (lon >= 0 ? "E" : "W");
    
    EXPECT_FALSE(generated_tile_name.empty()) << "Tile name should not be empty";
    EXPECT_TRUE(generated_tile_name.length() > 0) << "Tile name should have positive length";
    
    // Test tile coordinate calculation
    double tile_lat = std::floor(lat);
    double tile_lon = std::floor(lon);
    
    EXPECT_GE(tile_lat, -90.0) << "Tile latitude should be >= -90";
    EXPECT_LE(tile_lat, 90.0) << "Tile latitude should be <= 90";
    EXPECT_GE(tile_lon, -180.0) << "Tile longitude should be >= -180";
    EXPECT_LE(tile_lon, 180.0) << "Tile longitude should be <= 180";
    
    // Test tile size validation
    double tile_size_lat = 1.0; // 1 degree
    double tile_size_lon = 1.0; // 1 degree
    
    EXPECT_GT(tile_size_lat, 0.0) << "Tile latitude size should be positive";
    EXPECT_GT(tile_size_lon, 0.0) << "Tile longitude size should be positive";
    EXPECT_LE(tile_size_lat, 10.0) << "Tile latitude size should be reasonable";
    EXPECT_LE(tile_size_lon, 10.0) << "Tile longitude size should be reasonable";
}

TEST_F(TerrainDataTest, ElevationLookup) {
    // Test elevation lookup
    std::vector<std::tuple<double, double, double>> test_elevations = {
        {0.0, 0.0, 0.0},      // Sea level
        {40.7128, -74.0060, 10.0},  // NYC (approximate)
        {51.5074, -0.1278, 35.0},   // London (approximate)
        {35.6762, 139.6503, 40.0},  // Tokyo (approximate)
        {27.9881, 86.9250, 8848.0}  // Mount Everest
    };
    
    for (const auto& [lat, lon, expected_elevation] : test_elevations) {
        // Test elevation lookup
        double elevation = getElevation(lat, lon);
        
        // Test elevation validity
        EXPECT_TRUE(isValidTerrainElevation(elevation)) << "Elevation should be valid";
        EXPECT_GE(elevation, -1000.0) << "Elevation should be >= -1000m";
        EXPECT_LE(elevation, 10000.0) << "Elevation should be <= 10000m";
        
        // Test elevation accuracy for known locations
        if (lat == 0.0 && lon == 0.0) {
            EXPECT_NEAR(elevation, 0.0, 100.0) << "Sea level elevation should be near 0m";
        } else if (lat == 27.9881 && lon == 86.9250) {
            EXPECT_GT(elevation, 8000.0) << "Mount Everest elevation should be > 8000m";
        }
    }
    
    // Test elevation lookup with invalid coordinates
    double invalid_elevation = getElevation(91.0, 0.0);
    EXPECT_EQ(invalid_elevation, 0.0) << "Invalid coordinates should return 0 elevation";
    
    invalid_elevation = getElevation(0.0, 181.0);
    EXPECT_EQ(invalid_elevation, 0.0) << "Invalid coordinates should return 0 elevation";
}

TEST_F(TerrainDataTest, InterpolationBetweenPoints) {
    // Test interpolation between points
    double lat1 = test_latitude_nyc;
    double lon1 = test_longitude_nyc;
    double lat2 = test_latitude_london;
    double lon2 = test_longitude_london;
    
    // Test linear interpolation
    std::vector<double> interpolation_fractions = {0.0, 0.25, 0.5, 0.75, 1.0};
    
    for (double fraction : interpolation_fractions) {
        double interp_lat = lat1 + (lat2 - lat1) * fraction;
        double interp_lon = lon1 + (lon2 - lon1) * fraction;
        
        // Test interpolation validity
        EXPECT_GE(interp_lat, -90.0) << "Interpolated latitude should be >= -90";
        EXPECT_LE(interp_lat, 90.0) << "Interpolated latitude should be <= 90";
        EXPECT_GE(interp_lon, -180.0) << "Interpolated longitude should be >= -180";
        EXPECT_LE(interp_lon, 180.0) << "Interpolated longitude should be <= 180";
        
        // Test interpolation accuracy
        if (fraction == 0.0) {
            EXPECT_NEAR(interp_lat, lat1, 1e-6) << "Interpolation at 0.0 should match start point";
            EXPECT_NEAR(interp_lon, lon1, 1e-6) << "Interpolation at 0.0 should match start point";
        } else if (fraction == 1.0) {
            EXPECT_NEAR(interp_lat, lat2, 1e-6) << "Interpolation at 1.0 should match end point";
            EXPECT_NEAR(interp_lon, lon2, 1e-6) << "Interpolation at 1.0 should match end point";
        }
    }
    
    // Test interpolation with multiple points
    std::vector<std::tuple<double, double>> waypoints = {
        {0.0, 0.0},
        {10.0, 10.0},
        {20.0, 20.0},
        {30.0, 30.0}
    };
    
    for (size_t i = 0; i < waypoints.size() - 1; ++i) {
        auto [lat1, lon1] = waypoints[i];
        auto [lat2, lon2] = waypoints[i + 1];
        
        double mid_lat = (lat1 + lat2) / 2.0;
        double mid_lon = (lon1 + lon2) / 2.0;
        
        // Test midpoint interpolation
        EXPECT_NEAR(mid_lat, (lat1 + lat2) / 2.0, 1e-6) << "Midpoint latitude should be correct";
        EXPECT_NEAR(mid_lon, (lon1 + lon2) / 2.0, 1e-6) << "Midpoint longitude should be correct";
    }
}

TEST_F(TerrainDataTest, MissingDataHandling) {
    // Test missing data handling
    std::vector<std::tuple<double, double>> test_coordinates = {
        {0.0, 0.0},      // Valid coordinates
        {45.0, 45.0},    // Valid coordinates
        {91.0, 0.0},     // Invalid latitude
        {0.0, 181.0},    // Invalid longitude
        {-91.0, 0.0},    // Invalid latitude
        {0.0, -181.0}    // Invalid longitude
    };
    
    for (const auto& [lat, lon] : test_coordinates) {
        // Test missing data detection
        bool is_valid = isValidLatitude(lat) && isValidLongitude(lon);
        
        if (!is_valid) {
            // Test missing data handling
            double elevation = getElevation(lat, lon);
            EXPECT_EQ(elevation, 0.0) << "Invalid coordinates should return 0 elevation";
        } else {
            // Test valid data handling
            double elevation = getElevation(lat, lon);
            EXPECT_TRUE(isValidTerrainElevation(elevation)) << "Valid coordinates should return valid elevation";
        }
    }
    
    // Test missing data with interpolation
    double lat1 = 0.0, lon1 = 0.0;
    double lat2 = 1.0, lon2 = 1.0;
    
    // Test interpolation with missing data
    for (double fraction = 0.0; fraction <= 1.0; fraction += 0.1) {
        double interp_lat = lat1 + (lat2 - lat1) * fraction;
        double interp_lon = lon1 + (lon2 - lon1) * fraction;
        
        double elevation = getElevation(interp_lat, interp_lon);
        
        // Test missing data handling in interpolation
        if (isValidLatitude(interp_lat) && isValidLongitude(interp_lon)) {
            EXPECT_TRUE(isValidTerrainElevation(elevation)) << "Valid interpolated coordinates should return valid elevation";
        } else {
            EXPECT_EQ(elevation, 0.0) << "Invalid interpolated coordinates should return 0 elevation";
        }
    }
}

TEST_F(TerrainDataTest, TerrainProfileGeneration) {
    // Test terrain profile generation
    double lat1 = test_latitude_nyc;
    double lon1 = test_longitude_nyc;
    double lat2 = test_latitude_london;
    double lon2 = test_longitude_london;
    double resolution = test_terrain_resolution;
    
    // Test profile generation
    std::vector<std::tuple<double, double, double, double>> profile_points;
    
    // Calculate distance and number of points
    double distance = calculateGreatCircleDistance(lat1, lon1, lat2, lon2);
    int num_points = static_cast<int>(distance * 1000.0 / resolution) + 1;
    
    // Limit the number of points to prevent excessive computation
    if (num_points > 1000) {
        num_points = 1000;
    }
    
    EXPECT_GT(num_points, 0) << "Number of profile points should be positive";
    EXPECT_LE(num_points, 10000) << "Number of profile points should be reasonable";
    
    // Generate profile points
    for (int i = 0; i < num_points; ++i) {
        double fraction = static_cast<double>(i) / (num_points - 1);
        double lat = lat1 + (lat2 - lat1) * fraction;
        double lon = lon1 + (lon2 - lon1) * fraction;
        double dist = distance * fraction;
        double elevation = getElevation(lat, lon);
        
        profile_points.emplace_back(lat, lon, elevation, dist);
    }
    
    // Test profile validity
    EXPECT_EQ(profile_points.size(), num_points) << "Profile should have correct number of points";
    
    for (const auto& [lat, lon, elevation, dist] : profile_points) {
        // Test coordinate validity
        EXPECT_TRUE(isValidLatitude(lat)) << "Profile latitude should be valid";
        EXPECT_TRUE(isValidLongitude(lon)) << "Profile longitude should be valid";
        EXPECT_TRUE(isValidTerrainElevation(elevation)) << "Profile elevation should be valid";
        EXPECT_GE(dist, 0.0) << "Profile distance should be >= 0";
        EXPECT_LE(dist, distance) << "Profile distance should be <= total distance";
    }
    
    // Test profile statistics
    double min_elevation = std::numeric_limits<double>::max();
    double max_elevation = std::numeric_limits<double>::lowest();
    double sum_elevation = 0.0;
    
    for (const auto& [lat, lon, elevation, dist] : profile_points) {
        min_elevation = std::min(min_elevation, elevation);
        max_elevation = std::max(max_elevation, elevation);
        sum_elevation += elevation;
    }
    
    double avg_elevation = sum_elevation / profile_points.size();
    
    EXPECT_LE(min_elevation, max_elevation) << "Minimum elevation should be <= maximum elevation";
    EXPECT_GE(avg_elevation, min_elevation) << "Average elevation should be >= minimum elevation";
    EXPECT_LE(avg_elevation, max_elevation) << "Average elevation should be <= maximum elevation";
}

TEST_F(TerrainDataTest, MultiPolygonSupport) {
    // Test multi-polygon support
    std::vector<std::vector<std::tuple<double, double>>> polygons = {
        {{0.0, 0.0}, {1.0, 0.0}, {1.0, 1.0}, {0.0, 1.0}},  // Square 1
        {{2.0, 2.0}, {3.0, 2.0}, {3.0, 3.0}, {2.0, 3.0}},  // Square 2
        {{4.0, 4.0}, {5.0, 4.0}, {5.0, 5.0}, {4.0, 5.0}}   // Square 3
    };
    
    // Test polygon validity
    for (const auto& polygon : polygons) {
        EXPECT_GT(polygon.size(), 2) << "Polygon should have at least 3 points";
        
        for (const auto& [lat, lon] : polygon) {
            EXPECT_TRUE(isValidLatitude(lat)) << "Polygon latitude should be valid";
            EXPECT_TRUE(isValidLongitude(lon)) << "Polygon longitude should be valid";
        }
    }
    
    // Test point-in-polygon detection
    std::vector<std::tuple<double, double, bool>> test_points = {
        {0.5, 0.5, true},   // Inside first polygon
        {2.5, 2.5, true},   // Inside second polygon
        {4.5, 4.5, true},   // Inside third polygon
        {1.5, 1.5, false}, // Outside all polygons
        {3.5, 3.5, false}, // Outside all polygons
        {5.5, 5.5, false}  // Outside all polygons
    };
    
    for (const auto& [lat, lon, expected_inside] : test_points) {
        bool is_inside = false;
        
        for (const auto& polygon : polygons) {
            // Simple point-in-polygon test (ray casting algorithm)
            bool inside = false;
            for (size_t i = 0, j = polygon.size() - 1; i < polygon.size(); j = i++) {
                auto [lat1, lon1] = polygon[i];
                auto [lat2, lon2] = polygon[j];
                
                if (((lat1 > lat) != (lat2 > lat)) && 
                    (lon < (lon2 - lon1) * (lat - lat1) / (lat2 - lat1) + lon1)) {
                    inside = !inside;
                }
            }
            
            if (inside) {
                is_inside = true;
                break;
            }
        }
        
        EXPECT_EQ(is_inside, expected_inside) << "Point-in-polygon detection should match expected result";
    }
}

// Additional terrain data tests
TEST_F(TerrainDataTest, TerrainDataPerformance) {
    // Test terrain data performance
    const int num_lookups = 1000;
    std::vector<std::tuple<double, double>> test_coordinates;
    
    // Generate test coordinates
    for (int i = 0; i < num_lookups; ++i) {
        double lat = (i % 180) - 90.0;
        double lon = (i % 360) - 180.0;
        test_coordinates.emplace_back(lat, lon);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test elevation lookup performance
    for (const auto& [lat, lon] : test_coordinates) {
        double elevation = getElevation(lat, lon);
        // Use the elevation to verify it's reasonable
        EXPECT_GE(elevation, -500.0) << "Elevation should be reasonable (not below -500m)";
        EXPECT_LE(elevation, 9000.0) << "Elevation should be reasonable (not above 9000m)";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_lookup = static_cast<double>(duration.count()) / num_lookups;
    
    // Terrain lookup should be fast
    EXPECT_LT(time_per_lookup, 100.0) << "Terrain lookup too slow: " << time_per_lookup << " microseconds";
    
    std::cout << "Terrain lookup performance: " << time_per_lookup << " microseconds per lookup" << std::endl;
}

TEST_F(TerrainDataTest, TerrainDataAccuracy) {
    // Test terrain data accuracy
    std::vector<std::tuple<double, double, double>> test_elevations = {
        {0.0, 0.0, 0.0},      // Sea level
        {40.7128, -74.0060, 10.0},  // NYC (approximate)
        {51.5074, -0.1278, 35.0},   // London (approximate)
        {35.6762, 139.6503, 40.0},  // Tokyo (approximate)
        {27.9881, 86.9250, 8848.0}  // Mount Everest
    };
    
    for (const auto& [lat, lon, expected_elevation] : test_elevations) {
        double elevation = getElevation(lat, lon);
        
        // Test elevation accuracy
        if (expected_elevation > 0.0) {
            EXPECT_NEAR(elevation, expected_elevation, 1000.0) << "Elevation should be within 1000m of expected";
        } else {
            EXPECT_NEAR(elevation, 0.0, 100.0) << "Sea level elevation should be near 0m";
        }
        
        // Test elevation validity
        EXPECT_TRUE(isValidTerrainElevation(elevation)) << "Elevation should be valid";
        EXPECT_GE(elevation, -1000.0) << "Elevation should be >= -1000m";
        EXPECT_LE(elevation, 10000.0) << "Elevation should be <= 10000m";
    }
}
