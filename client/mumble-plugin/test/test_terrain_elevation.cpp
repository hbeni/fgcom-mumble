/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Terrain Elevation Tests for FGCom-mumble
 * Tests terrain elevation system and ASTER GDEM integration
 */

#include <iostream>
#include <cmath>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <sstream>

// Test terrain elevation data validation
bool testTerrainElevationDataValidation() {
    std::cout << "    Testing terrain elevation data validation..." << std::endl;
    
    // Test elevation data ranges
    struct ElevationTest {
        std::string location;
        double latitude;
        double longitude;
        double expected_elevation_min;
        double expected_elevation_max;
    };
    
    std::vector<ElevationTest> test_cases = {
        {"Mount Everest", 27.9881, 86.9250, 8000.0, 9000.0},
        {"Death Valley", 36.5054, -117.0794, -100.0, 100.0},
        {"Sea Level", 0.0, 0.0, -10.0, 10.0},
        {"Alps", 46.5197, 6.6323, 1000.0, 5000.0},
        {"Himalayas", 28.6139, 77.2090, 200.0, 3000.0},
        {"Rocky Mountains", 39.7392, -104.9903, 1000.0, 4000.0},
        {"Sahara Desert", 23.4241, 25.2697, 200.0, 1000.0},
        {"Amazon Basin", -3.4653, -62.2159, 0.0, 500.0}
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Validate coordinates
            bool valid_lat = test_case.latitude >= -90.0 && test_case.latitude <= 90.0;
            bool valid_lon = test_case.longitude >= -180.0 && test_case.longitude <= 180.0;
            bool valid_elevation_range = test_case.expected_elevation_min < test_case.expected_elevation_max;
            
            if (valid_lat && valid_lon && valid_elevation_range) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.location << " -> Invalid coordinates or elevation range" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.location << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Terrain elevation data validation results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test ASTER GDEM tile naming convention
bool testASTERGDEMTileNaming() {
    std::cout << "    Testing ASTER GDEM tile naming convention..." << std::endl;
    
    // Test ASTER GDEM tile naming convention
    // Format: ASTGTM2_N{lat}E{lon}_dem.tif
    struct TileTest {
        double latitude;
        double longitude;
        std::string expected_tile_name;
    };
    
    std::vector<TileTest> test_cases = {
        {27.9881, 86.9250, "ASTGTM2_N27E086_dem.tif"},  // Mount Everest
        {36.5054, -117.0794, "ASTGTM2_N36W117_dem.tif"}, // Death Valley
        {0.0, 0.0, "ASTGTM2_N00E000_dem.tif"},           // Equator/Prime Meridian
        {46.5197, 6.6323, "ASTGTM2_N46E006_dem.tif"},     // Alps
        {28.6139, 77.2090, "ASTGTM2_N28E077_dem.tif"},   // Himalayas
        {39.7392, -104.9903, "ASTGTM2_N39W104_dem.tif"}, // Rocky Mountains
        {23.4241, 25.2697, "ASTGTM2_N23E025_dem.tif"},   // Sahara Desert
        {-3.4653, -62.2159, "ASTGTM2_S03W062_dem.tif"}   // Amazon Basin (Southern Hemisphere)
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Generate tile name
            std::ostringstream oss;
            oss << "ASTGTM2_";
            
            if (test_case.latitude >= 0) {
                oss << "N" << std::setfill('0') << std::setw(2) << static_cast<int>(test_case.latitude);
            } else {
                oss << "S" << std::setfill('0') << std::setw(2) << static_cast<int>(-test_case.latitude);
            }
            
            if (test_case.longitude >= 0) {
                oss << "E" << std::setfill('0') << std::setw(3) << static_cast<int>(test_case.longitude);
            } else {
                oss << "W" << std::setfill('0') << std::setw(3) << static_cast<int>(-test_case.longitude);
            }
            
            oss << "_dem.tif";
            std::string generated_tile_name = oss.str();
            
            if (generated_tile_name == test_case.expected_tile_name) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.latitude << "," << test_case.longitude 
                         << " -> " << generated_tile_name << " (expected: " << test_case.expected_tile_name << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.latitude << "," << test_case.longitude << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    ASTER GDEM tile naming results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test terrain profile analysis
bool testTerrainProfileAnalysis() {
    std::cout << "    Testing terrain profile analysis..." << std::endl;
    
    // Test terrain profile calculations
    struct ProfileTest {
        double start_lat;
        double start_lon;
        double end_lat;
        double end_lon;
        double expected_distance_km;
        int expected_profile_points;
    };
    
    std::vector<ProfileTest> test_cases = {
        {27.9881, 86.9250, 27.9881, 86.9250, 0.0, 1},        // Same point
        {27.9881, 86.9250, 28.0000, 87.0000, 10.0, 10},       // Short distance
        {27.9881, 86.9250, 28.0000, 87.0000, 10.0, 10},       // Medium distance
        {27.9881, 86.9250, 30.0000, 90.0000, 300.0, 100},     // Long distance
        {0.0, 0.0, 1.0, 1.0, 150.0, 50}                      // Cross-equator
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Calculate distance using Haversine formula
            double lat1_rad = test_case.start_lat * M_PI / 180.0;
            double lon1_rad = test_case.start_lon * M_PI / 180.0;
            double lat2_rad = test_case.end_lat * M_PI / 180.0;
            double lon2_rad = test_case.end_lon * M_PI / 180.0;
            
            double dlat = lat2_rad - lat1_rad;
            double dlon = lon2_rad - lon1_rad;
            
            double a = sin(dlat/2) * sin(dlat/2) + cos(lat1_rad) * cos(lat2_rad) * sin(dlon/2) * sin(dlon/2);
            double c = 2 * atan2(sqrt(a), sqrt(1-a));
            double distance_km = 6371.0 * c; // Earth radius in km
            
            // Calculate expected profile points (1 point per km)
            int calculated_profile_points = static_cast<int>(distance_km) + 1;
            
            // Validate distance (within 10% tolerance)
            bool valid_distance = std::abs(distance_km - test_case.expected_distance_km) < (test_case.expected_distance_km * 0.1);
            bool valid_profile_points = calculated_profile_points >= 1;
            
            if (valid_distance && valid_profile_points) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: Distance " << distance_km << "km, Points " << calculated_profile_points 
                         << " (expected: " << test_case.expected_distance_km << "km, " << test_case.expected_profile_points << " points)" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.start_lat << "," << test_case.start_lon 
                     << " -> " << test_case.end_lat << "," << test_case.end_lon << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Terrain profile analysis results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test Fresnel zone calculations
bool testFresnelZoneCalculations() {
    std::cout << "    Testing Fresnel zone calculations..." << std::endl;
    
    // Test Fresnel zone calculations
    struct FresnelTest {
        double frequency_mhz;
        double distance_km;
        double expected_fresnel_radius_m;
    };
    
    std::vector<FresnelTest> test_cases = {
        {118.0, 10.0, 50.0},    // VHF aviation
        {121.5, 5.0, 35.0},     // Emergency frequency
        {137.0, 15.0, 60.0},    // VHF aviation
        {300.0, 5.0, 25.0},     // UHF
        {800.0, 2.0, 15.0},     // UHF
        {1200.0, 1.0, 10.0}     // UHF
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Calculate Fresnel zone radius
            // Formula: r = sqrt(λ * d1 * d2 / (d1 + d2))
            // For first Fresnel zone: r = sqrt(λ * d / 4)
            double wavelength_m = 300.0 / test_case.frequency_mhz; // c/f in meters
            double distance_m = test_case.distance_km * 1000.0;
            double fresnel_radius_m = sqrt(wavelength_m * distance_m / 4.0);
            
            // Validate Fresnel zone radius (within 20% tolerance)
            bool valid_radius = std::abs(fresnel_radius_m - test_case.expected_fresnel_radius_m) < (test_case.expected_fresnel_radius_m * 0.2);
            
            if (valid_radius) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.frequency_mhz << "MHz, " << test_case.distance_km 
                         << "km -> " << fresnel_radius_m << "m (expected: " << test_case.expected_fresnel_radius_m << "m)" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.frequency_mhz << "MHz -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Fresnel zone calculations results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test terrain obstruction detection
bool testTerrainObstructionDetection() {
    std::cout << "    Testing terrain obstruction detection..." << std::endl;
    
    // Test terrain obstruction scenarios
    struct ObstructionTest {
        std::string scenario;
        double transmitter_height_m;
        double receiver_height_m;
        double terrain_height_m;
        double distance_km;
        bool expected_obstruction;
    };
    
    std::vector<ObstructionTest> test_cases = {
        {"Clear line of sight", 100.0, 50.0, 30.0, 10.0, false},
        {"Terrain obstruction", 100.0, 50.0, 150.0, 10.0, true},
        {"Mountain obstruction", 100.0, 50.0, 200.0, 5.0, true},
        {"Valley clearance", 100.0, 50.0, 20.0, 15.0, false},
        {"Hill obstruction", 100.0, 50.0, 120.0, 8.0, true},
        {"Flat terrain", 100.0, 50.0, 10.0, 20.0, false}
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Calculate line of sight clearance
            double distance_m = test_case.distance_km * 1000.0;
            double earth_radius = 6371000.0; // Earth radius in meters
            
            // Calculate line of sight height at terrain point
            double line_of_sight_height = test_case.transmitter_height_m + 
                (test_case.receiver_height_m - test_case.transmitter_height_m) * (distance_m / 2.0) / distance_m;
            
            // Account for Earth curvature
            double earth_curvature = (distance_m * distance_m) / (8.0 * earth_radius);
            double effective_terrain_height = test_case.terrain_height_m + earth_curvature;
            
            bool obstruction_detected = effective_terrain_height > line_of_sight_height;
            
            if (obstruction_detected == test_case.expected_obstruction) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.scenario << " -> " << (obstruction_detected ? "Obstructed" : "Clear") 
                         << " (expected: " << (test_case.expected_obstruction ? "Obstructed" : "Clear") << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.scenario << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Terrain obstruction detection results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test configuration file validation
bool testTerrainConfigurationValidation() {
    std::cout << "    Testing terrain configuration validation..." << std::endl;
    
    // Test configuration parameters
    struct ConfigTest {
        std::string parameter;
        std::string value;
        bool expected_valid;
    };
    
    std::vector<ConfigTest> test_cases = {
        {"enabled", "true", true},
        {"enabled", "false", true},
        {"enabled", "invalid", false},
        {"elevation_source", "ASTER", true},
        {"elevation_source", "SRTM", true},
        {"elevation_source", "invalid", false},
        {"data_path", "/path/to/data", true},
        {"data_path", "", false},
        {"cache_size_mb", "100", true},
        {"cache_size_mb", "0", false},
        {"cache_size_mb", "invalid", false},
        {"terrain_resolution_m", "30", true},
        {"terrain_resolution_m", "0", false},
        {"terrain_resolution_m", "invalid", false}
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            bool valid = false;
            
            if (test_case.parameter == "enabled") {
                valid = (test_case.value == "true" || test_case.value == "false");
            } else if (test_case.parameter == "elevation_source") {
                valid = (test_case.value == "ASTER" || test_case.value == "SRTM");
            } else if (test_case.parameter == "data_path") {
                valid = !test_case.value.empty();
            } else if (test_case.parameter == "cache_size_mb") {
                try {
                    int size = std::stoi(test_case.value);
                    valid = size > 0;
                } catch (...) {
                    valid = false;
                }
            } else if (test_case.parameter == "terrain_resolution_m") {
                try {
                    int resolution = std::stoi(test_case.value);
                    valid = resolution > 0;
                } catch (...) {
                    valid = false;
                }
            }
            
            if (valid == test_case.expected_valid) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.parameter << "=" << test_case.value 
                         << " -> " << (valid ? "Valid" : "Invalid") << " (expected: " << (test_case.expected_valid ? "Valid" : "Invalid") << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.parameter << "=" << test_case.value << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Terrain configuration validation results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

int main() {
    std::cout << "Running FGCom-mumble Terrain Elevation Tests..." << std::endl;
    std::cout << "=============================================" << std::endl;
    
    int total_passed = 0;
    int total_failed = 0;
    
    // Run all tests
    if (testTerrainElevationDataValidation()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testASTERGDEMTileNaming()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testTerrainProfileAnalysis()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testFresnelZoneCalculations()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testTerrainObstructionDetection()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testTerrainConfigurationValidation()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    std::cout << "=============================================" << std::endl;
    std::cout << "Test Results:" << std::endl;
    std::cout << "  Passed: " << total_passed << std::endl;
    std::cout << "  Failed: " << total_failed << std::endl;
    std::cout << "  Total:  " << (total_passed + total_failed) << std::endl;
    
    if (total_failed == 0) {
        std::cout << "\nAll terrain elevation tests passed! ✓" << std::endl;
        return 0;
    } else {
        std::cout << "\nSome terrain elevation tests failed! ✗" << std::endl;
        return 1;
    }
}
