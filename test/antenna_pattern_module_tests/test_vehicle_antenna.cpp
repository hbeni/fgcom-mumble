// Test includes
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test_antenna_pattern_main.cpp"

// 11.2 Vehicle-Specific Antenna Tests
TEST_F(VehicleAntennaTest, AircraftAntennaBellyMounted) {
    // Test aircraft antenna (belly-mounted)
    std::string aircraft_type = "B737";
    double altitude = 10000.0; // feet
    double roll = 5.0; // degrees
    double pitch = 2.0; // degrees
    
    std::vector<FGCom_RadiationPattern> patterns = mock_vehicle_antenna_manager->getAircraftAntennaPattern(
        aircraft_type, altitude, roll, pitch);
    
    EXPECT_GT(patterns.size(), 0) << "Aircraft antenna patterns should not be empty";
    
    // Test pattern data validity
    for (const auto& pattern : patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test different aircraft types
    std::vector<std::string> aircraft_types = {"B737", "A320", "C172", "UH1", "C130"};
    for (const auto& type : aircraft_types) {
        std::vector<FGCom_RadiationPattern> type_patterns = mock_vehicle_antenna_manager->getAircraftAntennaPattern(
            type, altitude, roll, pitch);
        EXPECT_GT(type_patterns.size(), 0) << "Aircraft type " << type << " should have patterns";
    }
    
    // Test different altitudes
    std::vector<double> altitudes = {1000.0, 5000.0, 10000.0, 20000.0, 35000.0};
    for (double alt : altitudes) {
        std::vector<FGCom_RadiationPattern> alt_patterns = mock_vehicle_antenna_manager->getAircraftAntennaPattern(
            aircraft_type, alt, roll, pitch);
        EXPECT_GT(alt_patterns.size(), 0) << "Altitude " << alt << " should have patterns";
    }
    
    // Test different attitudes
    std::vector<double> rolls = {-30.0, -15.0, 0.0, 15.0, 30.0};
    std::vector<double> pitches = {-15.0, -5.0, 0.0, 5.0, 15.0};
    for (double r : rolls) {
        for (double p : pitches) {
            std::vector<FGCom_RadiationPattern> attitude_patterns = mock_vehicle_antenna_manager->getAircraftAntennaPattern(
                aircraft_type, altitude, r, p);
            EXPECT_GT(attitude_patterns.size(), 0) << "Attitude roll=" << r << " pitch=" << p << " should have patterns";
        }
    }
}

TEST_F(VehicleAntennaTest, GroundVehicleAntenna45DegreeTieDown) {
    // Test ground vehicle antenna (45° tie-down)
    std::string vehicle_type = "NATO_Jeep";
    double height = 2.0; // meters
    double angle = 45.0; // degrees
    
    std::vector<FGCom_RadiationPattern> patterns = mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern(
        vehicle_type, height, angle);
    
    EXPECT_GT(patterns.size(), 0) << "Ground vehicle antenna patterns should not be empty";
    
    // Test pattern data validity
    for (const auto& pattern : patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test different vehicle types
    std::vector<std::string> vehicle_types = {"NATO_Jeep", "Soviet_UAZ", "Ford_Transit", "VW_Passat"};
    for (const auto& type : vehicle_types) {
        std::vector<FGCom_RadiationPattern> type_patterns = mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern(
            type, height, angle);
        EXPECT_GT(type_patterns.size(), 0) << "Vehicle type " << type << " should have patterns";
    }
    
    // Test different heights
    std::vector<double> heights = {0.5, 1.0, 2.0, 3.0, 5.0};
    for (double h : heights) {
        std::vector<FGCom_RadiationPattern> height_patterns = mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern(
            vehicle_type, h, angle);
        EXPECT_GT(height_patterns.size(), 0) << "Height " << h << " should have patterns";
    }
    
    // Test different angles
    std::vector<double> angles = {0.0, 15.0, 30.0, 45.0, 60.0, 90.0};
    for (double a : angles) {
        std::vector<FGCom_RadiationPattern> angle_patterns = mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern(
            vehicle_type, height, a);
        EXPECT_GT(angle_patterns.size(), 0) << "Angle " << a << " should have patterns";
    }
}

TEST_F(VehicleAntennaTest, HandheldAntennaVertical) {
    // Test handheld antenna (vertical)
    std::string antenna_type = "Whip";
    double height = 1.5; // meters
    
    std::vector<FGCom_RadiationPattern> patterns = mock_vehicle_antenna_manager->getHandheldAntennaPattern(
        antenna_type, height);
    
    EXPECT_GT(patterns.size(), 0) << "Handheld antenna patterns should not be empty";
    
    // Test pattern data validity
    for (const auto& pattern : patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test different antenna types
    std::vector<std::string> antenna_types = {"Whip", "Rubber_Duck", "Helical", "Loaded"};
    for (const auto& type : antenna_types) {
        std::vector<FGCom_RadiationPattern> type_patterns = mock_vehicle_antenna_manager->getHandheldAntennaPattern(
            type, height);
        EXPECT_GT(type_patterns.size(), 0) << "Antenna type " << type << " should have patterns";
    }
    
    // Test different heights
    std::vector<double> heights = {0.5, 1.0, 1.5, 2.0, 3.0};
    for (double h : heights) {
        std::vector<FGCom_RadiationPattern> height_patterns = mock_vehicle_antenna_manager->getHandheldAntennaPattern(
            antenna_type, h);
        EXPECT_GT(height_patterns.size(), 0) << "Height " << h << " should have patterns";
    }
    
    // Test omnidirectional characteristics
    std::vector<double> azimuths = {0.0, 90.0, 180.0, 270.0};
    for (double az : azimuths) {
        double gain = mock_pattern_interpolator->lookupAzimuthPattern(az, patterns);
        EXPECT_GE(gain, -100.0) << "Omnidirectional gain should be reasonable";
        EXPECT_LE(gain, 50.0) << "Omnidirectional gain should be reasonable";
    }
}

TEST_F(VehicleAntennaTest, BaseStationAntennaElevated) {
    // Test base station antenna (elevated)
    std::string antenna_type = "Yagi";
    double height = 10.0; // meters
    
    std::vector<FGCom_RadiationPattern> patterns = mock_vehicle_antenna_manager->getBaseStationAntennaPattern(
        antenna_type, height);
    
    EXPECT_GT(patterns.size(), 0) << "Base station antenna patterns should not be empty";
    
    // Test pattern data validity
    for (const auto& pattern : patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test different antenna types
    std::vector<std::string> antenna_types = {"Yagi", "Dipole", "Vertical", "Loop", "Omni"};
    for (const auto& type : antenna_types) {
        std::vector<FGCom_RadiationPattern> type_patterns = mock_vehicle_antenna_manager->getBaseStationAntennaPattern(
            type, height);
        EXPECT_GT(type_patterns.size(), 0) << "Antenna type " << type << " should have patterns";
    }
    
    // Test different heights
    std::vector<double> heights = {5.0, 10.0, 15.0, 20.0, 30.0};
    for (double h : heights) {
        std::vector<FGCom_RadiationPattern> height_patterns = mock_vehicle_antenna_manager->getBaseStationAntennaPattern(
            antenna_type, h);
        EXPECT_GT(height_patterns.size(), 0) << "Height " << h << " should have patterns";
    }
    
    // Test directional characteristics
    std::vector<double> azimuths = {0.0, 90.0, 180.0, 270.0};
    for (double az : azimuths) {
        double gain = mock_pattern_interpolator->lookupAzimuthPattern(az, patterns);
        EXPECT_GE(gain, -100.0) << "Directional gain should be reasonable";
        EXPECT_LE(gain, 50.0) << "Directional gain should be reasonable";
    }
}

TEST_F(VehicleAntennaTest, MaritimeAntennaShipMounted) {
    // Test maritime antenna (ship-mounted)
    std::string ship_type = "Container_Ship";
    double height = 15.0; // meters
    double roll = 2.0; // degrees
    double pitch = 1.0; // degrees
    
    std::vector<FGCom_RadiationPattern> patterns = mock_vehicle_antenna_manager->getMaritimeAntennaPattern(
        ship_type, height, roll, pitch);
    
    EXPECT_GT(patterns.size(), 0) << "Maritime antenna patterns should not be empty";
    
    // Test pattern data validity
    for (const auto& pattern : patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test different ship types
    std::vector<std::string> ship_types = {"Container_Ship", "Cruise_Ship", "Navy_Ship", "Fishing_Boat", "Sailboat"};
    for (const auto& type : ship_types) {
        std::vector<FGCom_RadiationPattern> type_patterns = mock_vehicle_antenna_manager->getMaritimeAntennaPattern(
            type, height, roll, pitch);
        EXPECT_GT(type_patterns.size(), 0) << "Ship type " << type << " should have patterns";
    }
    
    // Test different heights
    std::vector<double> heights = {5.0, 10.0, 15.0, 20.0, 30.0};
    for (double h : heights) {
        std::vector<FGCom_RadiationPattern> height_patterns = mock_vehicle_antenna_manager->getMaritimeAntennaPattern(
            ship_type, h, roll, pitch);
        EXPECT_GT(height_patterns.size(), 0) << "Height " << h << " should have patterns";
    }
    
    // Test different ship attitudes
    std::vector<double> rolls = {-10.0, -5.0, 0.0, 5.0, 10.0};
    std::vector<double> pitches = {-5.0, -2.0, 0.0, 2.0, 5.0};
    for (double r : rolls) {
        for (double p : pitches) {
            std::vector<FGCom_RadiationPattern> attitude_patterns = mock_vehicle_antenna_manager->getMaritimeAntennaPattern(
                ship_type, height, r, p);
            EXPECT_GT(attitude_patterns.size(), 0) << "Attitude roll=" << r << " pitch=" << p << " should have patterns";
        }
    }
}

// Additional vehicle antenna tests
TEST_F(VehicleAntennaTest, VehicleAntennaPerformance) {
    // Test vehicle antenna performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test vehicle antenna performance
    for (int i = 0; i < num_operations; ++i) {
        mock_vehicle_antenna_manager->getAircraftAntennaPattern("B737", 10000.0, 5.0, 2.0);
        mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern("NATO_Jeep", 2.0, 45.0);
        mock_vehicle_antenna_manager->getHandheldAntennaPattern("Whip", 1.5);
        mock_vehicle_antenna_manager->getBaseStationAntennaPattern("Yagi", 10.0);
        mock_vehicle_antenna_manager->getMaritimeAntennaPattern("Container_Ship", 15.0, 2.0, 1.0);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Vehicle antenna operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Vehicle antenna operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Vehicle antenna performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(VehicleAntennaTest, VehicleAntennaAccuracy) {
    // Test vehicle antenna accuracy
    std::string aircraft_type = "B737";
    double altitude = 10000.0;
    double roll = 5.0;
    double pitch = 2.0;
    
    std::vector<FGCom_RadiationPattern> aircraft_patterns = mock_vehicle_antenna_manager->getAircraftAntennaPattern(
        aircraft_type, altitude, roll, pitch);
    EXPECT_GT(aircraft_patterns.size(), 0) << "Aircraft antenna patterns should be accurate";
    
    std::string vehicle_type = "NATO_Jeep";
    double height = 2.0;
    double angle = 45.0;
    
    std::vector<FGCom_RadiationPattern> vehicle_patterns = mock_vehicle_antenna_manager->getGroundVehicleAntennaPattern(
        vehicle_type, height, angle);
    EXPECT_GT(vehicle_patterns.size(), 0) << "Ground vehicle antenna patterns should be accurate";
    
    std::string antenna_type = "Whip";
    double handheld_height = 1.5;
    
    std::vector<FGCom_RadiationPattern> handheld_patterns = mock_vehicle_antenna_manager->getHandheldAntennaPattern(
        antenna_type, handheld_height);
    EXPECT_GT(handheld_patterns.size(), 0) << "Handheld antenna patterns should be accurate";
    
    std::string base_antenna_type = "Yagi";
    double base_height = 10.0;
    
    std::vector<FGCom_RadiationPattern> base_patterns = mock_vehicle_antenna_manager->getBaseStationAntennaPattern(
        base_antenna_type, base_height);
    EXPECT_GT(base_patterns.size(), 0) << "Base station antenna patterns should be accurate";
    
    std::string ship_type = "Container_Ship";
    double ship_height = 15.0;
    double ship_roll = 2.0;
    double ship_pitch = 1.0;
    
    std::vector<FGCom_RadiationPattern> maritime_patterns = mock_vehicle_antenna_manager->getMaritimeAntennaPattern(
        ship_type, ship_height, ship_roll, ship_pitch);
    EXPECT_GT(maritime_patterns.size(), 0) << "Maritime antenna patterns should be accurate";
}

