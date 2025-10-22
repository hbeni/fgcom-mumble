#include "test_geographic_module_main.cpp"

// 6.3 Vehicle Dynamics Tests
TEST_F(VehicleDynamicsTest, PositionTracking) {
    // Test position tracking
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_001");
    
    // Test initial position
    EXPECT_NEAR(dynamics.position.latitude, test_latitude_nyc, 1e-6) << "Initial latitude should match test value";
    EXPECT_NEAR(dynamics.position.longitude, test_longitude_nyc, 1e-6) << "Initial longitude should match test value";
    EXPECT_NEAR(dynamics.position.altitude_ft_msl, test_altitude_aircraft, 1.0) << "Initial altitude should match test value";
    EXPECT_EQ(dynamics.position.callsign, "TEST01") << "Initial callsign should match test value";
    EXPECT_EQ(dynamics.position.vehicle_type, "aircraft") << "Initial vehicle type should match test value";
    
    // Test position update
    fgcom_vehicle_position new_position;
    new_position.latitude = test_latitude_london;
    new_position.longitude = test_longitude_london;
    new_position.altitude_ft_msl = test_altitude_aircraft + 1000.0;
    new_position.altitude_ft_agl = test_altitude_aircraft + 1000.0 - test_altitude_ground;
    new_position.ground_elevation_ft = test_altitude_ground;
    new_position.callsign = "TEST02";
    new_position.vehicle_type = "aircraft";
    
    // Test position validation
    EXPECT_TRUE(isValidLatitude(new_position.latitude)) << "New position latitude should be valid";
    EXPECT_TRUE(isValidLongitude(new_position.longitude)) << "New position longitude should be valid";
    EXPECT_TRUE(isValidAltitude(new_position.altitude_ft_msl)) << "New position altitude should be valid";
    
    // Test position tracking accuracy
    double distance = calculateGreatCircleDistance(dynamics.position.latitude, dynamics.position.longitude,
                                                  new_position.latitude, new_position.longitude);
    EXPECT_GT(distance, 0.0) << "Distance between positions should be positive";
    EXPECT_LT(distance, 20000.0) << "Distance between positions should be reasonable";
    
    // Test position change detection
    bool position_changed = (dynamics.position.latitude != new_position.latitude) ||
                           (dynamics.position.longitude != new_position.longitude) ||
                           (dynamics.position.altitude_ft_msl != new_position.altitude_ft_msl);
    EXPECT_TRUE(position_changed) << "Position should have changed";
}

TEST_F(VehicleDynamicsTest, VelocityCalculation) {
    // Test velocity calculation
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_002");
    
    // Test initial velocity
    EXPECT_NEAR(dynamics.velocity.speed_knots, 100.0f, 1e-6) << "Initial speed in knots should match test value";
    EXPECT_NEAR(dynamics.velocity.speed_kmh, 185.0f, 1e-6) << "Initial speed in km/h should match test value";
    EXPECT_NEAR(dynamics.velocity.speed_ms, 51.4f, 1e-6) << "Initial speed in m/s should match test value";
    EXPECT_NEAR(dynamics.velocity.course_deg, 0.0f, 1e-6) << "Initial course should match test value";
    EXPECT_NEAR(dynamics.velocity.vertical_speed_fpm, 0.0f, 1e-6) << "Initial vertical speed should match test value";
    EXPECT_NEAR(dynamics.velocity.vertical_speed_ms, 0.0f, 1e-6) << "Initial vertical speed in m/s should match test value";
    
    // Test velocity validation
    EXPECT_TRUE(isValidVehicleSpeed(dynamics.velocity.speed_kmh)) << "Vehicle speed should be valid";
    EXPECT_TRUE(isValidVehicleHeading(dynamics.velocity.course_deg)) << "Vehicle course should be valid";
    
    // Test velocity unit conversion
    double speed_knots = dynamics.velocity.speed_knots;
    double speed_kmh = dynamics.velocity.speed_kmh;
    double speed_ms = dynamics.velocity.speed_ms;
    
    // Test conversion accuracy
    EXPECT_NEAR(speed_kmh, speed_knots * 1.852, 0.5) << "Speed conversion knots to km/h should be accurate";
    EXPECT_NEAR(speed_ms, speed_kmh / 3.6, 0.5) << "Speed conversion km/h to m/s should be accurate";
    
    // Test velocity update
    fgcom_vehicle_velocity new_velocity;
    new_velocity.speed_knots = 200.0f;
    new_velocity.speed_kmh = 370.0f;
    new_velocity.speed_ms = 102.8f;
    new_velocity.course_deg = 90.0f;
    new_velocity.vertical_speed_fpm = 1000.0f;
    new_velocity.vertical_speed_ms = 5.08f;
    
    // Test velocity validation
    EXPECT_TRUE(isValidVehicleSpeed(new_velocity.speed_kmh)) << "New vehicle speed should be valid";
    EXPECT_TRUE(isValidVehicleHeading(new_velocity.course_deg)) << "New vehicle course should be valid";
    
    // Test velocity change detection
    bool velocity_changed = (dynamics.velocity.speed_knots != new_velocity.speed_knots) ||
                           (dynamics.velocity.course_deg != new_velocity.course_deg);
    EXPECT_TRUE(velocity_changed) << "Velocity should have changed";
}

TEST_F(VehicleDynamicsTest, HeadingBearing) {
    // Test heading/bearing calculation
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_003");
    
    // Test initial heading
    EXPECT_NEAR(dynamics.attitude.yaw_deg, 0.0f, 1e-6) << "Initial yaw should match test value";
    EXPECT_NEAR(dynamics.attitude.magnetic_heading_deg, 0.0f, 1e-6) << "Initial magnetic heading should match test value";
    EXPECT_NEAR(dynamics.attitude.magnetic_declination_deg, 0.0f, 1e-6) << "Initial magnetic declination should match test value";
    
    // Test heading validation
    EXPECT_TRUE(isValidVehicleHeading(dynamics.attitude.yaw_deg)) << "Yaw should be valid";
    EXPECT_TRUE(isValidVehicleHeading(dynamics.attitude.magnetic_heading_deg)) << "Magnetic heading should be valid";
    
    // Test heading update
    fgcom_vehicle_attitude new_attitude;
    new_attitude.pitch_deg = 5.0f;
    new_attitude.roll_deg = 10.0f;
    new_attitude.yaw_deg = 45.0f;
    new_attitude.magnetic_heading_deg = 45.0f;
    new_attitude.magnetic_declination_deg = 2.0f;
    
    // Test attitude validation
    EXPECT_GE(new_attitude.pitch_deg, -90.0f) << "Pitch should be >= -90 degrees";
    EXPECT_LE(new_attitude.pitch_deg, 90.0f) << "Pitch should be <= 90 degrees";
    EXPECT_GE(new_attitude.roll_deg, -180.0f) << "Roll should be >= -180 degrees";
    EXPECT_LE(new_attitude.roll_deg, 180.0f) << "Roll should be <= 180 degrees";
    EXPECT_TRUE(isValidVehicleHeading(new_attitude.yaw_deg)) << "Yaw should be valid";
    EXPECT_TRUE(isValidVehicleHeading(new_attitude.magnetic_heading_deg)) << "Magnetic heading should be valid";
    
    // Test heading change detection
    bool heading_changed = (dynamics.attitude.yaw_deg != new_attitude.yaw_deg) ||
                          (dynamics.attitude.magnetic_heading_deg != new_attitude.magnetic_heading_deg);
    EXPECT_TRUE(heading_changed) << "Heading should have changed";
    
    // Test magnetic declination calculation
    double lat = test_latitude_nyc;
    double lon = test_longitude_nyc;
    double declination = calculateMagneticDeclination(lat, lon);
    
    EXPECT_GE(declination, -180.0) << "Magnetic declination should be >= -180 degrees";
    EXPECT_LE(declination, 180.0) << "Magnetic declination should be <= 180 degrees";
}

TEST_F(VehicleDynamicsTest, AltitudeChanges) {
    // Test altitude changes
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_004");
    
    // Test initial altitude
    EXPECT_NEAR(dynamics.position.altitude_ft_msl, test_altitude_aircraft, 1.0) << "Initial altitude MSL should match test value";
    EXPECT_NEAR(dynamics.position.altitude_ft_agl, test_altitude_aircraft - test_altitude_ground, 1.0) << "Initial altitude AGL should match test value";
    EXPECT_NEAR(dynamics.position.ground_elevation_ft, test_altitude_ground, 1.0) << "Initial ground elevation should match test value";
    
    // Test altitude validation
    EXPECT_TRUE(isValidAltitude(dynamics.position.altitude_ft_msl)) << "Altitude MSL should be valid";
    EXPECT_TRUE(isValidAltitude(dynamics.position.altitude_ft_agl)) << "Altitude AGL should be valid";
    EXPECT_TRUE(isValidAltitude(dynamics.position.ground_elevation_ft)) << "Ground elevation should be valid";
    
    // Test altitude change
    double new_altitude_msl = test_altitude_aircraft + test_vehicle_altitude_change;
    double new_altitude_agl = new_altitude_msl - test_altitude_ground;
    
    // Test altitude change calculation
    double altitude_change = new_altitude_msl - dynamics.position.altitude_ft_msl;
    EXPECT_NEAR(altitude_change, test_vehicle_altitude_change, 1.0) << "Altitude change should match expected value";
    
    // Test altitude change validation
    EXPECT_TRUE(isValidAltitude(new_altitude_msl)) << "New altitude MSL should be valid";
    EXPECT_TRUE(isValidAltitude(new_altitude_agl)) << "New altitude AGL should be valid";
    
    // Test altitude change detection
    bool altitude_changed = (dynamics.position.altitude_ft_msl != new_altitude_msl);
    EXPECT_TRUE(altitude_changed) << "Altitude should have changed";
    
    // Test vertical speed calculation
    double time_interval = 1.0; // 1 second
    double vertical_speed_fpm = altitude_change / time_interval;
    double vertical_speed_ms = vertical_speed_fpm * 0.3048 / 60.0; // Convert to m/s
    
    EXPECT_NEAR(vertical_speed_fpm, test_vehicle_altitude_change, 1.0) << "Vertical speed in fpm should match expected value";
    EXPECT_NEAR(vertical_speed_ms, test_vehicle_altitude_change * 0.3048 / 60.0, 0.1) << "Vertical speed in m/s should match expected value";
}

TEST_F(VehicleDynamicsTest, AntennaOrientation) {
    // Test antenna orientation
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_005");
    
    // Test initial antenna orientation
    EXPECT_EQ(dynamics.antennas.size(), 1) << "Should have one antenna";
    EXPECT_EQ(dynamics.antennas[0].antenna_id, "ant_001") << "Antenna ID should match test value";
    EXPECT_EQ(dynamics.antennas[0].antenna_type, "yagi") << "Antenna type should match test value";
    EXPECT_NEAR(dynamics.antennas[0].azimuth_deg, 0.0f, 1e-6) << "Initial azimuth should match test value";
    EXPECT_NEAR(dynamics.antennas[0].elevation_deg, 0.0f, 1e-6) << "Initial elevation should match test value";
    EXPECT_FALSE(dynamics.antennas[0].is_auto_tracking) << "Auto-tracking should be disabled initially";
    EXPECT_NEAR(dynamics.antennas[0].rotation_speed_deg_per_sec, 0.0f, 1e-6) << "Rotation speed should match test value";
    
    // Test antenna orientation validation
    EXPECT_TRUE(isValidAntennaAzimuth(dynamics.antennas[0].azimuth_deg)) << "Antenna azimuth should be valid";
    EXPECT_TRUE(isValidAntennaElevation(dynamics.antennas[0].elevation_deg)) << "Antenna elevation should be valid";
    
    // Test antenna orientation update
    fgcom_antenna_orientation new_antenna;
    new_antenna.antenna_id = "ant_002";
    new_antenna.antenna_type = "dipole";
    new_antenna.azimuth_deg = 45.0f;
    new_antenna.elevation_deg = 30.0f;
    new_antenna.is_auto_tracking = true;
    new_antenna.rotation_speed_deg_per_sec = 10.0f;
    
    // Test antenna orientation validation
    EXPECT_TRUE(isValidAntennaAzimuth(new_antenna.azimuth_deg)) << "New antenna azimuth should be valid";
    EXPECT_TRUE(isValidAntennaElevation(new_antenna.elevation_deg)) << "New antenna elevation should be valid";
    
    // Test antenna orientation change detection
    bool orientation_changed = (dynamics.antennas[0].azimuth_deg != new_antenna.azimuth_deg) ||
                              (dynamics.antennas[0].elevation_deg != new_antenna.elevation_deg);
    EXPECT_TRUE(orientation_changed) << "Antenna orientation should have changed";
    
    // Test antenna auto-tracking
    EXPECT_TRUE(new_antenna.is_auto_tracking) << "Auto-tracking should be enabled";
    EXPECT_GT(new_antenna.rotation_speed_deg_per_sec, 0.0f) << "Rotation speed should be positive for auto-tracking";
    
    // Test antenna rotation calculation
    double rotation_time = 10.0; // 10 seconds
    double rotation_angle = new_antenna.rotation_speed_deg_per_sec * rotation_time;
    EXPECT_NEAR(rotation_angle, 100.0f, 1e-6) << "Rotation angle should match expected value";
}

TEST_F(VehicleDynamicsTest, MobileVsStationaryDetection) {
    // Test mobile vs stationary detection
    fgcom_vehicle_dynamics mobile_vehicle = createTestVehicleDynamics("mobile_vehicle");
    fgcom_vehicle_dynamics stationary_vehicle = createTestVehicleDynamics("stationary_vehicle");
    
    // Test mobile vehicle
    mobile_vehicle.velocity.speed_kmh = test_vehicle_speed_medium;
    mobile_vehicle.velocity.course_deg = 45.0f;
    mobile_vehicle.position.latitude = test_latitude_nyc;
    mobile_vehicle.position.longitude = test_longitude_nyc;
    
    // Test stationary vehicle
    stationary_vehicle.velocity.speed_kmh = 0.0f;
    stationary_vehicle.velocity.course_deg = 0.0f;
    stationary_vehicle.position.latitude = test_latitude_london;
    stationary_vehicle.position.longitude = test_longitude_london;
    
    // Test mobile detection
    bool is_mobile = mobile_vehicle.velocity.speed_kmh > 1.0f; // Threshold for mobile detection
    EXPECT_TRUE(is_mobile) << "Mobile vehicle should be detected as mobile";
    
    // Test stationary detection
    bool is_stationary = stationary_vehicle.velocity.speed_kmh <= 1.0f; // Threshold for stationary detection
    EXPECT_TRUE(is_stationary) << "Stationary vehicle should be detected as stationary";
    
    // Test speed threshold
    double speed_threshold = 1.0f; // 1 km/h threshold
    EXPECT_GT(mobile_vehicle.velocity.speed_kmh, speed_threshold) << "Mobile vehicle speed should be above threshold";
    EXPECT_LE(stationary_vehicle.velocity.speed_kmh, speed_threshold) << "Stationary vehicle speed should be below threshold";
    
    // Test position change detection
    double position_change_threshold = 0.001; // 0.001 degrees threshold
    double lat_change = std::abs(mobile_vehicle.position.latitude - stationary_vehicle.position.latitude);
    double lon_change = std::abs(mobile_vehicle.position.longitude - stationary_vehicle.position.longitude);
    
    bool position_changed = (lat_change > position_change_threshold) || (lon_change > position_change_threshold);
    EXPECT_TRUE(position_changed) << "Position should have changed between mobile and stationary vehicles";
    
    // Test velocity change detection
    double velocity_change_threshold = 1.0f; // 1 km/h threshold
    double speed_change = std::abs(mobile_vehicle.velocity.speed_kmh - stationary_vehicle.velocity.speed_kmh);
    
    bool velocity_changed = speed_change > velocity_change_threshold;
    EXPECT_TRUE(velocity_changed) << "Velocity should have changed between mobile and stationary vehicles";
}

// Additional vehicle dynamics tests
TEST_F(VehicleDynamicsTest, VehicleDynamicsPerformance) {
    // Test vehicle dynamics performance
    const int num_updates = 1000;
    std::vector<fgcom_vehicle_dynamics> vehicles;
    
    // Generate test vehicles
    for (int i = 0; i < num_updates; ++i) {
        fgcom_vehicle_dynamics vehicle = createTestVehicleDynamics("vehicle_" + std::to_string(i));
        vehicles.push_back(vehicle);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test vehicle dynamics update performance
    for (int i = 0; i < num_updates; ++i) {
        // Update position
        vehicles[i].position.latitude += 0.001;
        vehicles[i].position.longitude += 0.001;
        vehicles[i].position.altitude_ft_msl += 10.0;
        
        // Update velocity
        vehicles[i].velocity.speed_kmh += 1.0;
        vehicles[i].velocity.course_deg += 1.0;
        
        // Update attitude
        vehicles[i].attitude.yaw_deg += 1.0;
        vehicles[i].attitude.pitch_deg += 0.1;
        vehicles[i].attitude.roll_deg += 0.1;
        
        // Update antenna orientation
        if (!vehicles[i].antennas.empty()) {
            vehicles[i].antennas[0].azimuth_deg += 1.0;
            vehicles[i].antennas[0].elevation_deg += 0.1;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_update = static_cast<double>(duration.count()) / num_updates;
    
    // Vehicle dynamics update should be fast
    EXPECT_LT(time_per_update, 100.0) << "Vehicle dynamics update too slow: " << time_per_update << " microseconds";
    
    std::cout << "Vehicle dynamics update performance: " << time_per_update << " microseconds per update" << std::endl;
}

TEST_F(VehicleDynamicsTest, VehicleDynamicsAccuracy) {
    // Test vehicle dynamics accuracy
    fgcom_vehicle_dynamics dynamics = createTestVehicleDynamics("test_vehicle_006");
    
    // Test position accuracy
    EXPECT_NEAR(dynamics.position.latitude, test_latitude_nyc, 1e-6) << "Position latitude should be accurate";
    EXPECT_NEAR(dynamics.position.longitude, test_longitude_nyc, 1e-6) << "Position longitude should be accurate";
    EXPECT_NEAR(dynamics.position.altitude_ft_msl, test_altitude_aircraft, 1.0) << "Position altitude should be accurate";
    
    // Test velocity accuracy
    EXPECT_NEAR(dynamics.velocity.speed_kmh, 185.0f, 0.1) << "Velocity speed should be accurate";
    EXPECT_NEAR(dynamics.velocity.course_deg, 0.0f, 0.1) << "Velocity course should be accurate";
    
    // Test attitude accuracy
    EXPECT_NEAR(dynamics.attitude.yaw_deg, 0.0f, 0.1) << "Attitude yaw should be accurate";
    EXPECT_NEAR(dynamics.attitude.pitch_deg, 0.0f, 0.1) << "Attitude pitch should be accurate";
    EXPECT_NEAR(dynamics.attitude.roll_deg, 0.0f, 0.1) << "Attitude roll should be accurate";
    
    // Test antenna orientation accuracy
    EXPECT_NEAR(dynamics.antennas[0].azimuth_deg, 0.0f, 0.1) << "Antenna azimuth should be accurate";
    EXPECT_NEAR(dynamics.antennas[0].elevation_deg, 0.0f, 0.1) << "Antenna elevation should be accurate";
    
    // Test coordinate validation
    EXPECT_TRUE(isValidLatitude(dynamics.position.latitude)) << "Position latitude should be valid";
    EXPECT_TRUE(isValidLongitude(dynamics.position.longitude)) << "Position longitude should be valid";
    EXPECT_TRUE(isValidAltitude(dynamics.position.altitude_ft_msl)) << "Position altitude should be valid";
    
    // Test velocity validation
    EXPECT_TRUE(isValidVehicleSpeed(dynamics.velocity.speed_kmh)) << "Vehicle speed should be valid";
    EXPECT_TRUE(isValidVehicleHeading(dynamics.velocity.course_deg)) << "Vehicle course should be valid";
    
    // Test attitude validation
    EXPECT_GE(dynamics.attitude.pitch_deg, -90.0f) << "Pitch should be >= -90 degrees";
    EXPECT_LE(dynamics.attitude.pitch_deg, 90.0f) << "Pitch should be <= 90 degrees";
    EXPECT_GE(dynamics.attitude.roll_deg, -180.0f) << "Roll should be >= -180 degrees";
    EXPECT_LE(dynamics.attitude.roll_deg, 180.0f) << "Roll should be <= 180 degrees";
    EXPECT_TRUE(isValidVehicleHeading(dynamics.attitude.yaw_deg)) << "Yaw should be valid";
    
    // Test antenna orientation validation
    EXPECT_TRUE(isValidAntennaAzimuth(dynamics.antennas[0].azimuth_deg)) << "Antenna azimuth should be valid";
    EXPECT_TRUE(isValidAntennaElevation(dynamics.antennas[0].elevation_deg)) << "Antenna elevation should be valid";
}

