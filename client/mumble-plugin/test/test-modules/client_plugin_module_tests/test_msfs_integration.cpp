#include "test_client_plugin_module_main.cpp"

// 8.3 MSFS 2020 Integration Tests
TEST_F(MSFSIntegrationTest, SimConnectConnection) {
    // Test SimConnect connection
    EXPECT_FALSE(mock_msfs->isSimConnectConnected()) << "SimConnect should not be connected initially";
    
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    EXPECT_TRUE(mock_msfs->isSimConnectConnected()) << "SimConnect should be connected";
    
    // Test SimConnect disconnection
    mock_msfs->disconnectSimConnect();
    EXPECT_FALSE(mock_msfs->isSimConnectConnected()) << "SimConnect should not be connected after disconnect";
    
    // Test reconnection
    bool reconnect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(reconnect_result) << "SimConnect reconnection should succeed";
    EXPECT_TRUE(mock_msfs->isSimConnectConnected()) << "SimConnect should be connected after reconnection";
}

TEST_F(MSFSIntegrationTest, RadioVariableReading) {
    // Test radio variable reading
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    
    // Test radio variable reading
    bool read_result = mock_msfs->readRadioVariables();
    EXPECT_TRUE(read_result) << "Radio variable reading should succeed";
    
    // Test COM1 frequency reading
    double com1_frequency;
    bool com1_freq_result = mock_msfs->readCOM1Frequency(com1_frequency);
    EXPECT_TRUE(com1_freq_result) << "COM1 frequency reading should succeed";
    EXPECT_GT(com1_frequency, 0.0) << "COM1 frequency should be positive";
    
    // Test COM2 frequency reading
    double com2_frequency;
    bool com2_freq_result = mock_msfs->readCOM2Frequency(com2_frequency);
    EXPECT_TRUE(com2_freq_result) << "COM2 frequency reading should succeed";
    EXPECT_GT(com2_frequency, 0.0) << "COM2 frequency should be positive";
    
    // Test COM1 PTT reading
    bool com1_ptt;
    bool com1_ptt_result = mock_msfs->readCOM1PTT(com1_ptt);
    EXPECT_TRUE(com1_ptt_result) << "COM1 PTT reading should succeed";
    EXPECT_FALSE(com1_ptt) << "COM1 PTT should be false initially";
    
    // Test COM2 PTT reading
    bool com2_ptt;
    bool com2_ptt_result = mock_msfs->readCOM2PTT(com2_ptt);
    EXPECT_TRUE(com2_ptt_result) << "COM2 PTT reading should succeed";
    EXPECT_FALSE(com2_ptt) << "COM2 PTT should be false initially";
    
    // Test radio variable changes
    mock_msfs->setCOM1Frequency(121.650);
    mock_msfs->setCOM2Frequency(118.100);
    mock_msfs->setCOM1PTT(true);
    mock_msfs->setCOM2PTT(false);
    
    // Test updated COM1 frequency reading
    double updated_com1_freq;
    bool updated_com1_freq_result = mock_msfs->readCOM1Frequency(updated_com1_freq);
    EXPECT_TRUE(updated_com1_freq_result) << "Updated COM1 frequency reading should succeed";
    EXPECT_EQ(updated_com1_freq, 121.650) << "Updated COM1 frequency should match";
    
    // Test updated COM2 frequency reading
    double updated_com2_freq;
    bool updated_com2_freq_result = mock_msfs->readCOM2Frequency(updated_com2_freq);
    EXPECT_TRUE(updated_com2_freq_result) << "Updated COM2 frequency reading should succeed";
    EXPECT_EQ(updated_com2_freq, 118.100) << "Updated COM2 frequency should match";
    
    // Test updated COM1 PTT reading
    bool updated_com1_ptt;
    bool updated_com1_ptt_result = mock_msfs->readCOM1PTT(updated_com1_ptt);
    EXPECT_TRUE(updated_com1_ptt_result) << "Updated COM1 PTT reading should succeed";
    EXPECT_TRUE(updated_com1_ptt) << "Updated COM1 PTT should be true";
    
    // Test updated COM2 PTT reading
    bool updated_com2_ptt;
    bool updated_com2_ptt_result = mock_msfs->readCOM2PTT(updated_com2_ptt);
    EXPECT_TRUE(updated_com2_ptt_result) << "Updated COM2 PTT reading should succeed";
    EXPECT_FALSE(updated_com2_ptt) << "Updated COM2 PTT should be false";
}

TEST_F(MSFSIntegrationTest, PositionDataExtraction) {
    // Test position data extraction
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    
    // Test position data extraction
    bool extract_result = mock_msfs->extractPositionData();
    EXPECT_TRUE(extract_result) << "Position data extraction should succeed";
    
    // Test aircraft position
    double longitude, latitude, altitude;
    bool position_result = mock_msfs->getAircraftPosition(longitude, latitude, altitude);
    EXPECT_TRUE(position_result) << "Aircraft position reading should succeed";
    EXPECT_GT(longitude, -180.0) << "Longitude should be valid";
    EXPECT_LT(longitude, 180.0) << "Longitude should be valid";
    EXPECT_GT(latitude, -90.0) << "Latitude should be valid";
    EXPECT_LT(latitude, 90.0) << "Latitude should be valid";
    EXPECT_GE(altitude, 0.0) << "Altitude should be non-negative";
    
    // Test aircraft heading
    double heading;
    bool heading_result = mock_msfs->getAircraftHeading(heading);
    EXPECT_TRUE(heading_result) << "Aircraft heading reading should succeed";
    EXPECT_GE(heading, 0.0) << "Heading should be non-negative";
    EXPECT_LT(heading, 360.0) << "Heading should be less than 360 degrees";
    
    // Test aircraft speed
    double speed;
    bool speed_result = mock_msfs->getAircraftSpeed(speed);
    EXPECT_TRUE(speed_result) << "Aircraft speed reading should succeed";
    EXPECT_GE(speed, 0.0) << "Speed should be non-negative";
    
    // Test position data changes
    mock_msfs->setAircraftPosition(test_longitude, test_latitude, test_altitude);
    mock_msfs->setAircraftHeading(test_heading);
    mock_msfs->setAircraftSpeed(test_speed);
    
    // Test updated position data
    double updated_longitude, updated_latitude, updated_altitude;
    bool updated_position_result = mock_msfs->getAircraftPosition(updated_longitude, updated_latitude, updated_altitude);
    EXPECT_TRUE(updated_position_result) << "Updated aircraft position reading should succeed";
    EXPECT_EQ(updated_longitude, test_longitude) << "Updated longitude should match";
    EXPECT_EQ(updated_latitude, test_latitude) << "Updated latitude should match";
    EXPECT_EQ(updated_altitude, test_altitude) << "Updated altitude should match";
    
    // Test updated heading
    double updated_heading;
    bool updated_heading_result = mock_msfs->getAircraftHeading(updated_heading);
    EXPECT_TRUE(updated_heading_result) << "Updated aircraft heading reading should succeed";
    EXPECT_EQ(updated_heading, test_heading) << "Updated heading should match";
    
    // Test updated speed
    double updated_speed;
    bool updated_speed_result = mock_msfs->getAircraftSpeed(updated_speed);
    EXPECT_TRUE(updated_speed_result) << "Updated aircraft speed reading should succeed";
    EXPECT_EQ(updated_speed, test_speed) << "Updated speed should match";
}

TEST_F(MSFSIntegrationTest, PTTDetectionViaSimConnect) {
    // Test PTT detection via SimConnect
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    
    // Test initial PTT state
    bool initial_ptt = mock_msfs->detectPTTViaSimConnect();
    EXPECT_FALSE(initial_ptt) << "Initial PTT state should be false";
    
    // Test COM1 PTT activation
    mock_msfs->setCOM1PTT(true);
    bool com1_ptt_activated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_TRUE(com1_ptt_activated) << "PTT should be activated when COM1 is active";
    
    // Test COM1 PTT deactivation
    mock_msfs->setCOM1PTT(false);
    bool com1_ptt_deactivated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_FALSE(com1_ptt_deactivated) << "PTT should be deactivated when COM1 is inactive";
    
    // Test COM2 PTT activation
    mock_msfs->setCOM2PTT(true);
    bool com2_ptt_activated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_TRUE(com2_ptt_activated) << "PTT should be activated when COM2 is active";
    
    // Test COM2 PTT deactivation
    mock_msfs->setCOM2PTT(false);
    bool com2_ptt_deactivated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_FALSE(com2_ptt_deactivated) << "PTT should be deactivated when COM2 is inactive";
    
    // Test both COM radios active
    mock_msfs->setCOM1PTT(true);
    mock_msfs->setCOM2PTT(true);
    bool both_ptt_activated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_TRUE(both_ptt_activated) << "PTT should be activated when both COM radios are active";
    
    // Test both COM radios inactive
    mock_msfs->setCOM1PTT(false);
    mock_msfs->setCOM2PTT(false);
    bool both_ptt_deactivated = mock_msfs->detectPTTViaSimConnect();
    EXPECT_FALSE(both_ptt_deactivated) << "PTT should be deactivated when both COM radios are inactive";
}

TEST_F(MSFSIntegrationTest, RadioStateSynchronization) {
    // Test radio state synchronization
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    
    // Test radio state synchronization
    bool sync_result = mock_msfs->synchronizeRadioState();
    EXPECT_TRUE(sync_result) << "Radio state synchronization should succeed";
    
    // Test COM1 radio state
    mock_msfs->setCOM1Frequency(test_com1_frequency);
    mock_msfs->setCOM1PTT(false);
    
    double com1_freq;
    bool com1_ptt;
    bool com1_freq_result = mock_msfs->readCOM1Frequency(com1_freq);
    bool com1_ptt_result = mock_msfs->readCOM1PTT(com1_ptt);
    
    EXPECT_TRUE(com1_freq_result) << "COM1 frequency reading should succeed";
    EXPECT_TRUE(com1_ptt_result) << "COM1 PTT reading should succeed";
    
    EXPECT_EQ(com1_freq, test_com1_frequency) << "COM1 frequency should match";
    EXPECT_FALSE(com1_ptt) << "COM1 PTT should be false";
    
    // Test COM2 radio state
    mock_msfs->setCOM2Frequency(test_com2_frequency);
    mock_msfs->setCOM2PTT(false);
    
    double com2_freq;
    bool com2_ptt;
    bool com2_freq_result = mock_msfs->readCOM2Frequency(com2_freq);
    bool com2_ptt_result = mock_msfs->readCOM2PTT(com2_ptt);
    
    EXPECT_TRUE(com2_freq_result) << "COM2 frequency reading should succeed";
    EXPECT_TRUE(com2_ptt_result) << "COM2 PTT reading should succeed";
    
    EXPECT_EQ(com2_freq, test_com2_frequency) << "COM2 frequency should match";
    EXPECT_FALSE(com2_ptt) << "COM2 PTT should be false";
    
    // Test radio state changes
    mock_msfs->setCOM1PTT(true);
    mock_msfs->setCOM2PTT(true);
    
    bool com1_ptt_activated = mock_msfs->readCOM1PTT(com1_ptt);
    bool com2_ptt_activated = mock_msfs->readCOM2PTT(com2_ptt);
    bool ptt_activated = mock_msfs->detectPTTViaSimConnect();
    
    EXPECT_TRUE(com1_ptt_activated) << "COM1 PTT reading should succeed";
    EXPECT_TRUE(com2_ptt_activated) << "COM2 PTT reading should succeed";
    EXPECT_TRUE(com1_ptt) << "COM1 PTT should be activated";
    EXPECT_TRUE(com2_ptt) << "COM2 PTT should be activated";
    EXPECT_TRUE(ptt_activated) << "PTT should be activated";
    
    // Test radio state deactivation
    mock_msfs->setCOM1PTT(false);
    mock_msfs->setCOM2PTT(false);
    
    bool com1_ptt_deactivated = mock_msfs->readCOM1PTT(com1_ptt);
    bool com2_ptt_deactivated = mock_msfs->readCOM2PTT(com2_ptt);
    bool ptt_deactivated = mock_msfs->detectPTTViaSimConnect();
    
    EXPECT_TRUE(com1_ptt_deactivated) << "COM1 PTT reading should succeed";
    EXPECT_TRUE(com2_ptt_deactivated) << "COM2 PTT reading should succeed";
    EXPECT_FALSE(com1_ptt) << "COM1 PTT should be deactivated";
    EXPECT_FALSE(com2_ptt) << "COM2 PTT should be deactivated";
    EXPECT_FALSE(ptt_deactivated) << "PTT should be deactivated";
}

// Additional MSFS integration tests
TEST_F(MSFSIntegrationTest, MSFSPerformance) {
    // Test MSFS integration performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test SimConnect connection performance
    for (int i = 0; i < num_operations; ++i) {
        mock_msfs->connectSimConnect();
        mock_msfs->disconnectSimConnect();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // MSFS operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "MSFS operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "MSFS performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(MSFSIntegrationTest, MSFSAccuracy) {
    // Test MSFS integration accuracy
    bool connect_result = mock_msfs->connectSimConnect();
    EXPECT_TRUE(connect_result) << "SimConnect connection should succeed";
    
    // Test position accuracy
    double test_lon = -74.0060, test_lat = 40.7128, test_alt = 1000.0;
    mock_msfs->setAircraftPosition(test_lon, test_lat, test_alt);
    
    double longitude, latitude, altitude;
    bool position_result = mock_msfs->getAircraftPosition(longitude, latitude, altitude);
    EXPECT_TRUE(position_result) << "Aircraft position reading should succeed";
    
    EXPECT_EQ(longitude, test_lon) << "Longitude should be accurate";
    EXPECT_EQ(latitude, test_lat) << "Latitude should be accurate";
    EXPECT_EQ(altitude, test_alt) << "Altitude should be accurate";
    
    // Test heading accuracy
    double test_heading = 270.0;
    mock_msfs->setAircraftHeading(test_heading);
    
    double heading;
    bool heading_result = mock_msfs->getAircraftHeading(heading);
    EXPECT_TRUE(heading_result) << "Aircraft heading reading should succeed";
    EXPECT_EQ(heading, test_heading) << "Heading should be accurate";
    
    // Test speed accuracy
    double test_speed = 150.0;
    mock_msfs->setAircraftSpeed(test_speed);
    
    double speed;
    bool speed_result = mock_msfs->getAircraftSpeed(speed);
    EXPECT_TRUE(speed_result) << "Aircraft speed reading should succeed";
    EXPECT_EQ(speed, test_speed) << "Speed should be accurate";
    
    // Test frequency accuracy
    double test_freq1 = 121.650, test_freq2 = 118.100;
    mock_msfs->setCOM1Frequency(test_freq1);
    mock_msfs->setCOM2Frequency(test_freq2);
    
    double freq1, freq2;
    bool freq1_result = mock_msfs->readCOM1Frequency(freq1);
    bool freq2_result = mock_msfs->readCOM2Frequency(freq2);
    
    EXPECT_TRUE(freq1_result) << "COM1 frequency reading should succeed";
    EXPECT_TRUE(freq2_result) << "COM2 frequency reading should succeed";
    
    EXPECT_EQ(freq1, test_freq1) << "COM1 frequency should be accurate";
    EXPECT_EQ(freq2, test_freq2) << "COM2 frequency should be accurate";
    
    // Test PTT accuracy
    mock_msfs->setCOM1PTT(true);
    mock_msfs->setCOM2PTT(false);
    
    bool com1_ptt, com2_ptt;
    bool com1_ptt_result = mock_msfs->readCOM1PTT(com1_ptt);
    bool com2_ptt_result = mock_msfs->readCOM2PTT(com2_ptt);
    bool ptt_result = mock_msfs->detectPTTViaSimConnect();
    
    EXPECT_TRUE(com1_ptt_result) << "COM1 PTT reading should succeed";
    EXPECT_TRUE(com2_ptt_result) << "COM2 PTT reading should succeed";
    
    EXPECT_TRUE(com1_ptt) << "COM1 PTT should be accurate";
    EXPECT_FALSE(com2_ptt) << "COM2 PTT should be accurate";
    EXPECT_TRUE(ptt_result) << "PTT should be accurate";
}

