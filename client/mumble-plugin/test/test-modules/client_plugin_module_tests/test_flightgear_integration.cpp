#include "test_client_plugin_module_main.cpp"

// 8.2 FlightGear Integration Tests
TEST_F(FlightGearIntegrationTest, PropertyTreeReading) {
    // Test property tree reading
    EXPECT_FALSE(mock_flightgear->isConnected()) << "FlightGear should not be connected initially";
    
    // Test property tree loading
    std::string config_file = generateConfigFile("flightgear_config.ini", {
        {"position/longitude-deg", "-74.0060"},
        {"position/latitude-deg", "40.7128"},
        {"position/altitude-ft", "1000.0"},
        {"instrumentation/comm[0]/frequencies/selected-mhz", "121.650"},
        {"instrumentation/comm[1]/frequencies/selected-mhz", "118.100"},
        {"instrumentation/comm[0]/ptt", "0"},
        {"instrumentation/comm[1]/ptt", "0"}
    });
    
    bool load_result = mock_flightgear->loadPropertyTree(config_file);
    EXPECT_TRUE(load_result) << "Property tree loading should succeed";
    
    // Test property reading
    std::string value;
    
    // Test longitude reading
    bool lon_result = mock_flightgear->readProperty("/position/longitude-deg", value);
    EXPECT_TRUE(lon_result) << "Longitude property reading should succeed";
    EXPECT_EQ(value, "-74.0060") << "Longitude value should match";
    
    // Test latitude reading
    bool lat_result = mock_flightgear->readProperty("/position/latitude-deg", value);
    EXPECT_TRUE(lat_result) << "Latitude property reading should succeed";
    EXPECT_EQ(value, "40.7128") << "Latitude value should match";
    
    // Test altitude reading
    bool alt_result = mock_flightgear->readProperty("/position/altitude-ft", value);
    EXPECT_TRUE(alt_result) << "Altitude property reading should succeed";
    EXPECT_EQ(value, "1000.0") << "Altitude value should match";
    
    // Test COM1 frequency reading
    bool com1_freq_result = mock_flightgear->readProperty("/instrumentation/comm[0]/frequencies/selected-mhz", value);
    EXPECT_TRUE(com1_freq_result) << "COM1 frequency property reading should succeed";
    EXPECT_EQ(value, "121.650") << "COM1 frequency value should match";
    
    // Test COM2 frequency reading
    bool com2_freq_result = mock_flightgear->readProperty("/instrumentation/comm[1]/frequencies/selected-mhz", value);
    EXPECT_TRUE(com2_freq_result) << "COM2 frequency property reading should succeed";
    EXPECT_EQ(value, "118.100") << "COM2 frequency value should match";
    
    // Test COM1 PTT reading
    bool com1_ptt_result = mock_flightgear->readProperty("/instrumentation/comm[0]/ptt", value);
    EXPECT_TRUE(com1_ptt_result) << "COM1 PTT property reading should succeed";
    EXPECT_EQ(value, "0") << "COM1 PTT value should match";
    
    // Test COM2 PTT reading
    bool com2_ptt_result = mock_flightgear->readProperty("/instrumentation/comm[1]/ptt", value);
    EXPECT_TRUE(com2_ptt_result) << "COM2 PTT property reading should succeed";
    EXPECT_EQ(value, "0") << "COM2 PTT value should match";
}

TEST_F(FlightGearIntegrationTest, RadioFrequencySync) {
    // Test radio frequency sync
    bool connect_result = mock_flightgear->connect();
    EXPECT_TRUE(connect_result) << "FlightGear connection should succeed";
    EXPECT_TRUE(mock_flightgear->isConnected()) << "FlightGear should be connected";
    
    // Test frequency sync
    bool sync_result = mock_flightgear->syncRadioFrequencies();
    EXPECT_TRUE(sync_result) << "Radio frequency sync should succeed";
    
    // Test frequency reading after sync
    std::string com1_freq, com2_freq;
    bool com1_read = mock_flightgear->readProperty("/instrumentation/comm[0]/frequencies/selected-mhz", com1_freq);
    bool com2_read = mock_flightgear->readProperty("/instrumentation/comm[1]/frequencies/selected-mhz", com2_freq);
    
    EXPECT_TRUE(com1_read) << "COM1 frequency reading should succeed";
    EXPECT_TRUE(com2_read) << "COM2 frequency reading should succeed";
    
    // Test frequency values
    EXPECT_EQ(com1_freq, "121.650") << "COM1 frequency should match";
    EXPECT_EQ(com2_freq, "118.100") << "COM2 frequency should match";
    
    // Test frequency writing
    bool com1_write = mock_flightgear->writeProperty("/instrumentation/comm[0]/frequencies/selected-mhz", "121.900");
    bool com2_write = mock_flightgear->writeProperty("/instrumentation/comm[1]/frequencies/selected-mhz", "118.500");
    
    EXPECT_TRUE(com1_write) << "COM1 frequency writing should succeed";
    EXPECT_TRUE(com2_write) << "COM2 frequency writing should succeed";
    
    // Test frequency reading after writing
    bool com1_read_after = mock_flightgear->readProperty("/instrumentation/comm[0]/frequencies/selected-mhz", com1_freq);
    bool com2_read_after = mock_flightgear->readProperty("/instrumentation/comm[1]/frequencies/selected-mhz", com2_freq);
    
    EXPECT_TRUE(com1_read_after) << "COM1 frequency reading after write should succeed";
    EXPECT_TRUE(com2_read_after) << "COM2 frequency reading after write should succeed";
    
    EXPECT_EQ(com1_freq, "121.900") << "COM1 frequency should be updated";
    EXPECT_EQ(com2_freq, "118.500") << "COM2 frequency should be updated";
}

TEST_F(FlightGearIntegrationTest, PTTDetection) {
    // Test PTT detection
    bool connect_result = mock_flightgear->connect();
    EXPECT_TRUE(connect_result) << "FlightGear connection should succeed";
    
    // Test initial PTT state
    bool initial_ptt = mock_flightgear->detectPTT();
    EXPECT_FALSE(initial_ptt) << "Initial PTT state should be false";
    
    bool initial_com1_ptt = mock_flightgear->detectCOM1PTT();
    EXPECT_FALSE(initial_com1_ptt) << "Initial COM1 PTT state should be false";
    
    bool initial_com2_ptt = mock_flightgear->detectCOM2PTT();
    EXPECT_FALSE(initial_com2_ptt) << "Initial COM2 PTT state should be false";
    
    // Test COM1 PTT activation
    mock_flightgear->setCOM1PTT(true);
    bool com1_ptt_activated = mock_flightgear->detectCOM1PTT();
    EXPECT_TRUE(com1_ptt_activated) << "COM1 PTT should be activated";
    
    bool ptt_activated = mock_flightgear->detectPTT();
    EXPECT_TRUE(ptt_activated) << "PTT should be activated when COM1 is active";
    
    // Test COM1 PTT deactivation
    mock_flightgear->setCOM1PTT(false);
    bool com1_ptt_deactivated = mock_flightgear->detectCOM1PTT();
    EXPECT_FALSE(com1_ptt_deactivated) << "COM1 PTT should be deactivated";
    
    bool ptt_deactivated = mock_flightgear->detectPTT();
    EXPECT_FALSE(ptt_deactivated) << "PTT should be deactivated when COM1 is inactive";
    
    // Test COM2 PTT activation
    mock_flightgear->setCOM2PTT(true);
    bool com2_ptt_activated = mock_flightgear->detectCOM2PTT();
    EXPECT_TRUE(com2_ptt_activated) << "COM2 PTT should be activated";
    
    bool ptt_activated_com2 = mock_flightgear->detectPTT();
    EXPECT_TRUE(ptt_activated_com2) << "PTT should be activated when COM2 is active";
    
    // Test COM2 PTT deactivation
    mock_flightgear->setCOM2PTT(false);
    bool com2_ptt_deactivated = mock_flightgear->detectCOM2PTT();
    EXPECT_FALSE(com2_ptt_deactivated) << "COM2 PTT should be deactivated";
    
    bool ptt_deactivated_com2 = mock_flightgear->detectPTT();
    EXPECT_FALSE(ptt_deactivated_com2) << "PTT should be deactivated when COM2 is inactive";
}

TEST_F(FlightGearIntegrationTest, AircraftPositionSync) {
    // Test aircraft position sync
    bool connect_result = mock_flightgear->connect();
    EXPECT_TRUE(connect_result) << "FlightGear connection should succeed";
    
    // Test position sync
    bool sync_result = mock_flightgear->syncAircraftPosition();
    EXPECT_TRUE(sync_result) << "Aircraft position sync should succeed";
    
    // Test position data setting
    mock_flightgear->setPosition(test_longitude, test_latitude, test_altitude);
    
    // Test position data reading
    std::string lon_str, lat_str, alt_str;
    bool lon_read = mock_flightgear->readProperty("/position/longitude-deg", lon_str);
    bool lat_read = mock_flightgear->readProperty("/position/latitude-deg", lat_str);
    bool alt_read = mock_flightgear->readProperty("/position/altitude-ft", alt_str);
    
    EXPECT_TRUE(lon_read) << "Longitude reading should succeed";
    EXPECT_TRUE(lat_read) << "Latitude reading should succeed";
    EXPECT_TRUE(alt_read) << "Altitude reading should succeed";
    
    // Test position data accuracy
    EXPECT_EQ(lon_str, std::to_string(test_longitude)) << "Longitude should match";
    EXPECT_EQ(lat_str, std::to_string(test_latitude)) << "Latitude should match";
    EXPECT_EQ(alt_str, std::to_string(test_altitude)) << "Altitude should match";
    
    // Test position data writing
    double new_longitude = -75.0000;
    double new_latitude = 41.0000;
    double new_altitude = 2000.0;
    
    bool lon_write = mock_flightgear->writeProperty("/position/longitude-deg", std::to_string(new_longitude));
    bool lat_write = mock_flightgear->writeProperty("/position/latitude-deg", std::to_string(new_latitude));
    bool alt_write = mock_flightgear->writeProperty("/position/altitude-ft", std::to_string(new_altitude));
    
    EXPECT_TRUE(lon_write) << "Longitude writing should succeed";
    EXPECT_TRUE(lat_write) << "Latitude writing should succeed";
    EXPECT_TRUE(alt_write) << "Altitude writing should succeed";
    
    // Test position data reading after writing
    bool lon_read_after = mock_flightgear->readProperty("/position/longitude-deg", lon_str);
    bool lat_read_after = mock_flightgear->readProperty("/position/latitude-deg", lat_str);
    bool alt_read_after = mock_flightgear->readProperty("/position/altitude-ft", alt_str);
    
    EXPECT_TRUE(lon_read_after) << "Longitude reading after write should succeed";
    EXPECT_TRUE(lat_read_after) << "Latitude reading after write should succeed";
    EXPECT_TRUE(alt_read_after) << "Altitude reading after write should succeed";
    
    EXPECT_EQ(lon_str, std::to_string(new_longitude)) << "Longitude should be updated";
    EXPECT_EQ(lat_str, std::to_string(new_latitude)) << "Latitude should be updated";
    EXPECT_EQ(alt_str, std::to_string(new_altitude)) << "Altitude should be updated";
}

TEST_F(FlightGearIntegrationTest, COMRadioStateSync) {
    // Test COM radio state sync
    bool connect_result = mock_flightgear->connect();
    EXPECT_TRUE(connect_result) << "FlightGear connection should succeed";
    
    // Test COM radio state sync
    bool sync_result = mock_flightgear->syncCOMRadioState();
    EXPECT_TRUE(sync_result) << "COM radio state sync should succeed";
    
    // Test COM1 radio state
    mock_flightgear->setCOM1Frequency(test_com1_frequency);
    mock_flightgear->setCOM1PTT(false);
    
    std::string com1_freq, com1_ptt;
    bool com1_freq_read = mock_flightgear->readProperty("/instrumentation/comm[0]/frequencies/selected-mhz", com1_freq);
    bool com1_ptt_read = mock_flightgear->readProperty("/instrumentation/comm[0]/ptt", com1_ptt);
    
    EXPECT_TRUE(com1_freq_read) << "COM1 frequency reading should succeed";
    EXPECT_TRUE(com1_ptt_read) << "COM1 PTT reading should succeed";
    
    EXPECT_EQ(com1_freq, std::to_string(test_com1_frequency)) << "COM1 frequency should match";
    EXPECT_EQ(com1_ptt, "0") << "COM1 PTT should be false";
    
    // Test COM2 radio state
    mock_flightgear->setCOM2Frequency(test_com2_frequency);
    mock_flightgear->setCOM2PTT(false);
    
    std::string com2_freq, com2_ptt;
    bool com2_freq_read = mock_flightgear->readProperty("/instrumentation/comm[1]/frequencies/selected-mhz", com2_freq);
    bool com2_ptt_read = mock_flightgear->readProperty("/instrumentation/comm[1]/ptt", com2_ptt);
    
    EXPECT_TRUE(com2_freq_read) << "COM2 frequency reading should succeed";
    EXPECT_TRUE(com2_ptt_read) << "COM2 PTT reading should succeed";
    
    EXPECT_EQ(com2_freq, std::to_string(test_com2_frequency)) << "COM2 frequency should match";
    EXPECT_EQ(com2_ptt, "0") << "COM2 PTT should be false";
    
    // Test COM radio state changes
    mock_flightgear->setCOM1PTT(true);
    mock_flightgear->setCOM2PTT(true);
    
    bool com1_ptt_activated = mock_flightgear->detectCOM1PTT();
    bool com2_ptt_activated = mock_flightgear->detectCOM2PTT();
    bool ptt_activated = mock_flightgear->detectPTT();
    
    EXPECT_TRUE(com1_ptt_activated) << "COM1 PTT should be activated";
    EXPECT_TRUE(com2_ptt_activated) << "COM2 PTT should be activated";
    EXPECT_TRUE(ptt_activated) << "PTT should be activated";
    
    // Test COM radio state deactivation
    mock_flightgear->setCOM1PTT(false);
    mock_flightgear->setCOM2PTT(false);
    
    bool com1_ptt_deactivated = mock_flightgear->detectCOM1PTT();
    bool com2_ptt_deactivated = mock_flightgear->detectCOM2PTT();
    bool ptt_deactivated = mock_flightgear->detectPTT();
    
    EXPECT_FALSE(com1_ptt_deactivated) << "COM1 PTT should be deactivated";
    EXPECT_FALSE(com2_ptt_deactivated) << "COM2 PTT should be deactivated";
    EXPECT_FALSE(ptt_deactivated) << "PTT should be deactivated";
}

// Additional FlightGear integration tests
TEST_F(FlightGearIntegrationTest, FlightGearPerformance) {
    // Test FlightGear integration performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test connection performance
    for (int i = 0; i < num_operations; ++i) {
        mock_flightgear->connect();
        mock_flightgear->disconnect();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // FlightGear operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "FlightGear operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "FlightGear performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(FlightGearIntegrationTest, FlightGearAccuracy) {
    // Test FlightGear integration accuracy
    bool connect_result = mock_flightgear->connect();
    EXPECT_TRUE(connect_result) << "FlightGear connection should succeed";
    
    // Test position accuracy
    double test_lon = -74.0060, test_lat = 40.7128, test_alt = 1000.0;
    mock_flightgear->setPosition(test_lon, test_lat, test_alt);
    
    std::string lon_str, lat_str, alt_str;
    bool lon_read = mock_flightgear->readProperty("/position/longitude-deg", lon_str);
    bool lat_read = mock_flightgear->readProperty("/position/latitude-deg", lat_str);
    bool alt_read = mock_flightgear->readProperty("/position/altitude-ft", alt_str);
    
    EXPECT_TRUE(lon_read) << "Longitude reading should succeed";
    EXPECT_TRUE(lat_read) << "Latitude reading should succeed";
    EXPECT_TRUE(alt_read) << "Altitude reading should succeed";
    
    EXPECT_EQ(lon_str, std::to_string(test_lon)) << "Longitude should be accurate";
    EXPECT_EQ(lat_str, std::to_string(test_lat)) << "Latitude should be accurate";
    EXPECT_EQ(alt_str, std::to_string(test_alt)) << "Altitude should be accurate";
    
    // Test frequency accuracy
    double test_freq1 = 121.650, test_freq2 = 118.100;
    mock_flightgear->setCOM1Frequency(test_freq1);
    mock_flightgear->setCOM2Frequency(test_freq2);
    
    std::string freq1_str, freq2_str;
    bool freq1_read = mock_flightgear->readProperty("/instrumentation/comm[0]/frequencies/selected-mhz", freq1_str);
    bool freq2_read = mock_flightgear->readProperty("/instrumentation/comm[1]/frequencies/selected-mhz", freq2_str);
    
    EXPECT_TRUE(freq1_read) << "COM1 frequency reading should succeed";
    EXPECT_TRUE(freq2_read) << "COM2 frequency reading should succeed";
    
    EXPECT_EQ(freq1_str, std::to_string(test_freq1)) << "COM1 frequency should be accurate";
    EXPECT_EQ(freq2_str, std::to_string(test_freq2)) << "COM2 frequency should be accurate";
    
    // Test PTT accuracy
    mock_flightgear->setCOM1PTT(true);
    mock_flightgear->setCOM2PTT(false);
    
    bool com1_ptt = mock_flightgear->detectCOM1PTT();
    bool com2_ptt = mock_flightgear->detectCOM2PTT();
    bool ptt = mock_flightgear->detectPTT();
    
    EXPECT_TRUE(com1_ptt) << "COM1 PTT should be accurate";
    EXPECT_FALSE(com2_ptt) << "COM2 PTT should be accurate";
    EXPECT_TRUE(ptt) << "PTT should be accurate";
}

