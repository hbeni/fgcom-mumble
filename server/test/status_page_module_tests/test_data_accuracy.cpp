#include "test_status_page_main.cpp"

// 13.2 Data Accuracy Tests
TEST_F(DataAccuracyTest, ClientCountAccuracy) {
    // Test client count accuracy
    int expected_count = test_clients.size();
    EXPECT_EQ(expected_count, 10) << "Expected client count should be 10";
    
    // Test client count validation
    for (const auto& client : test_clients) {
        bool is_valid = mock_data_validator->validateClientData(client);
        EXPECT_TRUE(is_valid) << "Client data should be valid";
    }
    
    // Test client count with different datasets (reduced for test stability)
    std::vector<int> test_counts = {0, 1, 5, 10, 50};
    for (int count : test_counts) {
        std::vector<std::map<std::string, std::string>> test_data = generateTestClients(count);
        EXPECT_EQ(test_data.size(), count) << "Generated client count should match expected count";
        
        // Test client data validation for each count
        for (const auto& client : test_data) {
            bool is_valid = mock_data_validator->validateClientData(client);
            EXPECT_TRUE(is_valid) << "Client data should be valid for count " << count;
        }
    }
    
    // Test client count accuracy with invalid data
    std::map<std::string, std::string> invalid_client;
    invalid_client["callsign"] = "";
    invalid_client["lat"] = "invalid";
    invalid_client["lon"] = "invalid";
    invalid_client["alt"] = "invalid";
    invalid_client["frequency"] = "invalid";
    
    bool is_invalid = mock_data_validator->validateClientData(invalid_client);
    EXPECT_FALSE(is_invalid) << "Invalid client data should be rejected";
    
    // Test client count accuracy with missing fields
    std::map<std::string, std::string> missing_fields_client;
    missing_fields_client["callsign"] = "TEST";
    // Missing lat, lon, alt, frequency
    
    bool is_missing_fields = mock_data_validator->validateClientData(missing_fields_client);
    EXPECT_FALSE(is_missing_fields) << "Client data with missing fields should be rejected";
}

TEST_F(DataAccuracyTest, PositionAccuracyOnMap) {
    // Test position accuracy on map
    for (const auto& marker : test_map_data) {
        double lat = std::stod(marker.at("lat"));
        double lon = std::stod(marker.at("lon"));
        
        bool is_valid_position = mock_data_validator->validatePositionData(lat, lon, 1000.0);
        EXPECT_TRUE(is_valid_position) << "Position data should be valid";
    }
    
    // Test position accuracy with different coordinates
    std::vector<std::pair<double, double>> test_coordinates = {
        {0.0, 0.0},      // Equator, Prime Meridian
        {90.0, 0.0},     // North Pole
        {-90.0, 0.0},    // South Pole
        {0.0, 180.0},    // Equator, International Date Line
        {0.0, -180.0},   // Equator, International Date Line
        {45.0, -90.0},   // North America
        {-45.0, 90.0},   // Australia
        {60.0, 30.0},    // Europe
        {-30.0, -60.0}   // South America
    };
    
    for (const auto& coord : test_coordinates) {
        bool is_valid_position = mock_data_validator->validatePositionData(coord.first, coord.second, 1000.0);
        EXPECT_TRUE(is_valid_position) << "Position data should be valid for " << coord.first << ", " << coord.second;
    }
    
    // Test position accuracy with invalid coordinates
    std::vector<std::tuple<double, double, double>> invalid_coordinates = {
        {91.0, 0.0, 1000.0},    // Invalid latitude
        {-91.0, 0.0, 1000.0},   // Invalid latitude
        {0.0, 181.0, 1000.0},   // Invalid longitude
        {0.0, -181.0, 1000.0},  // Invalid longitude
        {0.0, 0.0, -1000.0},    // Invalid altitude
        {0.0, 0.0, 200000.0}    // Invalid altitude
    };
    
    for (const auto& coord : invalid_coordinates) {
        bool is_invalid_position = mock_data_validator->validatePositionData(
            std::get<0>(coord), std::get<1>(coord), std::get<2>(coord));
        EXPECT_FALSE(is_invalid_position) << "Invalid position data should be rejected";
    }
    
    // Test position accuracy with edge cases
    std::vector<std::tuple<double, double, double>> edge_cases = {
        {90.0, 0.0, 0.0},       // North Pole, sea level
        {-90.0, 0.0, 0.0},      // South Pole, sea level
        {0.0, 180.0, 0.0},      // International Date Line, sea level
        {0.0, -180.0, 0.0},     // International Date Line, sea level
        {0.0, 0.0, 0.0},        // Equator, Prime Meridian, sea level
        {0.0, 0.0, 100000.0}    // Equator, Prime Meridian, high altitude
    };
    
    for (const auto& coord : edge_cases) {
        bool is_valid_position = mock_data_validator->validatePositionData(
            std::get<0>(coord), std::get<1>(coord), std::get<2>(coord));
        EXPECT_TRUE(is_valid_position) << "Edge case position data should be valid";
    }
}

TEST_F(DataAccuracyTest, FrequencyAccuracy) {
    // Test frequency accuracy
    for (const auto& frequency : test_frequencies) {
        double freq = std::stod(frequency.at("frequency"));
        bool is_valid_frequency = mock_data_validator->validateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Frequency data should be valid";
    }
    
    // Test frequency accuracy with different frequency ranges
    std::vector<double> test_frequencies = {
        0.0,      // DC
        1.0,      // Very low frequency
        10.0,     // Low frequency
        100.0,    // Medium frequency
        1000.0,   // High frequency
        10000.0   // Very high frequency
    };
    
    for (double freq : test_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Frequency data should be valid for " << freq;
    }
    
    // Test frequency accuracy with invalid frequencies
    std::vector<double> invalid_frequencies = {
        -1.0,     // Negative frequency
        10001.0,  // Too high
        std::numeric_limits<double>::infinity(),  // Infinity
        std::numeric_limits<double>::quiet_NaN()  // NaN
    };
    
    for (double freq : invalid_frequencies) {
        bool is_invalid_frequency = mock_data_validator->validateFrequency(freq);
        EXPECT_FALSE(is_invalid_frequency) << "Invalid frequency data should be rejected";
    }
    
    // Test frequency accuracy with aviation frequencies
    std::vector<double> aviation_frequencies = {
        121.5,    // Emergency frequency
        243.0,    // Military emergency frequency
        118.0,    // ATC frequency
        137.0,    // ATC frequency
        108.0,    // Navigation frequency
        118.0     // Navigation frequency
    };
    
    for (double freq : aviation_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Aviation frequency data should be valid for " << freq;
    }
    
    // Test frequency accuracy with amateur radio frequencies
    std::vector<double> amateur_frequencies = {
        144.0,    // 2m band
        430.0,    // 70cm band
        50.0,     // 6m band
        28.0,     // 10m band
        14.0,     // 20m band
        7.0       // 40m band
    };
    
    for (double freq : amateur_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Amateur radio frequency data should be valid for " << freq;
    }
}

TEST_F(DataAccuracyTest, ConnectionStateAccuracy) {
    // Test connection state accuracy
    std::vector<std::string> valid_states = {"connected", "disconnected", "connecting", "error"};
    
    for (const auto& state : valid_states) {
        bool is_valid_state = mock_data_validator->validateConnectionState(state);
        EXPECT_TRUE(is_valid_state) << "Connection state should be valid for " << state;
    }
    
    // Test connection state accuracy with invalid states
    std::vector<std::string> invalid_states = {
        "",           // Empty state
        "invalid",    // Invalid state
        "CONNECTED",  // Wrong case
        "disconnect", // Partial match
        "error_state" // Invalid format
    };
    
    for (const auto& state : invalid_states) {
        bool is_invalid_state = mock_data_validator->validateConnectionState(state);
        EXPECT_FALSE(is_invalid_state) << "Invalid connection state should be rejected for " << state;
    }
    
    // Test connection state accuracy with case sensitivity
    std::vector<std::string> case_sensitive_states = {
        "Connected",  // Wrong case
        "DISCONNECTED", // Wrong case
        "Connecting", // Wrong case
        "Error"      // Wrong case
    };
    
    for (const auto& state : case_sensitive_states) {
        bool is_invalid_state = mock_data_validator->validateConnectionState(state);
        EXPECT_FALSE(is_invalid_state) << "Case sensitive connection state should be rejected for " << state;
    }
    
    // Test connection state accuracy with whitespace
    std::vector<std::string> whitespace_states = {
        " connected",   // Leading space
        "connected ",   // Trailing space
        " connected ",  // Both spaces
        "\tconnected",  // Tab character
        "connected\n"  // Newline character
    };
    
    for (const auto& state : whitespace_states) {
        bool is_invalid_state = mock_data_validator->validateConnectionState(state);
        EXPECT_FALSE(is_invalid_state) << "Whitespace connection state should be rejected for " << state;
    }
}

TEST_F(DataAccuracyTest, UpdateFrequency) {
    // Test update frequency accuracy
    std::vector<int> valid_frequencies = {1, 5, 10, 25, 50, 100};
    
    for (int freq : valid_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateUpdateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Update frequency should be valid for " << freq;
    }
    
    // Test update frequency accuracy with invalid frequencies
    std::vector<int> invalid_frequencies = {
        0,      // Zero frequency
        -1,     // Negative frequency
        101,    // Too high frequency
        1000,   // Very high frequency
        10000   // Extremely high frequency
    };
    
    for (int freq : invalid_frequencies) {
        bool is_invalid_frequency = mock_data_validator->validateUpdateFrequency(freq);
        EXPECT_FALSE(is_invalid_frequency) << "Invalid update frequency should be rejected for " << freq;
    }
    
    // Test update frequency accuracy with edge cases
    std::vector<int> edge_cases = {
        1,      // Minimum valid frequency
        100,    // Maximum valid frequency
        50,     // Middle frequency
        25,     // Quarter frequency
        75      // Three quarter frequency
    };
    
    for (int freq : edge_cases) {
        bool is_valid_frequency = mock_data_validator->validateUpdateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Edge case update frequency should be valid for " << freq;
    }
    
    // Test update frequency accuracy with real-time requirements
    std::vector<int> real_time_frequencies = {
        1,      // 1 Hz - Very slow updates
        10,     // 10 Hz - Slow updates
        25,     // 25 Hz - Medium updates
        50,     // 50 Hz - Fast updates
        100     // 100 Hz - Very fast updates
    };
    
    for (int freq : real_time_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateUpdateFrequency(freq);
        EXPECT_TRUE(is_valid_frequency) << "Real-time update frequency should be valid for " << freq;
    }
}

// Additional data accuracy tests
TEST_F(DataAccuracyTest, DataAccuracyPerformance) {
    // Test data accuracy performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test data validation performance
    for (int i = 0; i < num_operations; ++i) {
        for (const auto& client : test_clients) {
            mock_data_validator->validateClientData(client);
        }
        for (const auto& frequency : test_frequencies) {
            mock_data_validator->validateFrequencyData(frequency);
        }
        mock_data_validator->validatePositionData(40.0, -74.0, 1000.0);
        mock_data_validator->validateFrequency(144.0);
        mock_data_validator->validateConnectionState("connected");
        mock_data_validator->validateUpdateFrequency(10);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Data validation operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Data validation operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Data accuracy performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(DataAccuracyTest, DataAccuracyComprehensive) {
    // Test comprehensive data accuracy
    std::vector<std::map<std::string, std::string>> comprehensive_clients = generateTestClients(100);
    std::vector<std::map<std::string, std::string>> comprehensive_frequencies = generateTestFrequencies(50);
    std::vector<std::map<std::string, std::string>> comprehensive_map_data = generateTestMapData(100);
    
    // Test client data accuracy
    for (const auto& client : comprehensive_clients) {
        bool is_valid_client = mock_data_validator->validateClientData(client);
        EXPECT_TRUE(is_valid_client) << "Comprehensive client data should be valid";
    }
    
    // Test frequency data accuracy
    for (const auto& frequency : comprehensive_frequencies) {
        bool is_valid_frequency = mock_data_validator->validateFrequencyData(frequency);
        EXPECT_TRUE(is_valid_frequency) << "Comprehensive frequency data should be valid";
    }
    
    // Test map data accuracy
    for (const auto& marker : comprehensive_map_data) {
        double lat = std::stod(marker.at("lat"));
        double lon = std::stod(marker.at("lon"));
        bool is_valid_position = mock_data_validator->validatePositionData(lat, lon, 1000.0);
        EXPECT_TRUE(is_valid_position) << "Comprehensive map data should be valid";
    }
    
    // Test data accuracy with mixed valid and invalid data
    std::vector<std::map<std::string, std::string>> mixed_clients;
    
    // Add valid clients
    for (int i = 0; i < 50; ++i) {
        mixed_clients.push_back(comprehensive_clients[i]);
    }
    
    // Add invalid clients
    for (int i = 0; i < 10; ++i) {
        std::map<std::string, std::string> invalid_client;
        invalid_client["callsign"] = "";
        invalid_client["lat"] = "invalid";
        invalid_client["lon"] = "invalid";
        invalid_client["alt"] = "invalid";
        invalid_client["frequency"] = "invalid";
        mixed_clients.push_back(invalid_client);
    }
    
    // Test mixed data accuracy
    int valid_count = 0;
    int invalid_count = 0;
    
    for (const auto& client : mixed_clients) {
        bool is_valid = mock_data_validator->validateClientData(client);
        if (is_valid) {
            valid_count++;
        } else {
            invalid_count++;
        }
    }
    
    EXPECT_EQ(valid_count, 50) << "Should have 50 valid clients";
    EXPECT_EQ(invalid_count, 10) << "Should have 10 invalid clients";
    
    // Test data accuracy with edge cases
    std::vector<std::map<std::string, std::string>> edge_case_clients;
    
    // Edge case 1: Minimum valid values
    std::map<std::string, std::string> min_client;
    min_client["callsign"] = "A";
    min_client["lat"] = "-90.0";
    min_client["lon"] = "-180.0";
    min_client["alt"] = "0.0";
    min_client["frequency"] = "0.0";
    edge_case_clients.push_back(min_client);
    
    // Edge case 2: Maximum valid values
    std::map<std::string, std::string> max_client;
    max_client["callsign"] = "ZZZZZZZZ";
    max_client["lat"] = "90.0";
    max_client["lon"] = "180.0";
    max_client["alt"] = "100000.0";
    max_client["frequency"] = "10000.0";
    edge_case_clients.push_back(max_client);
    
    // Test edge case data accuracy
    for (const auto& client : edge_case_clients) {
        bool is_valid = mock_data_validator->validateClientData(client);
        EXPECT_TRUE(is_valid) << "Edge case client data should be valid";
    }
}

