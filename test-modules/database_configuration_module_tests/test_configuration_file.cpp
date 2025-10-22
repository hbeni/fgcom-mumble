#include "test_database_configuration_main.cpp"

// 10.2 Configuration File Tests
TEST_F(ConfigurationFileTest, INIFileParsing) {
    // Test INI file parsing
    std::map<std::string, std::map<std::string, std::string>> ini_data;
    bool parse_result = mock_ini_parser->parseINIFile(test_ini_file, ini_data);
    EXPECT_TRUE(parse_result) << "INI file parsing should succeed";
    
    // Test that data was parsed correctly
    EXPECT_GT(ini_data.size(), 0) << "INI data should not be empty";
    
    // Test power_management section
    auto power_section = ini_data.find("power_management");
    EXPECT_NE(power_section, ini_data.end()) << "power_management section should exist";
    
    if (power_section != ini_data.end()) {
        auto& power_data = power_section->second;
        EXPECT_EQ(power_data["enable_automatic_power_limiting"], "true") << "Power limiting setting should be correct";
        EXPECT_EQ(power_data["enable_efficiency_optimization"], "true") << "Efficiency optimization setting should be correct";
        EXPECT_EQ(power_data["default_efficiency_threshold"], "0.8") << "Efficiency threshold should be correct";
    }
    
    // Test features section
    auto features_section = ini_data.find("features");
    EXPECT_NE(features_section, ini_data.end()) << "features section should exist";
    
    if (features_section != ini_data.end()) {
        auto& features_data = features_section->second;
        EXPECT_EQ(features_data["enable_advanced_audio_processing"], "true") << "Audio processing setting should be correct";
        EXPECT_EQ(features_data["enable_gpu_acceleration"], "false") << "GPU acceleration setting should be correct";
        EXPECT_EQ(features_data["enable_terrain_integration"], "true") << "Terrain integration setting should be correct";
    }
}

TEST_F(ConfigurationFileTest, SectionHandling) {
    // Test section handling
    std::string section_line = "[power_management]";
    std::string current_section = "";
    bool section_result = mock_ini_parser->handleSections(section_line, current_section);
    EXPECT_TRUE(section_result) << "Section line should be handled";
    EXPECT_EQ(current_section, "power_management") << "Section name should be extracted correctly";
    
    // Test invalid section line
    std::string invalid_section_line = "power_management";
    std::string invalid_section = "";
    bool invalid_section_result = mock_ini_parser->handleSections(invalid_section_line, invalid_section);
    EXPECT_FALSE(invalid_section_result) << "Invalid section line should be rejected";
    
    // Test empty section line
    std::string empty_section_line = "";
    std::string empty_section = "";
    bool empty_section_result = mock_ini_parser->handleSections(empty_section_line, empty_section);
    EXPECT_FALSE(empty_section_result) << "Empty section line should be rejected";
    
    // Test section with spaces
    std::string spaced_section_line = "[ power_management ]";
    std::string spaced_section = "";
    bool spaced_section_result = mock_ini_parser->handleSections(spaced_section_line, spaced_section);
    EXPECT_TRUE(spaced_section_result) << "Section with spaces should be handled";
    EXPECT_EQ(spaced_section, " power_management ") << "Section name with spaces should be extracted";
    
    // Test nested section (not supported in standard INI)
    std::string nested_section_line = "[power_management.subsection]";
    std::string nested_section = "";
    bool nested_section_result = mock_ini_parser->handleSections(nested_section_line, nested_section);
    EXPECT_TRUE(nested_section_result) << "Nested section should be handled";
    EXPECT_EQ(nested_section, "power_management.subsection") << "Nested section name should be extracted";
}

TEST_F(ConfigurationFileTest, KeyValuePairExtraction) {
    // Test key-value pair extraction
    std::string key_value_line = "enable_automatic_power_limiting=true";
    std::string key, value;
    bool extraction_result = mock_ini_parser->extractKeyValuePair(key_value_line, key, value);
    EXPECT_TRUE(extraction_result) << "Key-value pair extraction should succeed";
    EXPECT_EQ(key, "enable_automatic_power_limiting") << "Key should be extracted correctly";
    EXPECT_EQ(value, "true") << "Value should be extracted correctly";
    
    // Test key-value pair with spaces
    std::string spaced_line = "enable_automatic_power_limiting = true";
    std::string spaced_key, spaced_value;
    bool spaced_result = mock_ini_parser->extractKeyValuePair(spaced_line, spaced_key, spaced_value);
    EXPECT_TRUE(spaced_result) << "Key-value pair with spaces should be extracted";
    EXPECT_EQ(spaced_key, "enable_automatic_power_limiting") << "Key with spaces should be extracted correctly";
    EXPECT_EQ(spaced_value, "true") << "Value with spaces should be extracted correctly";
    
    // Test key-value pair with tabs
    std::string tabbed_line = "enable_automatic_power_limiting\t=\ttrue";
    std::string tabbed_key, tabbed_value;
    bool tabbed_result = mock_ini_parser->extractKeyValuePair(tabbed_line, tabbed_key, tabbed_value);
    EXPECT_TRUE(tabbed_result) << "Key-value pair with tabs should be extracted";
    EXPECT_EQ(tabbed_key, "enable_automatic_power_limiting") << "Key with tabs should be extracted correctly";
    EXPECT_EQ(tabbed_value, "true") << "Value with tabs should be extracted correctly";
    
    // Test invalid key-value pair
    std::string invalid_line = "enable_automatic_power_limiting";
    std::string invalid_key, invalid_value;
    bool invalid_result = mock_ini_parser->extractKeyValuePair(invalid_line, invalid_key, invalid_value);
    EXPECT_FALSE(invalid_result) << "Invalid key-value pair should be rejected";
    
    // Test empty key-value pair
    std::string empty_line = "";
    std::string empty_key, empty_value;
    bool empty_result = mock_ini_parser->extractKeyValuePair(empty_line, empty_key, empty_value);
    EXPECT_FALSE(empty_result) << "Empty key-value pair should be rejected";
}

TEST_F(ConfigurationFileTest, CommentHandling) {
    // Test comment handling
    std::string hash_comment = "# This is a comment";
    bool hash_result = mock_ini_parser->handleComments(hash_comment);
    EXPECT_TRUE(hash_result) << "Hash comment should be handled";
    
    std::string semicolon_comment = "; This is also a comment";
    bool semicolon_result = mock_ini_parser->handleComments(semicolon_comment);
    EXPECT_TRUE(semicolon_result) << "Semicolon comment should be handled";
    
    std::string empty_line = "";
    bool empty_result = mock_ini_parser->handleComments(empty_line);
    EXPECT_TRUE(empty_result) << "Empty line should be handled";
    
    std::string data_line = "enable_automatic_power_limiting=true";
    bool data_result = mock_ini_parser->handleComments(data_line);
    EXPECT_FALSE(data_result) << "Data line should not be handled as comment";
    
    std::string mixed_line = "enable_automatic_power_limiting=true # This is a comment";
    bool mixed_result = mock_ini_parser->handleComments(mixed_line);
    EXPECT_FALSE(mixed_result) << "Mixed line should not be handled as comment";
    
    std::string whitespace_comment = "   # This is a comment with leading whitespace";
    bool whitespace_result = mock_ini_parser->handleComments(whitespace_comment);
    EXPECT_FALSE(whitespace_result) << "Whitespace comment should not be handled";
}

TEST_F(ConfigurationFileTest, DefaultValueHandling) {
    // Test default value handling
    std::map<std::string, std::string> defaults = {
        {"enable_automatic_power_limiting", "false"},
        {"enable_efficiency_optimization", "false"},
        {"default_efficiency_threshold", "0.5"}
    };
    
    // Test existing key
    std::string existing_key = "enable_automatic_power_limiting";
    std::string existing_value = mock_ini_parser->getDefaultValue(existing_key, defaults);
    EXPECT_EQ(existing_value, "false") << "Existing key should return default value";
    
    // Test non-existing key
    std::string non_existing_key = "non_existing_key";
    std::string non_existing_value = mock_ini_parser->getDefaultValue(non_existing_key, defaults);
    EXPECT_EQ(non_existing_value, "") << "Non-existing key should return empty string";
    
    // Test empty key
    std::string empty_key = "";
    std::string empty_value = mock_ini_parser->getDefaultValue(empty_key, defaults);
    EXPECT_EQ(empty_value, "") << "Empty key should return empty string";
    
    // Test empty defaults
    std::map<std::string, std::string> empty_defaults;
    std::string empty_defaults_value = mock_ini_parser->getDefaultValue("any_key", empty_defaults);
    EXPECT_EQ(empty_defaults_value, "") << "Empty defaults should return empty string";
}

TEST_F(ConfigurationFileTest, InvalidSyntaxHandling) {
    // Test invalid syntax handling
    std::string valid_line = "enable_automatic_power_limiting=true";
    bool valid_result = mock_ini_parser->handleInvalidSyntax(valid_line);
    EXPECT_TRUE(valid_result) << "Valid line should be accepted";
    
    std::string invalid_line = "enable_automatic_power_limiting";
    bool invalid_result = mock_ini_parser->handleInvalidSyntax(invalid_line);
    EXPECT_FALSE(invalid_result) << "Invalid line should be rejected";
    
    std::string empty_line = "";
    bool empty_result = mock_ini_parser->handleInvalidSyntax(empty_line);
    EXPECT_TRUE(empty_result) << "Empty line should be accepted";
    
    std::string comment_line = "# This is a comment";
    bool comment_result = mock_ini_parser->handleInvalidSyntax(comment_line);
    EXPECT_TRUE(comment_result) << "Comment line should be accepted";
    
    std::string section_line = "[power_management]";
    bool section_result = mock_ini_parser->handleInvalidSyntax(section_line);
    EXPECT_TRUE(section_result) << "Section line should be accepted";
    
    std::string malformed_line = "enable_automatic_power_limiting=true=extra";
    bool malformed_result = mock_ini_parser->handleInvalidSyntax(malformed_line);
    EXPECT_TRUE(malformed_result) << "Malformed line should be accepted";
    
    std::string whitespace_line = "   enable_automatic_power_limiting   =   true   ";
    bool whitespace_result = mock_ini_parser->handleInvalidSyntax(whitespace_line);
    EXPECT_TRUE(whitespace_result) << "Whitespace line should be accepted";
}

// Additional configuration file tests
TEST_F(ConfigurationFileTest, ConfigurationFilePerformance) {
    // Test configuration file parsing performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test INI parsing performance
    for (int i = 0; i < num_operations; ++i) {
        std::map<std::string, std::map<std::string, std::string>> ini_data;
        mock_ini_parser->parseINIFile(test_ini_file, ini_data);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Configuration file parsing operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Configuration file parsing operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Configuration file parsing performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(ConfigurationFileTest, ConfigurationFileAccuracy) {
    // Test configuration file parsing accuracy
    std::map<std::string, std::map<std::string, std::string>> ini_data;
    bool parse_result = mock_ini_parser->parseINIFile(test_ini_file, ini_data);
    EXPECT_TRUE(parse_result) << "INI parsing should be accurate";
    
    // Test data accuracy
    EXPECT_GT(ini_data.size(), 0) << "INI data should be accurate";
    
    // Test section accuracy
    auto power_section = ini_data.find("power_management");
    EXPECT_NE(power_section, ini_data.end()) << "power_management section should be accurate";
    
    if (power_section != ini_data.end()) {
        auto& power_data = power_section->second;
        EXPECT_EQ(power_data["enable_automatic_power_limiting"], "true") << "Power limiting setting should be accurate";
        EXPECT_EQ(power_data["enable_efficiency_optimization"], "true") << "Efficiency optimization setting should be accurate";
        EXPECT_EQ(power_data["default_efficiency_threshold"], "0.8") << "Efficiency threshold should be accurate";
    }
    
    // Test key-value extraction accuracy
    std::string key_value_line = "enable_automatic_power_limiting=true";
    std::string key, value;
    bool extraction_result = mock_ini_parser->extractKeyValuePair(key_value_line, key, value);
    EXPECT_TRUE(extraction_result) << "Key-value extraction should be accurate";
    EXPECT_EQ(key, "enable_automatic_power_limiting") << "Key extraction should be accurate";
    EXPECT_EQ(value, "true") << "Value extraction should be accurate";
    
    // Test comment handling accuracy
    std::string comment_line = "# This is a comment";
    bool comment_result = mock_ini_parser->handleComments(comment_line);
    EXPECT_TRUE(comment_result) << "Comment handling should be accurate";
    
    // Test default value accuracy
    std::map<std::string, std::string> defaults = {
        {"enable_automatic_power_limiting", "false"},
        {"enable_efficiency_optimization", "false"},
        {"default_efficiency_threshold", "0.5"}
    };
    std::string default_value = mock_ini_parser->getDefaultValue("enable_automatic_power_limiting", defaults);
    EXPECT_EQ(default_value, "false") << "Default value should be accurate";
}

