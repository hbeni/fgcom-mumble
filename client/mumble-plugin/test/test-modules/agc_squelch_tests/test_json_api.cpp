#include "test_agc_squelch_main.cpp"

// 1.10 JSON API Tests
TEST_F(JSONAPITest, ValidJSONParsing) {
    // Test valid JSON parsing for AGC configuration
    std::string valid_agc_json = R"({
        "mode": "FAST",
        "threshold_db": -50.0,
        "max_gain_db": 30.0,
        "min_gain_db": -15.0,
        "attack_time_ms": 2.0,
        "release_time_ms": 200.0
    })";
    
    bool result = agc->updateAGCFromJSON(valid_agc_json);
    EXPECT_TRUE(result) << "Failed to parse valid AGC JSON";
    
    // Verify configuration was actually applied
    AGCConfig config = agc->getAGCConfig();
    EXPECT_EQ(config.mode, AGCMode::FAST);
    EXPECT_FLOAT_EQ(config.threshold_db, -50.0f);
    EXPECT_FLOAT_EQ(config.max_gain_db, 30.0f);
    EXPECT_FLOAT_EQ(config.min_gain_db, -15.0f);
    EXPECT_FLOAT_EQ(config.attack_time_ms, 2.0f);
    EXPECT_FLOAT_EQ(config.release_time_ms, 200.0f);
}

TEST_F(JSONAPITest, ValidSquelchJSONParsing) {
    // Test valid JSON parsing for Squelch configuration
    std::string valid_squelch_json = R"({
        "enabled": true,
        "threshold_db": -70.0,
        "hysteresis_db": 5.0,
        "attack_time_ms": 15.0,
        "release_time_ms": 100.0,
        "tone_squelch": true,
        "tone_frequency_hz": 1500.0,
        "noise_squelch": true,
        "noise_threshold_db": -65.0
    })";
    
    bool result = agc->updateSquelchFromJSON(valid_squelch_json);
    EXPECT_TRUE(result) << "Failed to parse valid Squelch JSON";
    
    // Verify configuration was actually applied
    SquelchConfig config = agc->getSquelchConfig();
    EXPECT_TRUE(config.enabled);
    EXPECT_FLOAT_EQ(config.threshold_db, -70.0f);
    EXPECT_FLOAT_EQ(config.hysteresis_db, 5.0f);
    EXPECT_FLOAT_EQ(config.attack_time_ms, 15.0f);
    EXPECT_FLOAT_EQ(config.release_time_ms, 100.0f);
    EXPECT_TRUE(config.tone_squelch);
    EXPECT_FLOAT_EQ(config.tone_frequency_hz, 1500.0f);
    EXPECT_TRUE(config.noise_squelch);
    EXPECT_FLOAT_EQ(config.noise_threshold_db, -65.0f);
}

TEST_F(JSONAPITest, InvalidJSONHandling) {
    // Test handling of invalid JSON
    std::vector<std::string> invalid_json_cases = {
        "",  // Empty string
        "invalid json",  // Invalid syntax
        "{",  // Incomplete JSON
        "{\"mode\": \"INVALID\"}",  // Invalid enum value
        "{\"threshold_db\": \"not_a_number\"}",  // Wrong type
        "{\"mode\": 123}",  // Wrong type for enum
        "{\"threshold_db\": null}",  // Null value
        "{\"threshold_db\": undefined}"  // Undefined value
    };
    
    for (const auto& invalid_json : invalid_json_cases) {
        bool agc_result = agc->updateAGCFromJSON(invalid_json);
        bool squelch_result = agc->updateSquelchFromJSON(invalid_json);
        
        // Should handle invalid JSON gracefully
        EXPECT_FALSE(agc_result) << "Should reject invalid AGC JSON: " << invalid_json;
        EXPECT_FALSE(squelch_result) << "Should reject invalid Squelch JSON: " << invalid_json;
    }
}

TEST_F(JSONAPITest, MalformedJSONHandling) {
    // Test handling of malformed JSON
    std::vector<std::string> malformed_json_cases = {
        "{invalid json}",  // Missing quotes
        "{\"mode\": FAST}",  // Missing quotes around value
        "{\"threshold_db\": -50.0,}",  // Trailing comma
        "{\"mode\": \"FAST\" \"threshold_db\": -50.0}",  // Missing comma
        "{\"mode\": \"FAST\", \"threshold_db\": -50.0,}",  // Trailing comma
        "{\"mode\": \"FAST\", \"threshold_db\": -50.0, \"extra_field\": 123}"  // Extra field
    };
    
    for (const auto& malformed_json : malformed_json_cases) {
        bool agc_result = agc->updateAGCFromJSON(malformed_json);
        bool squelch_result = agc->updateSquelchFromJSON(malformed_json);
        
        // Should handle malformed JSON gracefully
        EXPECT_FALSE(agc_result) << "Should reject malformed AGC JSON: " << malformed_json;
        EXPECT_FALSE(squelch_result) << "Should reject malformed Squelch JSON: " << malformed_json;
    }
}

TEST_F(JSONAPITest, MissingFieldsHandling) {
    // Test handling of missing fields
    std::string partial_agc_json = R"({
        "mode": "MEDIUM"
    })";
    
    bool result = agc->updateAGCFromJSON(partial_agc_json);
    
    // Should handle partial JSON (use defaults for missing fields)
    if (result) {
        AGCConfig config = agc->getAGCConfig();
        EXPECT_EQ(config.mode, AGCMode::MEDIUM);
        // Other fields should retain their default values
    }
}

TEST_F(JSONAPITest, ExtraFieldsHandling) {
    // Test handling of extra fields
    std::string extra_fields_json = R"({
        "mode": "SLOW",
        "threshold_db": -60.0,
        "extra_field1": "ignored",
        "extra_field2": 123,
        "extra_field3": true
    })";
    
    bool result = agc->updateAGCFromJSON(extra_fields_json);
    
    // Should handle extra fields gracefully
    if (result) {
        AGCConfig config = agc->getAGCConfig();
        EXPECT_EQ(config.mode, AGCMode::SLOW);
        EXPECT_FLOAT_EQ(config.threshold_db, -60.0f);
    }
}

TEST_F(JSONAPITest, TypeMismatchHandling) {
    // Test handling of type mismatches
    std::vector<std::string> type_mismatch_cases = {
        "{\"mode\": 123}",  // Number instead of string
        "{\"threshold_db\": \"not_a_number\"}",  // String instead of number
        "{\"attack_time_ms\": true}",  // Boolean instead of number
        "{\"enabled\": \"yes\"}",  // String instead of boolean
        "{\"mode\": [\"FAST\"]}",  // Array instead of string
        "{\"threshold_db\": {}}",  // Object instead of number
    };
    
    for (const auto& type_mismatch_json : type_mismatch_cases) {
        bool agc_result = agc->updateAGCFromJSON(type_mismatch_json);
        bool squelch_result = agc->updateSquelchFromJSON(type_mismatch_json);
        
        // Should handle type mismatches gracefully
        EXPECT_FALSE(agc_result) << "Should reject type mismatch in AGC JSON: " << type_mismatch_json;
        EXPECT_FALSE(squelch_result) << "Should reject type mismatch in Squelch JSON: " << type_mismatch_json;
    }
}

TEST_F(JSONAPITest, JSONStatusExportAccuracy) {
    // Test JSON status export accuracy
    // Set specific configuration
    AGCConfig agc_config;
    agc_config.mode = AGCMode::FAST;
    agc_config.threshold_db = -45.0f;
    agc_config.max_gain_db = 25.0f;
    agc_config.min_gain_db = -10.0f;
    agc_config.attack_time_ms = 1.5f;
    agc_config.release_time_ms = 150.0f;
    
    agc->setAGCConfig(agc_config);
    
    // Export status to JSON
    std::string agc_status_json = agc->getAGCStatusJSON();
    std::string squelch_status_json = agc->getSquelchStatusJSON();
    
    // JSON should not be empty
    EXPECT_FALSE(agc_status_json.empty()) << "AGC status JSON should not be empty";
    EXPECT_FALSE(squelch_status_json.empty()) << "Squelch status JSON should not be empty";
    
    // JSON should contain expected fields
    EXPECT_TRUE(agc_status_json.find("mode") != std::string::npos) << "AGC JSON should contain mode";
    EXPECT_TRUE(agc_status_json.find("threshold_db") != std::string::npos) << "AGC JSON should contain threshold_db";
    EXPECT_TRUE(squelch_status_json.find("enabled") != std::string::npos) << "Squelch JSON should contain enabled";
    EXPECT_TRUE(squelch_status_json.find("threshold_db") != std::string::npos) << "Squelch JSON should contain threshold_db";
}

TEST_F(JSONAPITest, RoundTripJSONExportImport) {
    // Test round-trip JSON export/import
    // Set initial configuration
    AGCConfig initial_config;
    initial_config.mode = AGCMode::MEDIUM;
    initial_config.threshold_db = -55.0f;
    initial_config.max_gain_db = 35.0f;
    initial_config.min_gain_db = -25.0f;
    initial_config.attack_time_ms = 3.0f;
    initial_config.release_time_ms = 300.0f;
    
    agc->setAGCConfig(initial_config);
    
    // Export to JSON
    std::string exported_json = agc->getAGCStatusJSON();
    EXPECT_FALSE(exported_json.empty()) << "Exported JSON should not be empty";
    
    // Change configuration
    AGCConfig changed_config;
    changed_config.mode = AGCMode::SLOW;
    changed_config.threshold_db = -65.0f;
    agc->setAGCConfig(changed_config);
    
    // Import from JSON
    bool import_result = agc->updateAGCFromJSON(exported_json);
    EXPECT_TRUE(import_result) << "Should successfully import exported JSON";
    
    // Verify configuration was restored
    AGCConfig restored_config = agc->getAGCConfig();
    EXPECT_EQ(restored_config.mode, initial_config.mode);
    EXPECT_FLOAT_EQ(restored_config.threshold_db, initial_config.threshold_db);
    EXPECT_FLOAT_EQ(restored_config.max_gain_db, initial_config.max_gain_db);
    EXPECT_FLOAT_EQ(restored_config.min_gain_db, initial_config.min_gain_db);
    EXPECT_FLOAT_EQ(restored_config.attack_time_ms, initial_config.attack_time_ms);
    EXPECT_FLOAT_EQ(restored_config.release_time_ms, initial_config.release_time_ms);
}

// Additional JSON API tests
TEST_F(JSONAPITest, JSONParsingPerformance) {
    // Test JSON parsing performance
    std::string test_json = R"({
        "mode": "FAST",
        "threshold_db": -50.0,
        "max_gain_db": 30.0,
        "min_gain_db": -15.0,
        "attack_time_ms": 2.0,
        "release_time_ms": 200.0
    })";
    
    const int iterations = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        agc->updateAGCFromJSON(test_json);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // JSON parsing should be fast
    double time_per_parse = static_cast<double>(duration.count()) / iterations;
    EXPECT_LT(time_per_parse, 1000.0) << "JSON parsing too slow: " << time_per_parse << " microseconds per parse";
    
    std::cout << "JSON parsing performance: " << time_per_parse << " microseconds per parse" << std::endl;
}

TEST_F(JSONAPITest, JSONParsingWithUnicode) {
    // Test JSON parsing with Unicode characters
    std::string unicode_json = R"({
        "mode": "FAST",
        "threshold_db": -50.0,
        "comment": "测试中文",
        "description": "Test with émojis 🎵🎶"
    })";
    
    bool result = agc->updateAGCFromJSON(unicode_json);
    
    // Should handle Unicode gracefully
    if (result) {
        AGCConfig config = agc->getAGCConfig();
        EXPECT_EQ(config.mode, AGCMode::FAST);
        EXPECT_FLOAT_EQ(config.threshold_db, -50.0f);
    }
}

TEST_F(JSONAPITest, JSONParsingWithLargeValues) {
    // Test JSON parsing with large values
    std::string large_values_json = R"({
        "mode": "FAST",
        "threshold_db": -999.999,
        "max_gain_db": 999.999,
        "min_gain_db": -999.999,
        "attack_time_ms": 999.999,
        "release_time_ms": 999999.999
    })";
    
    bool result = agc->updateAGCFromJSON(large_values_json);
    
    // Should handle large values (clamping should occur)
    if (result) {
        AGCConfig config = agc->getAGCConfig();
        EXPECT_EQ(config.mode, AGCMode::FAST);
        // Values should be clamped to valid ranges
        EXPECT_GE(config.threshold_db, -100.0f);
        EXPECT_LE(config.threshold_db, 0.0f);
        EXPECT_GE(config.max_gain_db, 0.0f);
        EXPECT_LE(config.max_gain_db, 60.0f);
    }
}

TEST_F(JSONAPITest, JSONParsingWithScientificNotation) {
    // Test JSON parsing with scientific notation
    std::string scientific_json = R"({
        "mode": "FAST",
        "threshold_db": -5.0e1,
        "max_gain_db": 3.0e1,
        "min_gain_db": -1.5e1,
        "attack_time_ms": 2.0e0,
        "release_time_ms": 2.0e2
    })";
    
    bool result = agc->updateAGCFromJSON(scientific_json);
    EXPECT_TRUE(result) << "Should handle scientific notation";
    
    if (result) {
        AGCConfig config = agc->getAGCConfig();
        EXPECT_EQ(config.mode, AGCMode::FAST);
        EXPECT_FLOAT_EQ(config.threshold_db, -50.0f);
        EXPECT_FLOAT_EQ(config.max_gain_db, 30.0f);
        EXPECT_FLOAT_EQ(config.min_gain_db, -15.0f);
        EXPECT_FLOAT_EQ(config.attack_time_ms, 2.0f);
        EXPECT_FLOAT_EQ(config.release_time_ms, 200.0f);
    }
}

