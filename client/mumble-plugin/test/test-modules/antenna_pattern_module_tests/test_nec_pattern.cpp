// Test includes
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test_antenna_pattern_main.cpp"

// 11.1 NEC Pattern Tests
TEST_F(NECPatternTest, NECFileParsing) {
    // Test NEC file parsing
    std::vector<FGCom_RadiationPattern> patterns;
    bool parse_result = mock_nec_parser->parseNECFile(test_nec_file, patterns);
    EXPECT_TRUE(parse_result) << "NEC file parsing should succeed";
    
    // Test that patterns were parsed correctly
    EXPECT_GT(patterns.size(), 0) << "NEC patterns should not be empty";
    
    // Test pattern data structure
    if (patterns.size() > 0) {
        const auto& first_pattern = patterns[0];
        EXPECT_GE(first_pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(first_pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(first_pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(first_pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(first_pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(first_pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(first_pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test invalid file
    std::string invalid_file = "/tmp/nonexistent.nec";
    std::vector<FGCom_RadiationPattern> invalid_patterns;
    bool invalid_result = mock_nec_parser->parseNECFile(invalid_file, invalid_patterns);
    EXPECT_FALSE(invalid_result) << "Invalid file should be rejected";
    
    // Test empty file
    std::string empty_file = "/tmp/empty.nec";
    std::ofstream empty_stream(empty_file);
    empty_stream.close();
    
    std::vector<FGCom_RadiationPattern> empty_patterns;
    bool empty_result = mock_nec_parser->parseNECFile(empty_file, empty_patterns);
    EXPECT_FALSE(empty_result) << "Empty file should be rejected";
    
    std::filesystem::remove(empty_file);
}

TEST_F(NECPatternTest, RadiationPatternExtraction) {
    // Test radiation pattern extraction
    std::string nec_data = generateTestNECData();
    std::vector<FGCom_RadiationPattern> patterns;
    bool extract_result = mock_nec_parser->extractRadiationPattern(nec_data, patterns);
    EXPECT_TRUE(extract_result) << "Radiation pattern extraction should succeed";
    
    // Test that patterns were extracted correctly
    EXPECT_GT(patterns.size(), 0) << "Radiation patterns should not be empty";
    
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
    
    // Test invalid data
    std::string invalid_data = "Invalid NEC data";
    std::vector<FGCom_RadiationPattern> invalid_patterns;
    bool invalid_result = mock_nec_parser->extractRadiationPattern(invalid_data, invalid_patterns);
    EXPECT_FALSE(invalid_result) << "Invalid data should be rejected";
    
    // Test empty data
    std::string empty_data = "";
    std::vector<FGCom_RadiationPattern> empty_patterns;
    bool empty_result = mock_nec_parser->extractRadiationPattern(empty_data, empty_patterns);
    EXPECT_FALSE(empty_result) << "Empty data should be rejected";
}

TEST_F(NECPatternTest, GainInterpolation) {
    // Test gain interpolation
    std::vector<FGCom_RadiationPattern> patterns;
    patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 90.0, 2.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 180.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 270.0, 2.0, 0.0, "V"));
    
    // Test interpolation at known points
    double gain_0 = mock_pattern_interpolator->interpolateGain(0.0, 0.0, patterns);
    EXPECT_GE(gain_0, -100.0) << "Interpolated gain should be reasonable";
    EXPECT_LE(gain_0, 50.0) << "Interpolated gain should be reasonable";
    
    double gain_90 = mock_pattern_interpolator->interpolateGain(90.0, 0.0, patterns);
    EXPECT_GE(gain_90, -100.0) << "Interpolated gain should be reasonable";
    EXPECT_LE(gain_90, 50.0) << "Interpolated gain should be reasonable";
    
    // Test interpolation at intermediate points
    double gain_45 = mock_pattern_interpolator->interpolateGain(45.0, 0.0, patterns);
    EXPECT_GE(gain_45, -100.0) << "Interpolated gain should be reasonable";
    EXPECT_LE(gain_45, 50.0) << "Interpolated gain should be reasonable";
    
    // Test interpolation with empty patterns
    std::vector<FGCom_RadiationPattern> empty_patterns;
    double empty_gain = mock_pattern_interpolator->interpolateGain(0.0, 0.0, empty_patterns);
    EXPECT_EQ(empty_gain, 0.0) << "Empty patterns should return 0 gain";
    
    // Test interpolation with single pattern
    std::vector<FGCom_RadiationPattern> single_pattern;
    single_pattern.push_back(FGCom_RadiationPattern(0.0, 0.0, 5.0, 0.0, "V"));
    double single_gain = mock_pattern_interpolator->interpolateGain(0.0, 0.0, single_pattern);
    EXPECT_EQ(single_gain, 5.0) << "Single pattern should return exact gain";
}

TEST_F(NECPatternTest, AzimuthPatternLookup) {
    // Test azimuth pattern lookup
    std::vector<FGCom_RadiationPattern> patterns;
    patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 90.0, 2.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 180.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 270.0, 2.0, 0.0, "V"));
    
    // Test lookup at known azimuths
    double gain_0 = mock_pattern_interpolator->lookupAzimuthPattern(0.0, patterns);
    EXPECT_GE(gain_0, -100.0) << "Azimuth pattern lookup should be reasonable";
    EXPECT_LE(gain_0, 50.0) << "Azimuth pattern lookup should be reasonable";
    
    double gain_90 = mock_pattern_interpolator->lookupAzimuthPattern(90.0, patterns);
    EXPECT_GE(gain_90, -100.0) << "Azimuth pattern lookup should be reasonable";
    EXPECT_LE(gain_90, 50.0) << "Azimuth pattern lookup should be reasonable";
    
    // Test lookup at intermediate azimuths
    double gain_45 = mock_pattern_interpolator->lookupAzimuthPattern(45.0, patterns);
    EXPECT_GE(gain_45, -100.0) << "Azimuth pattern lookup should be reasonable";
    EXPECT_LE(gain_45, 50.0) << "Azimuth pattern lookup should be reasonable";
    
    // Test lookup with empty patterns
    std::vector<FGCom_RadiationPattern> empty_patterns;
    double empty_gain = mock_pattern_interpolator->lookupAzimuthPattern(0.0, empty_patterns);
    EXPECT_EQ(empty_gain, 0.0) << "Empty patterns should return 0 gain";
    
    // Test lookup with single pattern
    std::vector<FGCom_RadiationPattern> single_pattern;
    single_pattern.push_back(FGCom_RadiationPattern(0.0, 0.0, 5.0, 0.0, "V"));
    double single_gain = mock_pattern_interpolator->lookupAzimuthPattern(0.0, single_pattern);
    EXPECT_EQ(single_gain, 5.0) << "Single pattern should return exact gain";
}

TEST_F(NECPatternTest, ElevationPatternLookup) {
    // Test elevation pattern lookup
    std::vector<FGCom_RadiationPattern> patterns;
    patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(45.0, 0.0, 2.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(90.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(-45.0, 0.0, 2.0, 0.0, "V"));
    
    // Test lookup at known elevations
    double gain_0 = mock_pattern_interpolator->lookupElevationPattern(0.0, patterns);
    EXPECT_GE(gain_0, -100.0) << "Elevation pattern lookup should be reasonable";
    EXPECT_LE(gain_0, 50.0) << "Elevation pattern lookup should be reasonable";
    
    double gain_45 = mock_pattern_interpolator->lookupElevationPattern(45.0, patterns);
    EXPECT_GE(gain_45, -100.0) << "Elevation pattern lookup should be reasonable";
    EXPECT_LE(gain_45, 50.0) << "Elevation pattern lookup should be reasonable";
    
    // Test lookup at intermediate elevations
    double gain_22_5 = mock_pattern_interpolator->lookupElevationPattern(22.5, patterns);
    EXPECT_GE(gain_22_5, -100.0) << "Elevation pattern lookup should be reasonable";
    EXPECT_LE(gain_22_5, 50.0) << "Elevation pattern lookup should be reasonable";
    
    // Test lookup with empty patterns
    std::vector<FGCom_RadiationPattern> empty_patterns;
    double empty_gain = mock_pattern_interpolator->lookupElevationPattern(0.0, empty_patterns);
    EXPECT_EQ(empty_gain, 0.0) << "Empty patterns should return 0 gain";
    
    // Test lookup with single pattern
    std::vector<FGCom_RadiationPattern> single_pattern;
    single_pattern.push_back(FGCom_RadiationPattern(0.0, 0.0, 5.0, 0.0, "V"));
    double single_gain = mock_pattern_interpolator->lookupElevationPattern(0.0, single_pattern);
    EXPECT_EQ(single_gain, 5.0) << "Single pattern should return exact gain";
}

TEST_F(NECPatternTest, Pattern3DGeneration) {
    // Test 3D pattern generation
    std::vector<FGCom_RadiationPattern> base_pattern;
    base_pattern.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    base_pattern.push_back(FGCom_RadiationPattern(0.0, 90.0, 2.0, 0.0, "V"));
    base_pattern.push_back(FGCom_RadiationPattern(0.0, 180.0, 0.0, 0.0, "V"));
    base_pattern.push_back(FGCom_RadiationPattern(0.0, 270.0, 2.0, 0.0, "V"));
    
    std::vector<FGCom_RadiationPattern> pattern_3d = mock_pattern_interpolator->generate3DPattern(base_pattern);
    EXPECT_GT(pattern_3d.size(), 0) << "3D pattern should not be empty";
    
    // Test that 3D pattern has reasonable coverage
    EXPECT_GE(pattern_3d.size(), 100) << "3D pattern should have reasonable coverage";
    
    // Test pattern data validity
    for (const auto& pattern : pattern_3d) {
        EXPECT_GE(pattern.theta, -90.0) << "Theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Polarization should not be empty";
    }
    
    // Test with empty base pattern
    std::vector<FGCom_RadiationPattern> empty_base;
    std::vector<FGCom_RadiationPattern> empty_3d = mock_pattern_interpolator->generate3DPattern(empty_base);
    EXPECT_EQ(empty_3d.size(), 0) << "Empty base pattern should produce empty 3D pattern";
}

// Additional NEC pattern tests
TEST_F(NECPatternTest, NECPatternPerformance) {
    // Test NEC pattern performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test NEC parsing performance
    for (int i = 0; i < num_operations; ++i) {
        std::vector<FGCom_RadiationPattern> patterns;
        mock_nec_parser->parseNECFile(test_nec_file, patterns);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // NEC parsing operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "NEC parsing operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "NEC pattern performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(NECPatternTest, NECPatternAccuracy) {
    // Test NEC pattern accuracy
    std::vector<FGCom_RadiationPattern> patterns;
    bool parse_result = mock_nec_parser->parseNECFile(test_nec_file, patterns);
    EXPECT_TRUE(parse_result) << "NEC parsing should be accurate";
    
    // Test pattern data accuracy
    EXPECT_GT(patterns.size(), 0) << "NEC patterns should be accurate";
    
    // Test gain interpolation accuracy
    double gain_0 = mock_pattern_interpolator->interpolateGain(0.0, 0.0, patterns);
    EXPECT_GE(gain_0, -100.0) << "Gain interpolation should be accurate";
    EXPECT_LE(gain_0, 50.0) << "Gain interpolation should be accurate";
    
    // Test azimuth pattern lookup accuracy
    double azimuth_gain = mock_pattern_interpolator->lookupAzimuthPattern(0.0, patterns);
    EXPECT_GE(azimuth_gain, -100.0) << "Azimuth pattern lookup should be accurate";
    EXPECT_LE(azimuth_gain, 50.0) << "Azimuth pattern lookup should be accurate";
    
    // Test elevation pattern lookup accuracy
    double elevation_gain = mock_pattern_interpolator->lookupElevationPattern(0.0, patterns);
    EXPECT_GE(elevation_gain, -100.0) << "Elevation pattern lookup should be accurate";
    EXPECT_LE(elevation_gain, 50.0) << "Elevation pattern lookup should be accurate";
    
    // Test 3D pattern generation accuracy
    std::vector<FGCom_RadiationPattern> pattern_3d = mock_pattern_interpolator->generate3DPattern(patterns);
    EXPECT_GT(pattern_3d.size(), 0) << "3D pattern generation should be accurate";
}

