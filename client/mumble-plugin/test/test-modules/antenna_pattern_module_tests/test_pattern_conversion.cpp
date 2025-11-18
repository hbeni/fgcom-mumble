// Test includes
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include "test_antenna_pattern_main.cpp"

// 11.3 Pattern Conversion Tests
TEST_F(PatternConversionTest, EZToNECConversion) {
    // Test EZ to NEC conversion
    std::string ez_file = test_ez_file;
    std::string nec_file = "/tmp/converted.nec";
    
    bool convert_result = mock_pattern_converter->convertEZToNEC(ez_file, nec_file);
    EXPECT_TRUE(convert_result) << "EZ to NEC conversion should succeed";
    
    // Test that converted file exists
    EXPECT_TRUE(std::filesystem::exists(nec_file)) << "Converted NEC file should exist";
    
    // Test that converted file has correct format
    std::ifstream converted_file(nec_file);
    std::string line;
    bool has_header = false;
    bool has_geometry = false;
    bool has_frequency = false;
    bool has_pattern = false;
    bool has_termination = false;
    
    while (std::getline(converted_file, line)) {
        if (line.find("CM") != std::string::npos) {
            has_header = true;
        } else if (line.find("GW") != std::string::npos) {
            has_geometry = true;
        } else if (line.find("FR") != std::string::npos) {
            has_frequency = true;
        } else if (line.find("RP") != std::string::npos) {
            has_pattern = true;
        } else if (line.find("EN") != std::string::npos) {
            has_termination = true;
        }
    }
    
    converted_file.close();
    
    EXPECT_TRUE(has_header) << "Converted file should have header";
    EXPECT_TRUE(has_geometry) << "Converted file should have geometry";
    EXPECT_TRUE(has_frequency) << "Converted file should have frequency";
    EXPECT_TRUE(has_pattern) << "Converted file should have pattern";
    EXPECT_TRUE(has_termination) << "Converted file should have termination";
    
    // Test invalid input file
    std::string invalid_ez_file = "/tmp/nonexistent.ez";
    std::string invalid_nec_file = "/tmp/invalid_converted.nec";
    bool invalid_result = mock_pattern_converter->convertEZToNEC(invalid_ez_file, invalid_nec_file);
    EXPECT_FALSE(invalid_result) << "Invalid input file should be rejected";
    
    // Test empty input file
    std::string empty_ez_file = "/tmp/empty.ez";
    std::ofstream empty_stream(empty_ez_file);
    empty_stream.close();
    
    std::string empty_nec_file = "/tmp/empty_converted.nec";
    bool empty_result = mock_pattern_converter->convertEZToNEC(empty_ez_file, empty_nec_file);
    EXPECT_FALSE(empty_result) << "Empty input file should be rejected";
    
    std::filesystem::remove(empty_ez_file);
    std::filesystem::remove(nec_file);
    std::filesystem::remove(invalid_nec_file);
    std::filesystem::remove(empty_nec_file);
}

TEST_F(PatternConversionTest, EZNECFormatHandling) {
    // Test EZNEC format handling
    std::string eznec_file = test_eznec_file;
    std::vector<FGCom_RadiationPattern> patterns;
    
    bool handle_result = mock_pattern_converter->handleEZNECFormat(eznec_file, patterns);
    EXPECT_TRUE(handle_result) << "EZNEC format handling should succeed";
    
    // Test that patterns were extracted correctly
    EXPECT_GT(patterns.size(), 0) << "EZNEC patterns should not be empty";
    
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
    
    // Test invalid EZNEC file
    std::string invalid_eznec_file = "/tmp/nonexistent.eznec";
    std::vector<FGCom_RadiationPattern> invalid_patterns;
    bool invalid_result = mock_pattern_converter->handleEZNECFormat(invalid_eznec_file, invalid_patterns);
    EXPECT_FALSE(invalid_result) << "Invalid EZNEC file should be rejected";
    
    // Test empty EZNEC file
    std::string empty_eznec_file = "/tmp/empty.eznec";
    std::ofstream empty_stream(empty_eznec_file);
    empty_stream.close();
    
    std::vector<FGCom_RadiationPattern> empty_patterns;
    bool empty_result = mock_pattern_converter->handleEZNECFormat(empty_eznec_file, empty_patterns);
    EXPECT_FALSE(empty_result) << "Empty EZNEC file should be rejected";
    
    std::filesystem::remove(empty_eznec_file);
}

TEST_F(PatternConversionTest, PatternNormalization) {
    // Test pattern normalization
    std::vector<FGCom_RadiationPattern> patterns;
    patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 90.0, 2.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 180.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(0.0, 270.0, 2.0, 0.0, "V"));
    
    std::vector<FGCom_RadiationPattern> normalized_patterns = mock_pattern_converter->normalizePattern(patterns);
    EXPECT_EQ(normalized_patterns.size(), patterns.size()) << "Normalized patterns should have same size";
    
    // Test that normalization worked correctly
    double max_gain = std::numeric_limits<double>::lowest();
    for (const auto& pattern : normalized_patterns) {
        max_gain = std::max(max_gain, pattern.gain_dbi);
    }
    
    EXPECT_LE(max_gain, 0.0) << "Normalized maximum gain should be <= 0 dB";
    
    // Test with empty patterns
    std::vector<FGCom_RadiationPattern> empty_patterns;
    std::vector<FGCom_RadiationPattern> empty_normalized = mock_pattern_converter->normalizePattern(empty_patterns);
    EXPECT_EQ(empty_normalized.size(), 0) << "Empty patterns should produce empty normalized patterns";
    
    // Test with single pattern
    std::vector<FGCom_RadiationPattern> single_pattern;
    single_pattern.push_back(FGCom_RadiationPattern(0.0, 0.0, 5.0, 0.0, "V"));
    std::vector<FGCom_RadiationPattern> single_normalized = mock_pattern_converter->normalizePattern(single_pattern);
    EXPECT_EQ(single_normalized.size(), 1) << "Single pattern should produce single normalized pattern";
    EXPECT_EQ(single_normalized[0].gain_dbi, 0.0) << "Single pattern should be normalized to 0 dB";
    
    // Test with all same gain patterns
    std::vector<FGCom_RadiationPattern> same_gain_patterns;
    same_gain_patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 3.0, 0.0, "V"));
    same_gain_patterns.push_back(FGCom_RadiationPattern(0.0, 90.0, 3.0, 0.0, "V"));
    same_gain_patterns.push_back(FGCom_RadiationPattern(0.0, 180.0, 3.0, 0.0, "V"));
    same_gain_patterns.push_back(FGCom_RadiationPattern(0.0, 270.0, 3.0, 0.0, "V"));
    
    std::vector<FGCom_RadiationPattern> same_normalized = mock_pattern_converter->normalizePattern(same_gain_patterns);
    EXPECT_EQ(same_normalized.size(), same_gain_patterns.size()) << "Same gain patterns should produce same size normalized patterns";
    
    for (const auto& pattern : same_normalized) {
        EXPECT_EQ(pattern.gain_dbi, 0.0) << "Same gain patterns should all be normalized to 0 dB";
    }
}

TEST_F(PatternConversionTest, CoordinateSystemConversion) {
    // Test coordinate system conversion
    std::vector<FGCom_RadiationPattern> patterns;
    patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(45.0, 90.0, 2.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(90.0, 180.0, 0.0, 0.0, "V"));
    patterns.push_back(FGCom_RadiationPattern(-45.0, 270.0, 2.0, 0.0, "V"));
    
    // Test conversion to spherical coordinates
    std::vector<FGCom_RadiationPattern> spherical_patterns = mock_pattern_converter->convertCoordinateSystem(
        patterns, "spherical");
    EXPECT_EQ(spherical_patterns.size(), patterns.size()) << "Spherical conversion should preserve size";
    
    // Test that spherical conversion preserves data
    for (size_t i = 0; i < patterns.size(); ++i) {
        EXPECT_EQ(spherical_patterns[i].theta, patterns[i].theta) << "Spherical theta should be preserved";
        EXPECT_EQ(spherical_patterns[i].phi, patterns[i].phi) << "Spherical phi should be preserved";
        EXPECT_EQ(spherical_patterns[i].gain_dbi, patterns[i].gain_dbi) << "Spherical gain should be preserved";
        EXPECT_EQ(spherical_patterns[i].phase_deg, patterns[i].phase_deg) << "Spherical phase should be preserved";
        EXPECT_EQ(spherical_patterns[i].polarization, patterns[i].polarization) << "Spherical polarization should be preserved";
    }
    
    // Test conversion to Cartesian coordinates
    std::vector<FGCom_RadiationPattern> cartesian_patterns = mock_pattern_converter->convertCoordinateSystem(
        patterns, "cartesian");
    EXPECT_EQ(cartesian_patterns.size(), patterns.size()) << "Cartesian conversion should preserve size";
    
    // Test that Cartesian conversion produces valid coordinates
    for (const auto& pattern : cartesian_patterns) {
        EXPECT_GE(pattern.theta, -90.0) << "Cartesian theta should be valid";
        EXPECT_LE(pattern.theta, 90.0) << "Cartesian theta should be valid";
        EXPECT_GE(pattern.phi, 0.0) << "Cartesian phi should be valid";
        EXPECT_LE(pattern.phi, 360.0) << "Cartesian phi should be valid";
        EXPECT_GE(pattern.gain_dbi, -100.0) << "Cartesian gain should be reasonable";
        EXPECT_LE(pattern.gain_dbi, 50.0) << "Cartesian gain should be reasonable";
        EXPECT_FALSE(pattern.polarization.empty()) << "Cartesian polarization should not be empty";
    }
    
    // Test with empty patterns
    std::vector<FGCom_RadiationPattern> empty_patterns;
    std::vector<FGCom_RadiationPattern> empty_spherical = mock_pattern_converter->convertCoordinateSystem(
        empty_patterns, "spherical");
    EXPECT_EQ(empty_spherical.size(), 0) << "Empty patterns should produce empty spherical patterns";
    
    std::vector<FGCom_RadiationPattern> empty_cartesian = mock_pattern_converter->convertCoordinateSystem(
        empty_patterns, "cartesian");
    EXPECT_EQ(empty_cartesian.size(), 0) << "Empty patterns should produce empty Cartesian patterns";
    
    // Test with invalid coordinate system
    std::vector<FGCom_RadiationPattern> invalid_patterns = mock_pattern_converter->convertCoordinateSystem(
        patterns, "invalid");
    EXPECT_EQ(invalid_patterns.size(), patterns.size()) << "Invalid coordinate system should preserve size";
    
    // Test that invalid coordinate system preserves original data
    for (size_t i = 0; i < patterns.size(); ++i) {
        EXPECT_EQ(invalid_patterns[i].theta, patterns[i].theta) << "Invalid coordinate system should preserve theta";
        EXPECT_EQ(invalid_patterns[i].phi, patterns[i].phi) << "Invalid coordinate system should preserve phi";
        EXPECT_EQ(invalid_patterns[i].gain_dbi, patterns[i].gain_dbi) << "Invalid coordinate system should preserve gain";
        EXPECT_EQ(invalid_patterns[i].phase_deg, patterns[i].phase_deg) << "Invalid coordinate system should preserve phase";
        EXPECT_EQ(invalid_patterns[i].polarization, patterns[i].polarization) << "Invalid coordinate system should preserve polarization";
    }
}

// Additional pattern conversion tests
TEST_F(PatternConversionTest, PatternConversionPerformance) {
    // Test pattern conversion performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test pattern conversion performance
    for (int i = 0; i < num_operations; ++i) {
        mock_pattern_converter->convertEZToNEC(test_ez_file, "/tmp/temp_converted.nec");
        std::vector<FGCom_RadiationPattern> patterns1;
        mock_pattern_converter->handleEZNECFormat(test_eznec_file, patterns1);
        std::vector<FGCom_RadiationPattern> patterns2;
        mock_pattern_converter->normalizePattern(patterns2);
        std::vector<FGCom_RadiationPattern> patterns3;
        mock_pattern_converter->convertCoordinateSystem(patterns3, "spherical");
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Pattern conversion operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Pattern conversion operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Pattern conversion performance: " << time_per_operation << " microseconds per operation" << std::endl;
    
    // Clean up temporary files
    std::filesystem::remove("/tmp/temp_converted.nec");
}

TEST_F(PatternConversionTest, PatternConversionAccuracy) {
    // Test pattern conversion accuracy
    std::string ez_file = test_ez_file;
    std::string nec_file = "/tmp/accuracy_converted.nec";
    
    bool convert_result = mock_pattern_converter->convertEZToNEC(ez_file, nec_file);
    EXPECT_TRUE(convert_result) << "EZ to NEC conversion should be accurate";
    
    // Test that converted file has correct content
    std::ifstream converted_file(nec_file);
    std::string line;
    bool has_correct_header = false;
    bool has_correct_geometry = false;
    bool has_correct_frequency = false;
    bool has_correct_pattern = false;
    bool has_correct_termination = false;
    
    while (std::getline(converted_file, line)) {
        if (line.find("CM EZNEC Model Converted to NEC2") != std::string::npos) {
            has_correct_header = true;
        } else if (line.find("GW") != std::string::npos) {
            has_correct_geometry = true;
        } else if (line.find("FR") != std::string::npos) {
            has_correct_frequency = true;
        } else if (line.find("RP") != std::string::npos) {
            has_correct_pattern = true;
        } else if (line.find("EN") != std::string::npos) {
            has_correct_termination = true;
        }
    }
    
    converted_file.close();
    
    EXPECT_TRUE(has_correct_header) << "Converted file should have correct header";
    EXPECT_TRUE(has_correct_geometry) << "Converted file should have correct geometry";
    EXPECT_TRUE(has_correct_frequency) << "Converted file should have correct frequency";
    EXPECT_TRUE(has_correct_pattern) << "Converted file should have correct pattern";
    EXPECT_TRUE(has_correct_termination) << "Converted file should have correct termination";
    
    // Test EZNEC format handling accuracy
    std::string eznec_file = test_eznec_file;
    std::vector<FGCom_RadiationPattern> patterns;
    bool handle_result = mock_pattern_converter->handleEZNECFormat(eznec_file, patterns);
    EXPECT_TRUE(handle_result) << "EZNEC format handling should be accurate";
    EXPECT_GT(patterns.size(), 0) << "EZNEC patterns should be accurate";
    
    // Test pattern normalization accuracy
    std::vector<FGCom_RadiationPattern> test_patterns;
    test_patterns.push_back(FGCom_RadiationPattern(0.0, 0.0, 0.0, 0.0, "V"));
    test_patterns.push_back(FGCom_RadiationPattern(0.0, 90.0, 2.0, 0.0, "V"));
    test_patterns.push_back(FGCom_RadiationPattern(0.0, 180.0, 0.0, 0.0, "V"));
    test_patterns.push_back(FGCom_RadiationPattern(0.0, 270.0, 2.0, 0.0, "V"));
    
    std::vector<FGCom_RadiationPattern> normalized_patterns = mock_pattern_converter->normalizePattern(test_patterns);
    EXPECT_EQ(normalized_patterns.size(), test_patterns.size()) << "Pattern normalization should be accurate";
    
    double max_gain = std::numeric_limits<double>::lowest();
    for (const auto& pattern : normalized_patterns) {
        max_gain = std::max(max_gain, pattern.gain_dbi);
    }
    EXPECT_LE(max_gain, 0.0) << "Normalized maximum gain should be accurate";
    
    // Test coordinate system conversion accuracy
    std::vector<FGCom_RadiationPattern> spherical_patterns = mock_pattern_converter->convertCoordinateSystem(
        test_patterns, "spherical");
    EXPECT_EQ(spherical_patterns.size(), test_patterns.size()) << "Coordinate system conversion should be accurate";
    
    for (size_t i = 0; i < test_patterns.size(); ++i) {
        EXPECT_EQ(spherical_patterns[i].theta, test_patterns[i].theta) << "Spherical conversion should be accurate";
        EXPECT_EQ(spherical_patterns[i].phi, test_patterns[i].phi) << "Spherical conversion should be accurate";
        EXPECT_EQ(spherical_patterns[i].gain_dbi, test_patterns[i].gain_dbi) << "Spherical conversion should be accurate";
        EXPECT_EQ(spherical_patterns[i].phase_deg, test_patterns[i].phase_deg) << "Spherical conversion should be accurate";
        EXPECT_EQ(spherical_patterns[i].polarization, test_patterns[i].polarization) << "Spherical conversion should be accurate";
    }
    
    // Clean up temporary files
    std::filesystem::remove(nec_file);
}

