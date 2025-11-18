#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <regex>
#include <exception>

// Include the antenna pattern modules
#include "../../client/mumble-plugin/lib/pattern_interpolation.h"
#include "../../client/mumble-plugin/lib/antenna_orientation_calculator.h"
#include "../../client/mumble-plugin/lib/antenna_ground_system.h"
#include "../../client/mumble-plugin/lib/vehicle_dynamics.h"

// Mock classes for testing
class MockNECParser {
public:
    MockNECParser() = default;
    
    virtual ~MockNECParser() = default;
    
    // NEC file parsing methods
    virtual bool parseNECFile(const std::string& filename, std::vector<FGCom_RadiationPattern>& patterns) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        bool in_pattern_section = false;
        
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            
            if (line.find("RADIATION PATTERN") != std::string::npos ||
                line.find("FAR FIELD") != std::string::npos) {
                in_pattern_section = true;
                continue;
            }
            
            if (in_pattern_section) {
                std::istringstream iss(line);
                double theta, phi, gain, phase;
                std::string pol;
                
                if (iss >> theta >> phi >> gain >> phase >> pol) {
                    patterns.push_back(FGCom_RadiationPattern(theta, phi, gain, phase, pol));
                }
            }
        }
        
        file.close();
        return !patterns.empty();
    }
    
    virtual bool extractRadiationPattern(const std::string& nec_data, std::vector<FGCom_RadiationPattern>& patterns) {
        std::istringstream iss(nec_data);
        std::string line;
        
        while (std::getline(iss, line)) {
            if (line.find("RADIATION PATTERN") != std::string::npos ||
                line.find("FAR FIELD") != std::string::npos) {
                continue;
            }
            
            std::istringstream line_stream(line);
            double theta, phi, gain, phase;
            std::string pol;
            
            if (line_stream >> theta >> phi >> gain >> phase >> pol) {
                patterns.push_back(FGCom_RadiationPattern(theta, phi, gain, phase, pol));
            }
        }
        
        return !patterns.empty();
    }
    
    virtual bool validateNECFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        bool has_geometry = false;
        bool has_frequency = false;
        bool has_pattern = false;
        
        while (std::getline(file, line)) {
            if (line.find("GW") != std::string::npos) {
                has_geometry = true;
            } else if (line.find("FR") != std::string::npos) {
                has_frequency = true;
            } else if (line.find("RP") != std::string::npos) {
                has_pattern = true;
            }
        }
        
        file.close();
        return has_geometry && has_frequency && has_pattern;
    }
};

// Mock antenna pattern interpolator
class MockAntennaPatternInterpolator {
public:
    MockAntennaPatternInterpolator() = default;
    
    virtual ~MockAntennaPatternInterpolator() = default;
    
    // Gain interpolation methods
    virtual double interpolateGain(double azimuth, double elevation, const std::vector<FGCom_RadiationPattern>& patterns) {
        if (patterns.empty()) {
            return 0.0;
        }
        
        // Simple linear interpolation
        double min_distance = std::numeric_limits<double>::max();
        double best_gain = 0.0;
        
        for (const auto& pattern : patterns) {
            double distance = std::sqrt(std::pow(pattern.phi - azimuth, 2) + std::pow(pattern.theta - elevation, 2));
            if (distance < min_distance) {
                min_distance = distance;
                best_gain = pattern.gain_dbi;
            }
        }
        
        return best_gain;
    }
    
    virtual double lookupAzimuthPattern(double azimuth, const std::vector<FGCom_RadiationPattern>& patterns) {
        if (patterns.empty()) {
            return 0.0;
        }
        
        // Find closest azimuth match
        double min_distance = std::numeric_limits<double>::max();
        double best_gain = 0.0;
        
        for (const auto& pattern : patterns) {
            double distance = std::abs(pattern.phi - azimuth);
            if (distance < min_distance) {
                min_distance = distance;
                best_gain = pattern.gain_dbi;
            }
        }
        
        return best_gain;
    }
    
    virtual double lookupElevationPattern(double elevation, const std::vector<FGCom_RadiationPattern>& patterns) {
        if (patterns.empty()) {
            return 0.0;
        }
        
        // Find closest elevation match
        double min_distance = std::numeric_limits<double>::max();
        double best_gain = 0.0;
        
        for (const auto& pattern : patterns) {
            double distance = std::abs(pattern.theta - elevation);
            if (distance < min_distance) {
                min_distance = distance;
                best_gain = pattern.gain_dbi;
            }
        }
        
        return best_gain;
    }
    
    virtual std::vector<FGCom_RadiationPattern> generate3DPattern(const std::vector<FGCom_RadiationPattern>& base_pattern) {
        std::vector<FGCom_RadiationPattern> pattern_3d;
        
        // Return empty pattern if base pattern is empty
        if (base_pattern.empty()) {
            return pattern_3d;
        }
        
        // Generate 3D pattern by interpolating between azimuth and elevation
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = interpolateGain(azimuth, elevation, base_pattern);
                pattern_3d.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return pattern_3d;
    }
};

// Mock vehicle-specific antenna manager
class MockVehicleAntennaManager {
public:
    MockVehicleAntennaManager() = default;
    
    virtual ~MockVehicleAntennaManager() = default;
    
    // Vehicle-specific antenna methods
    virtual std::vector<FGCom_RadiationPattern> getAircraftAntennaPattern(const std::string& aircraft_type, double altitude, double roll, double pitch) {
        std::vector<FGCom_RadiationPattern> patterns;
        
        // Use aircraft_type to adjust pattern characteristics
        double type_factor = 1.0;
        if (aircraft_type == "commercial") type_factor = 1.2;
        else if (aircraft_type == "military") type_factor = 1.5;
        else if (aircraft_type == "general") type_factor = 0.8;
        
        // Simulate aircraft antenna pattern (belly-mounted)
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = calculateAircraftGain(azimuth, elevation, altitude, roll, pitch) * type_factor;
                patterns.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return patterns;
    }
    
    virtual std::vector<FGCom_RadiationPattern> getGroundVehicleAntennaPattern(const std::string& vehicle_type, double height, double angle) {
        std::vector<FGCom_RadiationPattern> patterns;
        
        // Use vehicle_type to adjust pattern characteristics
        double type_factor = 1.0;
        if (vehicle_type == "truck") type_factor = 1.3;
        else if (vehicle_type == "car") type_factor = 0.7;
        else if (vehicle_type == "bus") type_factor = 1.1;
        
        // Simulate ground vehicle antenna pattern (45° tie-down)
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = calculateGroundVehicleGain(azimuth, elevation, height, angle) * type_factor;
                patterns.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return patterns;
    }
    
    virtual std::vector<FGCom_RadiationPattern> getHandheldAntennaPattern(const std::string& antenna_type, double height) {
        std::vector<FGCom_RadiationPattern> patterns;
        
        // Use antenna_type to adjust pattern characteristics
        double type_factor = 1.0;
        if (antenna_type == "whip") type_factor = 1.2;
        else if (antenna_type == "helical") type_factor = 1.5;
        else if (antenna_type == "rubber_duck") type_factor = 0.8;
        
        // Simulate handheld antenna pattern (vertical)
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = calculateHandheldGain(azimuth, elevation, height) * type_factor;
                patterns.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return patterns;
    }
    
    virtual std::vector<FGCom_RadiationPattern> getBaseStationAntennaPattern(const std::string& antenna_type, double height) {
        std::vector<FGCom_RadiationPattern> patterns;
        
        // Use antenna_type to adjust pattern characteristics
        double type_factor = 1.0;
        if (antenna_type == "yagi") type_factor = 1.4;
        else if (antenna_type == "dipole") type_factor = 1.0;
        else if (antenna_type == "array") type_factor = 1.8;
        
        // Simulate base station antenna pattern (elevated)
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = calculateBaseStationGain(azimuth, elevation, height) * type_factor;
                patterns.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return patterns;
    }
    
    virtual std::vector<FGCom_RadiationPattern> getMaritimeAntennaPattern(const std::string& ship_type, double height, double roll, double pitch) {
        std::vector<FGCom_RadiationPattern> patterns;
        
        // Use ship_type to adjust pattern characteristics
        double type_factor = 1.0;
        if (ship_type == "cargo") type_factor = 1.2;
        else if (ship_type == "passenger") type_factor = 1.1;
        else if (ship_type == "navy") type_factor = 1.5;
        
        // Simulate maritime antenna pattern (ship-mounted)
        for (double azimuth = 0; azimuth < 360; azimuth += 10) {
            for (double elevation = -90; elevation <= 90; elevation += 10) {
                double gain = calculateMaritimeGain(azimuth, elevation, height, roll, pitch) * type_factor;
                patterns.push_back(FGCom_RadiationPattern(elevation, azimuth, gain, 0.0, "V"));
            }
        }
        
        return patterns;
    }
    
protected:
    double calculateAircraftGain(double azimuth, double elevation, double altitude, double roll, double pitch) {
        // Simulate aircraft antenna gain based on altitude and attitude
        double base_gain = 0.0;
        double altitude_factor = std::log10(altitude / 1000.0 + 1.0);
        double attitude_factor = std::cos(roll * M_PI / 180.0) * std::cos(pitch * M_PI / 180.0);
        double directional_factor = std::cos(elevation * M_PI / 180.0) * std::cos(azimuth * M_PI / 180.0);
        return base_gain + altitude_factor + attitude_factor + directional_factor;
    }
    
    double calculateGroundVehicleGain(double azimuth, double elevation, double height, double angle) {
        // Simulate ground vehicle antenna gain based on height and angle
        double base_gain = 0.0;
        double height_factor = std::log10(height / 10.0 + 1.0);
        double angle_factor = std::cos((elevation - angle) * M_PI / 180.0);
        double directional_factor = std::cos(elevation * M_PI / 180.0) * std::sin(azimuth * M_PI / 180.0);
        return base_gain + height_factor + angle_factor + directional_factor;
    }
    
    double calculateHandheldGain(double azimuth, double elevation, double height) {
        // Simulate handheld antenna gain (omnidirectional)
        double base_gain = 0.0;
        double height_factor = std::log10(height / 2.0 + 1.0);
        double directional_factor = std::cos(elevation * M_PI / 180.0) * std::cos(azimuth * M_PI / 180.0);
        return base_gain + height_factor + directional_factor;
    }
    
    double calculateBaseStationGain(double azimuth, double elevation, double height) {
        // Simulate base station antenna gain (elevated)
        double base_gain = 0.0;
        double height_factor = std::log10(height / 10.0 + 1.0);
        double elevation_factor = std::cos(elevation * M_PI / 180.0);
        double directional_factor = std::sin(azimuth * M_PI / 180.0);
        return base_gain + height_factor + elevation_factor + directional_factor;
    }
    
    double calculateMaritimeGain(double azimuth, double elevation, double height, double roll, double pitch) {
        // Simulate maritime antenna gain based on ship attitude
        double base_gain = 0.0;
        double height_factor = std::log10(height / 10.0 + 1.0);
        double attitude_factor = std::cos(roll * M_PI / 180.0) * std::cos(pitch * M_PI / 180.0);
        double directional_factor = std::cos(elevation * M_PI / 180.0) * std::cos(azimuth * M_PI / 180.0);
        return base_gain + height_factor + attitude_factor + directional_factor;
    }
};

// Mock pattern converter
class MockPatternConverter {
public:
    MockPatternConverter() = default;
    
    virtual ~MockPatternConverter() = default;
    
    // Pattern conversion methods
    virtual bool convertEZToNEC(const std::string& ez_file, const std::string& nec_file) {
        std::ifstream input(ez_file);
        if (!input.is_open()) {
            return false;
        }
        
        std::ofstream output(nec_file);
        if (!output.is_open()) {
            return false;
        }
        
        // Check if input file is empty
        std::string line;
        bool has_content = false;
        while (std::getline(input, line)) {
            has_content = true;
            break;
        }
        
        if (!has_content) {
            return false; // Empty file should be rejected
        }
        
        // Reset file pointer to beginning
        input.clear();
        input.seekg(0, std::ios::beg);
        
        // Convert EZ format to NEC format
        output << "CM EZNEC Model Converted to NEC2\n";
        output << "CE\n";
        
        while (std::getline(input, line)) {
            if (line.find("GW") != std::string::npos) {
                output << line << "\n";
            } else if (line.find("EX") != std::string::npos) {
                output << line << "\n";
            } else if (line.find("GN") != std::string::npos) {
                output << line << "\n";
            } else if (line.find("FR") != std::string::npos) {
                output << line << "\n";
            } else if (line.find("RP") != std::string::npos) {
                output << line << "\n";
            }
        }
        
        output << "EN\n";
        
        input.close();
        output.close();
        return true;
    }
    
    virtual bool handleEZNECFormat(const std::string& eznec_file, std::vector<FGCom_RadiationPattern>& patterns) {
        std::ifstream file(eznec_file);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        bool in_pattern_section = false;
        
        while (std::getline(file, line)) {
            if (line.find("RADIATION PATTERN") != std::string::npos ||
                line.find("FAR FIELD") != std::string::npos) {
                in_pattern_section = true;
                continue;
            }
            
            if (in_pattern_section) {
                std::istringstream iss(line);
                double theta, phi, gain, phase;
                std::string pol;
                
                if (iss >> theta >> phi >> gain >> phase >> pol) {
                    patterns.push_back(FGCom_RadiationPattern(theta, phi, gain, phase, pol));
                }
            }
        }
        
        file.close();
        return !patterns.empty();
    }
    
    virtual std::vector<FGCom_RadiationPattern> normalizePattern(const std::vector<FGCom_RadiationPattern>& patterns) {
        if (patterns.empty()) {
            return patterns;
        }
        
        // Find maximum gain
        double max_gain = std::numeric_limits<double>::lowest();
        for (const auto& pattern : patterns) {
            max_gain = std::max(max_gain, pattern.gain_dbi);
        }
        
        // Normalize to 0 dB maximum
        std::vector<FGCom_RadiationPattern> normalized_patterns;
        for (const auto& pattern : patterns) {
            normalized_patterns.push_back(FGCom_RadiationPattern(
                pattern.theta, pattern.phi, pattern.gain_dbi - max_gain, pattern.phase_deg, pattern.polarization));
        }
        
        return normalized_patterns;
    }
    
    virtual std::vector<FGCom_RadiationPattern> convertCoordinateSystem(const std::vector<FGCom_RadiationPattern>& patterns, const std::string& target_system) {
        std::vector<FGCom_RadiationPattern> converted_patterns;
        
        for (const auto& pattern : patterns) {
            double new_theta = pattern.theta;
            double new_phi = pattern.phi;
            
            if (target_system == "spherical") {
                // Convert to spherical coordinates
                new_theta = pattern.theta;
                new_phi = pattern.phi;
            } else if (target_system == "cartesian") {
                // Convert to Cartesian coordinates
                double x = std::sin(pattern.theta * M_PI / 180.0) * std::cos(pattern.phi * M_PI / 180.0);
                double y = std::sin(pattern.theta * M_PI / 180.0) * std::sin(pattern.phi * M_PI / 180.0);
                double z = std::cos(pattern.theta * M_PI / 180.0);
                
                new_theta = std::atan2(std::sqrt(x*x + y*y), z) * 180.0 / M_PI;
                new_phi = std::atan2(y, x) * 180.0 / M_PI;
            }
            
            converted_patterns.push_back(FGCom_RadiationPattern(
                new_theta, new_phi, pattern.gain_dbi, pattern.phase_deg, pattern.polarization));
        }
        
        return converted_patterns;
    }
};

// Test fixtures and utilities
class AntennaPatternModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_nec_file = "/tmp/test_antenna.nec";
        test_ez_file = "/tmp/test_antenna.ez";
        test_eznec_file = "/tmp/test_antenna.eznec";
        
        test_nec_data = "CM Test Antenna Pattern\n"
                       "CE\n"
                       "GW 1 1 0.0 0.0 0.0 0.0 0.0 1.0 0.001\n"
                       "FR 0 1 0 0 144.0 0\n"
                       "RP 0 1 1 1000 0.0 0.0 1.0 1.0\n"
                       "RADIATION PATTERN\n"
                       "0.0 0.0 0.0 0.0 V\n"
                       "0.0 90.0 2.0 0.0 V\n"
                       "0.0 180.0 0.0 0.0 V\n"
                       "0.0 270.0 2.0 0.0 V\n"
                       "EN\n";
        
        test_ez_data = "GW 1 1 0.0 0.0 0.0 0.0 0.0 1.0 0.001\n"
                      "EX 0 1 1 0 1.0 0.0\n"
                      "FR 0 1 0 0 144.0 0\n"
                      "RP 0 1 1 1000 0.0 0.0 1.0 1.0\n";
        
        // Test directories
        test_pattern_dir = "/tmp/antenna_pattern_test_data";
        std::filesystem::create_directories(test_pattern_dir);
        
        // Initialize mock objects
        mock_nec_parser = std::make_unique<MockNECParser>();
        mock_pattern_interpolator = std::make_unique<MockAntennaPatternInterpolator>();
        mock_vehicle_antenna_manager = std::make_unique<MockVehicleAntennaManager>();
        mock_pattern_converter = std::make_unique<MockPatternConverter>();
        
        // Create test files
        createTestFiles();
    }
    
    void TearDown() override {
        // Clean up test files
        std::filesystem::remove_all(test_pattern_dir);
        std::filesystem::remove(test_nec_file);
        std::filesystem::remove(test_ez_file);
        std::filesystem::remove(test_eznec_file);
        
        // Clean up mock objects
        mock_nec_parser.reset();
        mock_pattern_interpolator.reset();
        mock_vehicle_antenna_manager.reset();
        mock_pattern_converter.reset();
    }
    
    // Test parameters
    std::string test_nec_file, test_ez_file, test_eznec_file;
    std::string test_nec_data, test_ez_data;
    std::string test_pattern_dir;
    
    // Mock objects
    std::unique_ptr<MockNECParser> mock_nec_parser;
    std::unique_ptr<MockAntennaPatternInterpolator> mock_pattern_interpolator;
    std::unique_ptr<MockVehicleAntennaManager> mock_vehicle_antenna_manager;
    std::unique_ptr<MockPatternConverter> mock_pattern_converter;
    
    // Helper functions
    void createTestFiles() {
        // Create test NEC file
        std::ofstream nec_file(test_nec_file);
        nec_file << test_nec_data;
        nec_file.close();
        
        // Create test EZ file
        std::ofstream ez_file(test_ez_file);
        ez_file << test_ez_data;
        ez_file.close();
        
        // Create test EZNEC file
        std::ofstream eznec_file(test_eznec_file);
        eznec_file << test_nec_data;
        eznec_file.close();
    }
    
    std::string generateTestNECData() {
        return test_nec_data;
    }
    
    std::string generateTestEZData() {
        return test_ez_data;
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
};

// Test suite for NEC pattern tests
class NECPatternTest : public AntennaPatternModuleTest {
protected:
    void SetUp() override {
        AntennaPatternModuleTest::SetUp();
    }
};

// Test suite for vehicle-specific antenna tests
class VehicleAntennaTest : public AntennaPatternModuleTest {
protected:
    void SetUp() override {
        AntennaPatternModuleTest::SetUp();
    }
};

// Test suite for pattern conversion tests
class PatternConversionTest : public AntennaPatternModuleTest {
protected:
    void SetUp() override {
        AntennaPatternModuleTest::SetUp();
    }
};


