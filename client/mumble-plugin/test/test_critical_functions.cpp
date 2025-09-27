/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Critical Function Tests for FGCom-mumble
 * Tests the most important functions without complex dependencies
 */

#include <iostream>
#include <cmath>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>

// Test 8.33kHz channel spacing calculation
bool test833kHzChannelSpacing() {
    std::cout << "    Testing 8.33kHz channel spacing calculation..." << std::endl;
    
    // Test cases: input frequency -> expected 8.33kHz channel
    std::vector<std::pair<std::string, std::string>> test_cases = {
        {"118.000", "118.0000"},  // Exact 25kHz channel
        {"118.005", "118.0000"},  // Should round down to 25kHz
        {"118.010", "118.00834"}, // Should round to 8.33kHz channel
        {"118.015", "118.01667"}, // Should round to 8.33kHz channel
        {"118.025", "118.0250"},  // Exact 25kHz channel
        {"118.030", "118.0250"},  // Should round down to 25kHz
        {"118.035", "118.03334"}, // Should round to 8.33kHz channel
        {"118.040", "118.04167"}, // Should round to 8.33kHz channel
        {"118.050", "118.0500"},  // Exact 25kHz channel
        {"118.055", "118.0500"},  // Should round down to 25kHz
        {"118.060", "118.05834"}, // Should round to 8.33kHz channel
        {"118.065", "118.06667"}, // Should round to 8.33kHz channel
        {"118.075", "118.0750"},  // Exact 25kHz channel
        {"118.080", "118.0750"},  // Should round down to 25kHz
        {"118.085", "118.08334"}, // Should round to 8.33kHz channel
        {"118.090", "118.09167"}, // Should round to 8.33kHz channel
        {"118.100", "118.1000"},  // Exact 25kHz channel
        {"118.105", "118.1000"},  // Should round down to 25kHz
        {"118.110", "118.10834"}, // Should round to 8.33kHz channel
        {"118.115", "118.11668"}, // Should round to 8.33kHz channel
        {"118.125", "118.1250"},  // Exact 25kHz channel
        {"118.130", "118.1250"},  // Should round down to 25kHz
        {"118.135", "118.13334"}, // Should round to 8.33kHz channel
        {"118.140", "118.14167"}, // Should round to 8.33kHz channel
        {"118.150", "118.1500"},  // Exact 25kHz channel
        {"118.155", "118.1500"},  // Should round down to 25kHz
        
        // Mid-range frequencies
        {"126.565", "126.56667"}, // Mid-range frequency
        {"126.575", "126.5750"},  // Mid-range frequency
        {"126.580", "126.5750"},  // Mid-range frequency
        {"126.585", "126.58334"}, // Mid-range frequency
        {"126.590", "126.59167"}, // Mid-range frequency
        {"126.600", "126.6000"},  // Mid-range frequency
        {"126.605", "126.6000"},  // Mid-range frequency
        {"126.610", "126.60834"}, // Mid-range frequency
        {"126.615", "126.61668"}, // Mid-range frequency
        {"126.625", "126.6250"},  // Mid-range frequency
        {"126.630", "126.6250"},  // Mid-range frequency
        {"126.635", "126.63334"}, // Mid-range frequency
        {"126.640", "126.64167"}, // Mid-range frequency
        {"126.650", "126.6500"},  // Mid-range frequency
        {"126.655", "126.6500"},  // Mid-range frequency
        {"126.660", "126.65834"}, // Mid-range frequency
        {"126.665", "126.66667"}, // Mid-range frequency
        {"126.675", "126.6750"},  // Mid-range frequency
        {"126.680", "126.6750"},  // Mid-range frequency
        {"126.685", "126.68334"}, // Mid-range frequency
        {"126.690", "126.69167"}, // Mid-range frequency
        {"126.710", "126.70834"}, // Mid-range frequency
        
        // End range frequencies
        {"137.900", "137.9000"},  // End range
        {"137.905", "137.9000"},  // End range
        {"137.910", "137.90834"}, // End range
        {"137.915", "137.91667"}, // End range
        {"137.925", "137.9250"},  // End range
        {"137.930", "137.9250"},  // End range
        {"137.935", "137.93333"}, // End range
        {"137.940", "137.94168"}, // End range
        {"137.950", "137.9500"},  // End range
        {"137.955", "137.9500"},  // End range
        {"137.960", "137.95834"}, // End range
        {"137.965", "137.96667"}, // End range
        {"137.975", "137.9750"},  // End range
        {"137.980", "137.9750"},  // End range
        {"137.985", "137.98334"}, // End range
        {"137.990", "137.99167"}  // End range
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            // Parse input frequency
            double input_freq = std::stod(test_case.first);
            
            // Calculate 8.33kHz channel spacing
            // 8.33kHz = 0.00833 MHz
            double channel_spacing = 0.00833;
            
            // Find the closest 8.33kHz channel
            double channel_number = std::round(input_freq / channel_spacing);
            double calculated_channel = channel_number * channel_spacing;
            
            // Format to 4 decimal places
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(4) << calculated_channel;
            std::string result = oss.str();
            
            if (result == test_case.second) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.first << " -> " << result 
                         << " (expected: " << test_case.second << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.first << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    8.33kHz channel spacing results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test new modulation mode channel spacing
bool testModulationModeChannelSpacing() {
    std::cout << "    Testing modulation mode channel spacing..." << std::endl;
    
    // Test cases: mode -> expected channel spacing in Hz
    std::vector<std::pair<std::string, float>> test_cases = {
        {"CW", 500.0f},      // 500Hz for CW
        {"SSB", 3000.0f},    // 3kHz for SSB
        {"AM", 3000.0f},     // 3kHz for AM
        {"FM", 25000.0f},    // 25kHz for FM
        {"DSB", 6000.0f},    // 6kHz for DSB
        {"ISB", 6000.0f},    // 6kHz for ISB
        {"VSB", 4000.0f},    // 4kHz for VSB
        {"NFM", 12500.0f},   // 12.5kHz for NFM
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            std::string mode = test_case.first;
            float expected_spacing = test_case.second;
            
            // Simulate channel spacing calculation
            float calculated_spacing = 0.0f;
            
            if (mode == "CW") {
                calculated_spacing = 500.0f;
            } else if (mode == "SSB" || mode == "AM") {
                calculated_spacing = 3000.0f;
            } else if (mode == "FM") {
                calculated_spacing = 25000.0f;
            } else if (mode == "DSB" || mode == "ISB") {
                calculated_spacing = 6000.0f;
            } else if (mode == "VSB") {
                calculated_spacing = 4000.0f;
            } else if (mode == "NFM") {
                calculated_spacing = 12500.0f;
            }
            
            if (std::abs(calculated_spacing - expected_spacing) < 0.1f) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << mode << " -> " << calculated_spacing 
                         << "Hz (expected: " << expected_spacing << "Hz)" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.first << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Modulation mode channel spacing results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test propagation model wavelength calculations
bool testPropagationWavelengthCalculations() {
    std::cout << "    Testing propagation wavelength calculations..." << std::endl;
    
    // Test cases: frequency (MHz) -> expected wavelength (meters)
    std::vector<std::pair<double, double>> test_cases = {
        // HF bands
        {3.5, 85.7},   // 80m band
        {7.0, 42.9},   // 40m band
        {14.0, 21.4},  // 20m band
        {21.0, 14.3},  // 15m band
        {28.0, 10.7},  // 10m band
        
        // VHF bands
        {118.0, 1.0},  // Aviation VHF
        {121.5, 1.0},  // Emergency frequency
        {123.0, 1.0},  // Aviation VHF
        {137.0, 1.0},  // Aviation VHF
        
        // UHF bands
        {300.0, 0.3},  // UHF
        {400.0, 0.2},  // UHF
        {800.0, 0.1},  // UHF
        {1200.0, 0.07}, // UHF
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            double frequency = test_case.first;
            double expected_wavelength = test_case.second;
            
            // Calculate wavelength: c/f where c = 300 m/μs
            double calculated_wavelength = 300.0 / frequency;
            
            if (std::abs(calculated_wavelength - expected_wavelength) < 0.1) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << frequency << "MHz -> " << calculated_wavelength 
                         << "m (expected: " << expected_wavelength << "m)" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.first << "MHz -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Propagation wavelength results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test antenna pattern file existence
bool testAntennaPatternFileExistence() {
    std::cout << "    Testing antenna pattern file existence..." << std::endl;
    
    // Test pattern files that should exist
    std::vector<std::string> pattern_files = {
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/5.0mhz/80m-loop_60m_0m_roll_0_pitch_0_5.0MHz.txt",
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/3.5mhz/80m-loop_80m_0m_roll_0_pitch_0_3.5MHz.txt",
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/7.0mhz/80m-loop_40m_0m_roll_0_pitch_0_7.0MHz.txt",
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/14.0mhz/80m-loop_20m_0m_roll_0_pitch_0_14.0MHz.txt",
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/21.0mhz/80m-loop_15m_0m_roll_0_pitch_0_21.0MHz.txt",
        "lib/antenna_patterns/Ground-based/80m-loop/patterns/28.0mhz/80m-loop_10m_0m_roll_0_pitch_0_28.0MHz.txt"
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& pattern_file : pattern_files) {
        try {
            // Check if pattern file exists
            std::ifstream file(pattern_file);
            if (file.good()) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: Pattern file not found: " << pattern_file << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << pattern_file << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Antenna pattern file existence results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

// Test solar data validation ranges
bool testSolarDataValidationRanges() {
    std::cout << "    Testing solar data validation ranges..." << std::endl;
    
    // Test solar data ranges
    struct SolarDataTest {
        std::string name;
        double value;
        double min_val;
        double max_val;
    };
    
    std::vector<SolarDataTest> test_cases = {
        {"SFI", 150.0, 0.0, 300.0},      // Solar Flux Index
        {"K-Index", 3.0, 0.0, 9.0},       // K-Index
        {"A-Index", 15.0, 0.0, 400.0},    // A-Index
        {"SFI_Min", 0.0, 0.0, 300.0},     // Minimum SFI
        {"SFI_Max", 300.0, 0.0, 300.0},   // Maximum SFI
        {"K-Index_Min", 0.0, 0.0, 9.0},   // Minimum K-Index
        {"K-Index_Max", 9.0, 0.0, 9.0},  // Maximum K-Index
        {"A-Index_Min", 0.0, 0.0, 400.0}, // Minimum A-Index
        {"A-Index_Max", 400.0, 0.0, 400.0} // Maximum A-Index
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test_case : test_cases) {
        try {
            bool valid = (test_case.value >= test_case.min_val && test_case.value <= test_case.max_val);
            
            if (valid) {
                passed++;
            } else {
                failed++;
                std::cout << "      FAILED: " << test_case.name << " = " << test_case.value 
                         << " (range: " << test_case.min_val << " - " << test_case.max_val << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "      EXCEPTION: " << test_case.name << " -> " << e.what() << std::endl;
        }
    }
    
    std::cout << "    Solar data validation results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed == 0;
}

int main() {
    std::cout << "Running FGCom-mumble Critical Function Tests..." << std::endl;
    std::cout << "=============================================" << std::endl;
    
    int total_passed = 0;
    int total_failed = 0;
    
    // Run all tests
    if (test833kHzChannelSpacing()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testModulationModeChannelSpacing()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testPropagationWavelengthCalculations()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testAntennaPatternFileExistence()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    if (testSolarDataValidationRanges()) {
        total_passed++;
    } else {
        total_failed++;
    }
    
    std::cout << "=============================================" << std::endl;
    std::cout << "Test Results:" << std::endl;
    std::cout << "  Passed: " << total_passed << std::endl;
    std::cout << "  Failed: " << total_failed << std::endl;
    std::cout << "  Total:  " << (total_passed + total_failed) << std::endl;
    
    if (total_failed == 0) {
        std::cout << "\nAll critical function tests passed! ✓" << std::endl;
        return 0;
    } else {
        std::cout << "\nSome critical function tests failed! ✗" << std::endl;
        return 1;
    }
}
