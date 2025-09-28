#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>

// Test 4m Yagi pattern file loading and validation
bool test4mYagiPatternFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "ERROR: Cannot open pattern file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    int line_count = 0;
    bool has_frequency = false;
    bool has_antenna_name = false;
    bool has_gain_data = false;
    bool has_header = false;
    
    while (std::getline(file, line) && line_count < 50) {
        line_count++;
        
        // Check for frequency information
        if (line.find("FREQUENCY") != std::string::npos || 
            line.find("MHz") != std::string::npos ||
            line.find("70.15") != std::string::npos) {
            has_frequency = true;
        }
        
        // Check for antenna name
        if (line.find("ANTENNA") != std::string::npos ||
            line.find("4m_yagi") != std::string::npos) {
            has_antenna_name = true;
        }
        
        // Check for header
        if (line.find("Theta") != std::string::npos && line.find("Phi") != std::string::npos) {
            has_header = true;
        }
        
        // Check for gain data (numeric values)
        if (line_count > 5 && !line.empty()) {
            std::istringstream iss(line);
            double theta, phi, gain;
            if (iss >> theta >> phi >> gain) {
                has_gain_data = true;
            }
        }
    }
    
    std::cout << "Pattern file " << filename << " - Lines: " << line_count 
              << ", Has frequency: " << (has_frequency ? "Yes" : "No")
              << ", Has antenna name: " << (has_antenna_name ? "Yes" : "No")
              << ", Has header: " << (has_header ? "Yes" : "No")
              << ", Has gain data: " << (has_gain_data ? "Yes" : "No") << std::endl;
    
    return has_frequency && has_antenna_name && has_header && has_gain_data;
}

int main() {
    std::cout << "Testing 4m Yagi pattern file loading..." << std::endl;
    
    // Test the 4m Yagi patterns with different pitch angles
    std::vector<std::string> pattern_files = {
        "lib/antenna_patterns/Ground-based/4m_band/patterns/70.15mhz/4m_yagi_0m_roll_0_pitch_0_70.15MHz.txt",
        "lib/antenna_patterns/Ground-based/4m_band/patterns/70.15mhz/4m_yagi_0m_roll_0_pitch_45_70.15MHz.txt",
        "lib/antenna_patterns/Ground-based/4m_band/patterns/70.15mhz/4m_yagi_0m_roll_0_pitch_90_70.15MHz.txt"
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& pattern_file : pattern_files) {
        if (test4mYagiPatternFile(pattern_file)) {
            passed++;
        } else {
            failed++;
        }
    }
    
    std::cout << "\n4m Yagi pattern loading test results: " << passed << " passed, " << failed << " failed" << std::endl;
    
    if (failed == 0) {
        std::cout << "SUCCESS: All 4m Yagi patterns loaded correctly!" << std::endl;
        return 0;
    } else {
        std::cout << "FAILURE: Some 4m Yagi patterns failed to load!" << std::endl;
        return 1;
    }
}