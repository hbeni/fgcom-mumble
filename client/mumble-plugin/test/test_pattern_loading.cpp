#include <iostream>
#include <string>
#include <fstream>

// Simple test to verify pattern file loading
bool testPatternFileExists(const std::string& filename) {
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
    
    while (std::getline(file, line) && line_count < 20) {
        line_count++;
        
        // Check for frequency information
        if (line.find("FREQUENCY") != std::string::npos || 
            line.find("MHz") != std::string::npos) {
            has_frequency = true;
        }
        
        // Check for antenna name
        if (line.find("ANTENNA") != std::string::npos) {
            has_antenna_name = true;
        }
        
        // Check for gain data (numeric values)
        if (line.find("0.00 0.00") != std::string::npos) {
            has_gain_data = true;
        }
    }
    
    std::cout << "Pattern file " << filename << " - Lines: " << line_count 
              << ", Has frequency: " << (has_frequency ? "Yes" : "No")
              << ", Has antenna name: " << (has_antenna_name ? "Yes" : "No")
              << ", Has gain data: " << (has_gain_data ? "Yes" : "No") << std::endl;
    
    return true;
}

int main() {
    std::cout << "Testing new Yagi pattern file loading..." << std::endl;
    
    // Test the new Yagi patterns
    testPatternFileExists("client/mumble-plugin/lib/antenna_patterns/Ground-based/Yagi-antennas/yagi_6m/patterns/52.000mhz/hy-6m_0m_roll_0_pitch_0_52.000MHz.txt");
    testPatternFileExists("client/mumble-plugin/lib/antenna_patterns/Ground-based/Yagi-antennas/yagi_144mhz/patterns/144.5mhz/yagi-11element_0m_roll_0_pitch_90_144.5MHz.txt");
    testPatternFileExists("client/mumble-plugin/lib/antenna_patterns/Ground-based/Yagi-antennas/yagi_70cm/patterns/432.0mhz/yagi-16element_0m_roll_0_pitch_45_432.0MHz.txt");
    
    std::cout << "New Yagi pattern file loading test completed." << std::endl;
    return 0;
}
