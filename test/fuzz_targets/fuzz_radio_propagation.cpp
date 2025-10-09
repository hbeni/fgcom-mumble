#include <stdint.h>
#include <stddef.h>
#include <cmath>
#include <vector>
#include <algorithm>
#include <iostream>
#include <cstdio>

// Radio propagation fuzzing harness
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 4 floats for parameters
    if (size < sizeof(float) * 4) return 0;
    
    const float* params = reinterpret_cast<const float*>(data);
    
    // Extract parameters
    float distance = params[0];
    float frequency = params[1];
    float altitude1 = params[2];
    float altitude2 = params[3];
    
    // Clamp to reasonable ranges
    distance = std::max(0.1f, std::min(1000.0f, distance));
    frequency = std::max(1.0f, std::min(1000.0f, frequency));
    altitude1 = std::max(0.0f, std::min(10000.0f, altitude1));
    altitude2 = std::max(0.0f, std::min(10000.0f, altitude2));
    
    try {
        // Simple radio propagation calculations
        float wavelength = 300.0f / frequency; // Approximate wavelength in meters
        
        // Free space path loss
        float fsl = 20.0f * log10(distance) + 20.0f * log10(frequency) - 147.55f;
        
        // Line of sight check
        float earth_radius = 6371000.0f; // Earth radius in meters
        float horizon1 = sqrt(2.0f * earth_radius * altitude1);
        float horizon2 = sqrt(2.0f * earth_radius * altitude2);
        bool los = (distance <= horizon1 + horizon2);
        
        // Fresnel zone calculation
        float fresnel_radius = sqrt(wavelength * distance / 2.0f);
        
        // Atmospheric absorption (simplified)
        float absorption = 0.0f;
        if (frequency > 10.0f) {
            absorption = 0.1f * (frequency / 100.0f) * (distance / 1000.0f);
        }
        
        // Total path loss
        float total_loss = fsl + absorption;
        if (!los) {
            total_loss += 20.0f; // Additional loss for non-LOS
        }
        
        // Signal strength calculation
        float tx_power = 10.0f; // 10 dBm
        float rx_power = tx_power - total_loss;
        
        // Antenna gain (simplified)
        float antenna_gain = 0.0f;
        if (frequency > 100.0f) {
            antenna_gain = 10.0f * log10(frequency / 100.0f);
        }
        
        float final_power = rx_power + antenna_gain;
        
        // Check for reasonable results
        if (final_power < -200.0f || final_power > 100.0f) {
            return 0; // Invalid result
        }
        
    } catch (...) {
        // Catch exceptions but don't crash
    }
    
    return 0;
}

// Main function for standalone execution
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    
    // Read input file
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        std::cerr << "Cannot open file: " << argv[1] << std::endl;
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);
    
    return LLVMFuzzerTestOneInput(data.data(), data.size());
}
