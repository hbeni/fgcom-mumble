#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <cstdio>

// Simple AGC fuzzing harness
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least enough data for parameters
    if (size < sizeof(float) * 4) return 0;
    
    const float* params = reinterpret_cast<const float*>(data);
    
    // Extract parameters from fuzz input
    float threshold = params[0];
    float attack_time = params[1];
    float release_time = params[2];
    float max_gain = params[3];
    
    // Clamp parameters to reasonable ranges
    threshold = std::max(-100.0f, std::min(0.0f, threshold));
    attack_time = std::max(0.001f, std::min(1000.0f, attack_time));
    release_time = std::max(0.001f, std::min(1000.0f, release_time));
    max_gain = std::max(0.0f, std::min(60.0f, max_gain));
    
    // Remaining data is audio samples
    size_t num_samples = (size - sizeof(float) * 4) / sizeof(float);
    if (num_samples == 0) return 0;
    
    const float* samples = &params[4];
    
    // Simple AGC simulation
    float gain = 1.0f;
    float target_gain = 1.0f;
    
    try {
        // Process samples with simple AGC
        for (size_t i = 0; i < num_samples; i++) {
            float sample = samples[i];
            
            // Calculate RMS
            float rms = 0.0f;
            for (size_t j = 0; j < std::min(size_t(10), num_samples - i); j++) {
                rms += samples[i + j] * samples[i + j];
            }
            rms = sqrt(rms / std::min(size_t(10), num_samples - i));
            
            // AGC logic
            if (rms > threshold) {
                target_gain = threshold / (rms + 1e-6f);
                target_gain = std::max(0.1f, std::min(max_gain, target_gain));
            } else {
                target_gain = 1.0f;
            }
            
            // Smooth gain changes
            float gain_diff = target_gain - gain;
            if (gain_diff > 0) {
                gain += gain_diff * (1.0f / attack_time);
            } else {
                gain += gain_diff * (1.0f / release_time);
            }
            
            // Apply gain
            float output = sample * gain;
            
            // Prevent overflow
            output = std::max(-1.0f, std::min(1.0f, output));
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
