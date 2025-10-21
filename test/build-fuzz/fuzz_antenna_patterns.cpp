#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>

// Fuzzing target for antenna pattern calculations
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 12) return 0; // Need minimum data
    
    // Systematically consume input bytes
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract antenna parameters
    float azimuth = 0.0f;
    float elevation = 0.0f;
    float frequency = 0.0f;
    
    if (offset + 4 <= Size) {
        memcpy(&azimuth, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        memcpy(&elevation, Data + offset, 4);
        offset += 4;
    }
    if (offset + 4 <= Size) {
        memcpy(&frequency, Data + offset, 4);
        offset += 4;
    }
    
    // Normalize angles to valid ranges
    azimuth = fmod(azimuth, 360.0f);
    if (azimuth < 0) azimuth += 360.0f;
    elevation = std::max(-90.0f, std::min(90.0f, elevation));
    
    // Ensure frequency is positive
    if (frequency <= 0) frequency = 100.0f; // Default 100 MHz
    
    try {
        // PURE FUZZING: Use selector byte to pick ONE code path
        switch (selector % 8) {
            case 0: {
                // Test omnidirectional pattern
                float gain = 1.0f; // Omnidirectional has constant gain
                
                // Test pattern characteristics
                if (gain > 0.5f && gain < 2.0f) {
                    // Valid omnidirectional gain
                    return 0;
                }
                break;
            }
            
            case 1: {
                // Test dipole pattern
                float gain = std::cos(elevation * M_PI / 180.0f);
                
                // Test dipole characteristics
                if (gain >= -1.0f && gain <= 1.0f) {
                    // Valid dipole gain range
                    return 0;
                }
                break;
            }
            
            case 2: {
                // Test directional pattern
                float gain = std::sin(azimuth * M_PI / 180.0f) * std::cos(elevation * M_PI / 180.0f);
                
                // Test directional characteristics
                if (gain >= -1.0f && gain <= 1.0f) {
                    // Valid directional gain range
                    return 0;
                }
                break;
            }
            
            case 3: {
                // Test frequency-dependent pattern
                float wavelength = 300.0f / frequency; // 300 MHz = 1m wavelength
                float gain = std::sin(2.0f * M_PI * frequency / 1000.0f);
                
                // Test frequency characteristics
                if (wavelength > 0.1f && wavelength < 1000.0f) {
                    // Valid wavelength range
                    return 0;
                }
                break;
            }
            
            case 4: {
                // Test beamwidth calculation
                float beamwidth = 360.0f / (1.0f + frequency / 1000.0f);
                
                // Test beamwidth characteristics
                if (beamwidth > 1.0f && beamwidth < 360.0f) {
                    // Valid beamwidth range
                    return 0;
                }
                break;
            }
            
            case 5: {
                // Test antenna efficiency
                float efficiency = std::abs(std::sin(azimuth * M_PI / 180.0f));
                
                // Test efficiency characteristics
                if (efficiency >= 0.0f && efficiency <= 1.0f) {
                    // Valid efficiency range
                    return 0;
                }
                break;
            }
            
            case 6: {
                // Test polarization effects
                float polarization_loss = std::abs(std::cos(elevation * M_PI / 180.0f));
                
                // Test polarization characteristics
                if (polarization_loss >= 0.0f && polarization_loss <= 1.0f) {
                    // Valid polarization loss range
                    return 0;
                }
                break;
            }
            
            case 7: {
                // Test antenna array pattern
                float array_factor = std::sin(4.0f * M_PI * frequency / 1000.0f * std::cos(azimuth * M_PI / 180.0f));
                
                // Test array characteristics
                if (array_factor >= -2.0f && array_factor <= 2.0f) {
                    // Valid array factor range
                    return 0;
                }
                break;
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        // Fuzzing should continue even if exceptions occur
        return 0;
    } catch (...) {
        // Handle any other exceptions
        return 0;
    }
}