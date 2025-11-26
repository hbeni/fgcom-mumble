#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <limits>

// Include FGCom radio propagation headers
// #include "../../client/mumble-plugin/lib/radio_model.h"
// #include "../../client/mumble-plugin/lib/propagation_physics.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0;
    
    FuzzedDataProvider fdp(Data, Size);
    
    try {
        // Timeout protection for long operations
        auto start = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(20);
        
        // Extract radio propagation parameters
        float frequency = fdp.ConsumeFloatingPointInRange<float>(118.0f, 137.0f);
        double lat1 = fdp.ConsumeFloatingPointInRange<double>(-90.0, 90.0);
        double lon1 = fdp.ConsumeFloatingPointInRange<double>(-180.0, 180.0);
        double lat2 = fdp.ConsumeFloatingPointInRange<double>(-90.0, 90.0);
        double lon2 = fdp.ConsumeFloatingPointInRange<double>(-180.0, 180.0);
        double altitude1 = fdp.ConsumeFloatingPointInRange<double>(0.0, 50000.0);
        double altitude2 = fdp.ConsumeFloatingPointInRange<double>(0.0, 50000.0);
        float power = fdp.ConsumeFloatingPointInRange<float>(1.0f, 1000.0f);
        
        // Additional parameters
        float antenna_gain = fdp.ConsumeFloatingPointInRange<float>(0.0f, 20.0f);
        float noise_floor = fdp.ConsumeFloatingPointInRange<float>(-120.0f, -60.0f);
        bool line_of_sight = fdp.ConsumeBool();
        
        // Test radio propagation calculations
        // Distance calculation
        double dx = lat1 - lat2;
        double dy = lon1 - lon2;
        double distance_km = std::sqrt(dx*dx + dy*dy) * 111.0;
        
        // Path loss calculation (simplified free space path loss)
        double path_loss = 20.0 * std::log10(distance_km) + 20.0 * std::log10(frequency) + 32.45;
        
        // Signal strength calculation
        double signal_strength = power - path_loss + antenna_gain;
        
        // Fresnel zone calculation
        double fresnel_radius = 17.3 * std::sqrt(distance_km / (4.0 * frequency));
        
        // Line of sight calculation
        double earth_radius = 6371000.0; // meters
        double horizon_distance1 = std::sqrt(2.0 * earth_radius * altitude1);
        double horizon_distance2 = std::sqrt(2.0 * earth_radius * altitude2);
        bool los_clear = (horizon_distance1 + horizon_distance2) >= distance_km * 1000.0;
        
        // Atmospheric absorption (simplified)
        double absorption = 0.003 * distance_km * (frequency / 1000.0);
        
        // Terrain shadowing (simplified)
        double terrain_loss = line_of_sight ? 0.0 : 20.0 * std::log10(1.0 + (altitude1 + altitude2) / 1000.0);
        
        // Final signal quality
        double final_signal = signal_strength - absorption - terrain_loss;
        double snr = final_signal - noise_floor;
        
        // Test edge cases
        if (std::isnan(distance_km) || std::isinf(distance_km)) return 0;
        if (std::isnan(signal_strength) || std::isinf(signal_strength)) return 0;
        if (std::isnan(snr) || std::isinf(snr)) return 0;
        
        // Test with extreme values
        if (distance_km > 100000.0) distance_km = 100000.0;
        if (frequency > 1000.0) frequency = 1000.0;
        if (power > 10000.0) power = 10000.0;
        
        // Test coordinate edge cases
        if (lat1 == lat2 && lon1 == lon2) {
            // Same location - test zero distance
            distance_km = 0.001; // Minimum distance
        }
        
        // Test frequency edge cases
        if (frequency < 0.1) frequency = 0.1;
        if (frequency > 10000.0) frequency = 10000.0;
        
        // Test power edge cases
        if (power < 0.001) power = 0.001;
        if (power > 100000.0) power = 100000.0;
        
        // Timeout check
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            return 0;
        }
        
    } catch (const std::exception& e) {
        // Catch and ignore exceptions to continue fuzzing
        return 0;
    } catch (...) {
        // Catch all other exceptions
        return 0;
    }
    
    return 0;
}
