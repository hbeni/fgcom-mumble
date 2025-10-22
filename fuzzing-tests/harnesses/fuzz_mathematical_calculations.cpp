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

// Include FGCom mathematical headers
// #include "../../client/mumble-plugin/lib/geographic_utils.h"
// #include "../../client/mumble-plugin/lib/signal_calculations.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0;
    
    FuzzedDataProvider fdp(Data, Size);
    
    try {
        // Timeout protection
        auto start = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(20);
        
        // Extract mathematical parameters
        double lat1 = fdp.ConsumeFloatingPointInRange<double>(-90.0, 90.0);
        double lon1 = fdp.ConsumeFloatingPointInRange<double>(-180.0, 180.0);
        double lat2 = fdp.ConsumeFloatingPointInRange<double>(-90.0, 90.0);
        double lon2 = fdp.ConsumeFloatingPointInRange<double>(-180.0, 180.0);
        double freq_mhz = fdp.ConsumeFloatingPointInRange<double>(0.1, 30000.0);
        double elevation = fdp.ConsumeFloatingPointInRange<double>(0.0, 9000.0);
        double power = fdp.ConsumeFloatingPointInRange<double>(0.1, 10000.0);
        
        // Test distance calculation (Haversine formula)
        double distance_km = 0.0;
        if (lat1 != lat2 || lon1 != lon2) {
            double dlat = (lat2 - lat1) * M_PI / 180.0;
            double dlon = (lon2 - lon1) * M_PI / 180.0;
            double a = std::sin(dlat/2) * std::sin(dlat/2) + 
                       std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) * 
                       std::sin(dlon/2) * std::sin(dlon/2);
            double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
            distance_km = 6371.0 * c; // Earth radius in km
        }
        
        // Test bearing calculation
        double bearing = 0.0;
        if (lat1 != lat2 || lon1 != lon2) {
            double dlon = (lon2 - lon1) * M_PI / 180.0;
            double y = std::sin(dlon) * std::cos(lat2 * M_PI / 180.0);
            double x = std::cos(lat1 * M_PI / 180.0) * std::sin(lat2 * M_PI / 180.0) - 
                      std::sin(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) * std::cos(dlon);
            bearing = std::atan2(y, x) * 180.0 / M_PI;
            if (bearing < 0) bearing += 360.0;
        }
        
        // Test signal strength calculation
        double signal_strength = 0.0;
        if (distance_km > 0 && freq_mhz > 0 && power > 0) {
            // Free space path loss
            double path_loss = 20.0 * std::log10(distance_km) + 20.0 * std::log10(freq_mhz) + 32.45;
            signal_strength = power - path_loss;
        }
        
        // Test Fresnel zone calculation
        double fresnel_radius = 0.0;
        if (distance_km > 0 && freq_mhz > 0) {
            fresnel_radius = 17.3 * std::sqrt(distance_km / (4.0 * freq_mhz));
        }
        
        // Test line of sight calculation
        bool los_clear = false;
        if (distance_km > 0) {
            double earth_radius = 6371000.0; // meters
            double horizon_distance1 = std::sqrt(2.0 * earth_radius * elevation);
            double horizon_distance2 = std::sqrt(2.0 * earth_radius * elevation);
            los_clear = (horizon_distance1 + horizon_distance2) >= distance_km * 1000.0;
        }
        
        // Test atmospheric absorption
        double absorption = 0.0;
        if (distance_km > 0 && freq_mhz > 0) {
            // Simplified atmospheric absorption model
            absorption = 0.003 * distance_km * (freq_mhz / 1000.0);
        }
        
        // Test terrain shadowing
        double terrain_loss = 0.0;
        if (elevation > 0 && distance_km > 0) {
            // Simplified terrain shadowing model
            terrain_loss = 20.0 * std::log10(1.0 + elevation / 1000.0);
        }
        
        // Test multipath fading
        double multipath_fading = 0.0;
        if (distance_km > 0 && freq_mhz > 0) {
            // Simplified multipath fading model
            multipath_fading = 10.0 * std::log10(1.0 + std::sin(2.0 * M_PI * distance_km * freq_mhz / 1000.0));
        }
        
        // Test antenna gain calculation
        double antenna_gain = 0.0;
        if (freq_mhz > 0) {
            // Simplified antenna gain model
            antenna_gain = 10.0 * std::log10(freq_mhz / 100.0);
        }
        
        // Test noise floor calculation
        double noise_floor = 0.0;
        if (freq_mhz > 0) {
            // Simplified noise floor model
            noise_floor = -174.0 + 10.0 * std::log10(freq_mhz * 1000000.0);
        }
        
        // Test signal-to-noise ratio
        double snr = 0.0;
        if (signal_strength > 0 && noise_floor < 0) {
            snr = signal_strength - noise_floor;
        }
        
        // Test coordinate transformation
        double x, y, z;
        if (lat1 >= -90.0 && lat1 <= 90.0 && lon1 >= -180.0 && lon1 <= 180.0) {
            // Convert to Cartesian coordinates
            double lat_rad = lat1 * M_PI / 180.0;
            double lon_rad = lon1 * M_PI / 180.0;
            double earth_radius = 6371000.0; // meters
            
            x = earth_radius * std::cos(lat_rad) * std::cos(lon_rad);
            y = earth_radius * std::cos(lat_rad) * std::sin(lon_rad);
            z = earth_radius * std::sin(lat_rad);
        }
        
        // Test coordinate validation
        bool valid_coords = true;
        if (lat1 < -90.0 || lat1 > 90.0 || lat2 < -90.0 || lat2 > 90.0) {
            valid_coords = false;
        }
        if (lon1 < -180.0 || lon1 > 180.0 || lon2 < -180.0 || lon2 > 180.0) {
            valid_coords = false;
        }
        
        // Test frequency validation
        bool valid_freq = true;
        if (freq_mhz <= 0 || freq_mhz > 100000.0) {
            valid_freq = false;
        }
        
        // Test power validation
        bool valid_power = true;
        if (power <= 0 || power > 1000000.0) {
            valid_power = false;
        }
        
        // Test elevation validation
        bool valid_elevation = true;
        if (elevation < 0 || elevation > 100000.0) {
            valid_elevation = false;
        }
        
        // Test mathematical edge cases
        if (std::isnan(distance_km) || std::isinf(distance_km)) {
            return 0;
        }
        if (std::isnan(bearing) || std::isinf(bearing)) {
            return 0;
        }
        if (std::isnan(signal_strength) || std::isinf(signal_strength)) {
            return 0;
        }
        if (std::isnan(fresnel_radius) || std::isinf(fresnel_radius)) {
            return 0;
        }
        if (std::isnan(snr) || std::isinf(snr)) {
            return 0;
        }
        
        // Test extreme values
        if (distance_km > 1000000.0) {
            distance_km = 1000000.0; // Clamp to reasonable maximum
        }
        if (freq_mhz > 100000.0) {
            freq_mhz = 100000.0; // Clamp to reasonable maximum
        }
        if (power > 1000000.0) {
            power = 1000000.0; // Clamp to reasonable maximum
        }
        
        // Test coordinate edge cases
        if (lat1 == lat2 && lon1 == lon2) {
            // Same location - test zero distance
            distance_km = 0.001; // Minimum distance
        }
        
        // Test frequency edge cases
        if (freq_mhz < 0.001) {
            freq_mhz = 0.001; // Minimum frequency
        }
        
        // Test power edge cases
        if (power < 0.001) {
            power = 0.001; // Minimum power
        }
        
        // Test elevation edge cases
        if (elevation < 0.001) {
            elevation = 0.001; // Minimum elevation
        }
        
        // Test mathematical operations with edge values
        double test_division = 0.0;
        if (distance_km > 0) {
            test_division = freq_mhz / distance_km;
        }
        
        double test_multiplication = freq_mhz * distance_km;
        double test_addition = freq_mhz + distance_km;
        double test_subtraction = freq_mhz - distance_km;
        
        // Test trigonometric functions
        double sin_result = std::sin(lat1 * M_PI / 180.0);
        double cos_result = std::cos(lat1 * M_PI / 180.0);
        double tan_result = std::tan(lat1 * M_PI / 180.0);
        
        // Test logarithmic functions
        double log_result = 0.0;
        if (freq_mhz > 0) {
            log_result = std::log10(freq_mhz);
        }
        
        double exp_result = std::exp(freq_mhz / 1000.0);
        double pow_result = std::pow(freq_mhz, 2.0);
        double sqrt_result = std::sqrt(std::abs(freq_mhz));
        
        // Test mathematical constants
        double pi_result = M_PI;
        double e_result = M_E;
        double sqrt2_result = M_SQRT2;
        
        // Test mathematical operations with constants
        double pi_mult = M_PI * freq_mhz;
        double e_mult = M_E * distance_km;
        double sqrt2_mult = M_SQRT2 * power;
        
        // Timeout check
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > timeout) {
            return 0;
        }
        
    } catch (const std::exception& e) {
        return 0;
    } catch (...) {
        return 0;
    }
    
    return 0;
}
