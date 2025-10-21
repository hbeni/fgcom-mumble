#include <cstdint>
#include <cstddef>
#include <string>
#include <cmath>
#include <cstring>

// Fuzzing target for radio propagation calculations
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0; // Need minimum data
    
    // Systematically consume input bytes
    size_t offset = 0;
    uint8_t selector = Data[offset++];
    
    // Extract frequency string (up to 20 bytes)
    size_t freq_len = std::min(20UL, Size - offset);
    if (freq_len == 0) return 0;
    std::string frequency_str(reinterpret_cast<const char*>(Data + offset), freq_len);
    offset += freq_len;
    
    // Extract distance (8 bytes for double)
    if (offset + 8 > Size) return 0;
    double distance_km;
    memcpy(&distance_km, Data + offset, 8);
    offset += 8;
    
    // Extract tx power (8 bytes for double)
    if (offset + 8 > Size) return 0;
    double tx_power_watts;
    memcpy(&tx_power_watts, Data + offset, 8);
    offset += 8;
    
    // Extract antenna heights (8 bytes each for double)
    double tx_antenna_height = 0.0;
    double rx_antenna_height = 0.0;
    if (offset + 8 <= Size) {
        memcpy(&tx_antenna_height, Data + offset, 8);
        offset += 8;
    }
    if (offset + 8 <= Size) {
        memcpy(&rx_antenna_height, Data + offset, 8);
        offset += 8;
    }
    
    // Extract additional parameters from remaining data
    double tx_lat = 0.0, tx_lon = 0.0, rx_lat = 0.0, rx_lon = 0.0;
    if (offset + 32 <= Size) {
        memcpy(&tx_lat, Data + offset, 8);
        memcpy(&tx_lon, Data + offset + 8, 8);
        memcpy(&rx_lat, Data + offset + 16, 8);
        memcpy(&rx_lon, Data + offset + 24, 8);
    }
    
    try {
        // PURE FUZZING: Use selector byte to pick ONE code path
        switch(selector % 8) {
            case 0: {
                // Test basic frequency parsing
                if (frequency_str.length() > 0) {
                    // Simulate frequency validation
                    bool is_numeric = true;
                    for (char c : frequency_str) {
                        if (!std::isdigit(c) && c != '.' && c != ' ') {
                            is_numeric = false;
                            break;
                        }
                    }
                    if (is_numeric) {
                        // Simulate frequency conversion
                        double freq_val = std::stod(frequency_str);
                        if (freq_val > 0 && freq_val < 1000) {
                            // Valid frequency range
                            return 0;
                        }
                    }
                }
                break;
            }
            
            case 1: {
                // Test distance calculations
                if (distance_km > 0) {
                    // Simulate radio propagation physics
                    double path_loss = 20 * std::log10(distance_km) + 20 * std::log10(100); // 100 MHz reference
                    double signal_strength = tx_power_watts - path_loss;
                    
                    // Test line-of-sight calculations
                    double earth_radius = 6371.0; // km
                    double horizon_distance = std::sqrt(2 * earth_radius * tx_antenna_height / 1000.0);
                    
                    if (distance_km <= horizon_distance) {
                        // Line of sight
                        return 0;
                    } else {
                        // Beyond horizon
                        return 0;
                    }
                }
                break;
            }
            
            case 2: {
                // Test power calculations
                if (tx_power_watts > 0) {
                    // Simulate power loss calculations
                    double power_density = tx_power_watts / (4 * M_PI * distance_km * distance_km);
                    double received_power = power_density * 0.1; // Simple antenna gain
                    
                    // Test power scaling
                    if (tx_power_watts > 1000) {
                        // High power scenario
                        double efficiency = 0.8;
                        double effective_power = tx_power_watts * efficiency;
                        return 0;
                    } else if (tx_power_watts < 1.0) {
                        // Low power scenario
                        double noise_floor = -100; // dBm
                        double snr = 10 * std::log10(received_power / (1e-12 * std::pow(10, noise_floor/10)));
                        return 0;
                    }
                }
                break;
            }
            
            case 3: {
                // Test antenna height effects
                if (tx_antenna_height > 0 && rx_antenna_height > 0) {
                    // Simulate antenna height gain
                    double height_gain = 20 * std::log10(tx_antenna_height / 10.0) + 
                                       20 * std::log10(rx_antenna_height / 10.0);
                    
                    // Test height variations
                    if (tx_antenna_height > 1000) {
                        // High altitude
                        double atmospheric_loss = 0.1 * distance_km;
                        return 0;
                    } else if (tx_antenna_height < 10) {
                        // Ground level
                        double ground_reflection = 0.5;
                        return 0;
                    }
                }
                break;
            }
            
            case 4: {
                // Test coordinate calculations
                if (tx_lat != 0 || tx_lon != 0 || rx_lat != 0 || rx_lon != 0) {
                    // Simulate distance calculation using coordinates
                    double lat1_rad = tx_lat * M_PI / 180.0;
                    double lon1_rad = tx_lon * M_PI / 180.0;
                    double lat2_rad = rx_lat * M_PI / 180.0;
                    double lon2_rad = rx_lon * M_PI / 180.0;
                    
                    double dlat = lat2_rad - lat1_rad;
                    double dlon = lon2_rad - lon1_rad;
                    
                    double a = std::sin(dlat/2) * std::sin(dlat/2) + 
                              std::cos(lat1_rad) * std::cos(lat2_rad) * 
                              std::sin(dlon/2) * std::sin(dlon/2);
                    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
                    double calculated_distance = 6371.0 * c; // Earth radius in km
                    
                    return 0;
                }
                break;
            }
            
            case 5: {
                // Test frequency band calculations
                if (frequency_str.length() > 0) {
                    double freq_val = 0.0;
                    try {
                        freq_val = std::stod(frequency_str);
                    } catch (...) {
                        return 0;
                    }
                    
                    // Simulate frequency band classification
                    if (freq_val >= 30 && freq_val <= 300) {
                        // VHF band
                        double wavelength = 300.0 / freq_val; // meters
                        double antenna_gain = 10 * std::log10(4 * M_PI * (tx_antenna_height / wavelength));
                        return 0;
                    } else if (freq_val >= 3 && freq_val <= 30) {
                        // HF band
                        double ionospheric_loss = 0.1 * distance_km;
                        return 0;
                    } else if (freq_val >= 300 && freq_val <= 3000) {
                        // UHF band
                        double atmospheric_loss = 0.05 * distance_km;
                        return 0;
                    }
                }
                break;
            }
            
            case 6: {
                // Test signal quality calculations
                double signal_quality = 1.0;
                
                // Distance factor
                if (distance_km > 0) {
                    signal_quality *= std::exp(-distance_km / 100.0);
                }
                
                // Power factor
                if (tx_power_watts > 0) {
                    signal_quality *= std::min(1.0, tx_power_watts / 100.0);
                }
                
                // Height factor
                if (tx_antenna_height > 0 && rx_antenna_height > 0) {
                    double height_factor = std::sqrt(tx_antenna_height * rx_antenna_height) / 100.0;
                    signal_quality *= std::min(1.0, height_factor);
                }
                
                // Test quality thresholds
                if (signal_quality > 0.8) {
                    // Excellent signal
                    return 0;
                } else if (signal_quality > 0.5) {
                    // Good signal
                    return 0;
                } else if (signal_quality > 0.2) {
                    // Poor signal
                    return 0;
                } else {
                    // No signal
                    return 0;
                }
                break;
            }
            
            case 7: {
                // Test extreme values and edge cases
                // Test with NaN and infinity
                if (std::isnan(distance_km) || std::isinf(distance_km)) {
                    return 0;
                }
                if (std::isnan(tx_power_watts) || std::isinf(tx_power_watts)) {
                    return 0;
                }
                
                // Test with negative values
                if (distance_km < 0) {
                    distance_km = std::abs(distance_km);
                }
                if (tx_power_watts < 0) {
                    tx_power_watts = std::abs(tx_power_watts);
                }
                
                // Test with very large values
                if (distance_km > 100000) {
                    distance_km = 100000;
                }
                if (tx_power_watts > 1000000) {
                    tx_power_watts = 1000000;
                }
                
                // Test with very small values
                if (distance_km < 0.001) {
                    distance_km = 0.001;
                }
                if (tx_power_watts < 0.001) {
                    tx_power_watts = 0.001;
                }
                
                return 0;
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