#include "propagation_physics.h"
#include <algorithm>

namespace FGCom_PropagationPhysics {

double calculateFreeSpacePathLoss(double distance_km, double frequency_mhz) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0) {
        return 0.0;
    }
    
    double distance_m = distance_km * 1000.0;
    double frequency_hz = frequency_mhz * 1e6;
    double wavelength = SPEED_OF_LIGHT / frequency_hz;
    
    // Free space path loss formula: FSPL = 20*log10(d) + 20*log10(f) + 32.45
    // where d is distance in km and f is frequency in MHz
    double fspl = 20.0 * log10(distance_km) + 20.0 * log10(frequency_mhz) + 32.45;
    
    return fspl;
}

double calculateAtmosphericAbsorption(double distance_km, double frequency_mhz, 
                                    double altitude_m, double temperature_c, 
                                    double humidity_percent) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0) {
        return 0.0;
    }
    
    // Simplified atmospheric absorption model
    // Based on ITU-R P.676-13 recommendations
    
    double absorption_db_per_km = 0.0;
    
    // Oxygen absorption (dominant at 60 GHz, but present at all frequencies)
    if (frequency_mhz > 1000.0) {  // UHF and above
        double oxygen_absorption = 0.001 * pow(frequency_mhz / 1000.0, 2.0);
        absorption_db_per_km += oxygen_absorption;
    }
    
    // Water vapor absorption (dominant at 22 GHz, but present at all frequencies)
    if (frequency_mhz > 1000.0) {  // UHF and above
        double water_vapor_absorption = 0.0005 * pow(frequency_mhz / 1000.0, 1.5) * 
                                      (humidity_percent / 100.0);
        absorption_db_per_km += water_vapor_absorption;
    }
    
    // Altitude factor (absorption decreases with altitude)
    double altitude_factor = exp(-altitude_m / 8000.0);  // Scale height ~8km
    
    // Temperature factor (absorption increases with temperature)
    double temperature_factor = 1.0 + (temperature_c - 20.0) * 0.01;
    
    double total_absorption = absorption_db_per_km * distance_km * altitude_factor * temperature_factor;
    
    return total_absorption;
}

double calculateTroposphericDucting(double distance_km, double frequency_mhz,
                                  double altitude_m, double temperature_c,
                                  double humidity_percent) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0) {
        return 0.0;
    }
    
    // Tropospheric ducting is most effective at VHF frequencies (30-300 MHz)
    if (frequency_mhz < 30.0 || frequency_mhz > 300.0) {
        return 0.0;  // No ducting effects outside VHF
    }
    
    // Ducting conditions: temperature inversion and high humidity
    double temperature_inversion = std::max(0.0, temperature_c - 15.0);  // Inversion strength
    double humidity_factor = humidity_percent / 100.0;
    
    // Ducting probability increases with distance and frequency
    double ducting_probability = std::min(0.8, distance_km / 200.0) * 
                                std::min(1.0, frequency_mhz / 150.0) *
                                temperature_inversion * humidity_factor;
    
    // Ducting gain (can be significant, up to 20-30 dB)
    double ducting_gain_db = ducting_probability * 25.0;  // Max 25 dB gain
    
    // Altitude factor (ducting more effective at lower altitudes)
    double altitude_factor = std::max(0.1, 1.0 - altitude_m / 10000.0);
    
    return ducting_gain_db * altitude_factor;
}

double calculateAntennaHeightGain(double antenna_height_m, double frequency_mhz, 
                                 double distance_km) {
    if (antenna_height_m <= 0.0 || frequency_mhz <= 0.0 || distance_km <= 0.0) {
        return 0.0;
    }
    
    // Antenna height gain is more significant at higher frequencies
    double frequency_factor = std::min(1.0, frequency_mhz / 100.0);
    
    // Height gain formula: 20*log10(h) where h is height in meters
    double height_gain_db = 20.0 * log10(antenna_height_m) * frequency_factor;
    
    // Distance factor (height gain decreases with distance)
    double distance_factor = std::max(0.1, 1.0 - distance_km / 100.0);
    
    return height_gain_db * distance_factor;
}

double calculateTerrainObstructionLoss(double distance_km, double frequency_mhz,
                                     double obstruction_height_m, double antenna_height_m) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0 || obstruction_height_m <= antenna_height_m) {
        return 0.0;  // No obstruction if antenna is higher
    }
    
    // Fresnel zone calculation
    double wavelength = SPEED_OF_LIGHT / (frequency_mhz * 1e6);
    double fresnel_radius = sqrt(wavelength * distance_km * 1000.0 / 2.0);
    
    // Obstruction loss depends on how much the obstruction blocks the Fresnel zone
    double obstruction_clearance = obstruction_height_m - antenna_height_m;
    double fresnel_clearance_ratio = obstruction_clearance / fresnel_radius;
    
    double obstruction_loss_db = 0.0;
    
    if (fresnel_clearance_ratio < 0.0) {
        // Complete obstruction
        obstruction_loss_db = 20.0 * log10(frequency_mhz / 100.0) + 30.0;
    } else if (fresnel_clearance_ratio < 0.6) {
        // Partial obstruction
        obstruction_loss_db = 20.0 * log10(frequency_mhz / 100.0) + 10.0 * 
                            (0.6 - fresnel_clearance_ratio);
    }
    
    return obstruction_loss_db;
}

double calculateRainAttenuation(double distance_km, double frequency_mhz, 
                               double rain_rate_mmh) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0 || rain_rate_mmh <= 0.0) {
        return 0.0;
    }
    
    // Rain attenuation is only significant at UHF and above
    if (frequency_mhz < 1000.0) {
        return 0.0;  // Negligible at VHF
    }
    
    // ITU-R P.838-3 rain attenuation model
    double frequency_ghz = frequency_mhz / 1000.0;
    
    // Coefficients for rain attenuation (simplified)
    double k = 0.001 * pow(frequency_ghz, 1.5);
    double alpha = 0.8;
    
    double rain_attenuation_db = k * pow(rain_rate_mmh, alpha) * distance_km;
    
    return rain_attenuation_db;
}

double calculateTotalPropagationLoss(double distance_km, double frequency_mhz,
                                   double altitude_m, double antenna_height_m,
                                   double temperature_c, double humidity_percent,
                                   double rain_rate_mmh, double obstruction_height_m) {
    if (distance_km <= 0.0 || frequency_mhz <= 0.0) {
        return 0.0;
    }
    
    double total_loss_db = 0.0;
    
    // 1. Free space path loss (always present)
    total_loss_db += calculateFreeSpacePathLoss(distance_km, frequency_mhz);
    
    // 2. Atmospheric absorption
    total_loss_db += calculateAtmosphericAbsorption(distance_km, frequency_mhz, 
                                                  altitude_m, temperature_c, humidity_percent);
    
    // 3. Tropospheric ducting (VHF only, can be negative = gain)
    if (frequency_mhz >= 30.0 && frequency_mhz <= 300.0) {
        double ducting_effect = calculateTroposphericDucting(distance_km, frequency_mhz,
                                                           altitude_m, temperature_c, humidity_percent);
        total_loss_db -= ducting_effect;  // Negative because it's a gain
    }
    
    // 4. Antenna height gain (negative because it's a gain)
    double height_gain = calculateAntennaHeightGain(antenna_height_m, frequency_mhz, distance_km);
    total_loss_db -= height_gain;
    
    // 5. Terrain obstruction loss
    total_loss_db += calculateTerrainObstructionLoss(distance_km, frequency_mhz,
                                                   obstruction_height_m, antenna_height_m);
    
    // 6. Rain attenuation (UHF and above)
    total_loss_db += calculateRainAttenuation(distance_km, frequency_mhz, rain_rate_mmh);
    
    return total_loss_db;
}

double dbToLinear(double loss_db) {
    if (loss_db <= 0.0) {
        return 1.0;
    }
    return pow(10.0, -loss_db / 10.0);
}

double linearToDb(double linear) {
    if (linear <= 0.0) {
        return 100.0;  // Very high loss
    }
    return -10.0 * log10(linear);
}

AtmosphericConditions getAtmosphericConditions(double latitude, double longitude, 
                                              double altitude_m) {
    AtmosphericConditions conditions;
    
    // Simplified atmospheric model based on altitude and latitude
    // In production, this would integrate with weather APIs
    
    // Temperature decreases with altitude (lapse rate ~6.5°C/km)
    conditions.temperature_c = 15.0 - (altitude_m / 1000.0) * 6.5;
    
    // Humidity decreases with altitude
    conditions.humidity_percent = std::max(10.0, 80.0 - (altitude_m / 1000.0) * 10.0);
    
    // Pressure decreases with altitude
    conditions.pressure_hpa = 1013.25 * exp(-altitude_m / 8400.0);
    
    // Rain rate (simplified - in production would use weather data)
    conditions.rain_rate_mmh = 0.0;  // Default to no rain
    
    return conditions;
}

} // namespace FGCom_PropagationPhysics
