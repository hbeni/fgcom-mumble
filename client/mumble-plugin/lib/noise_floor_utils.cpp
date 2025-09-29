#include "atmospheric_noise.h"
#include <cmath>
#include <string>

namespace NoiseFloorUtils {

float dbmToMicrovolts(float dbm, float impedance_ohms) {
    // Convert dBm to microvolts across specified impedance
    // P = V^2 / R, so V = sqrt(P * R)
    // dBm to watts: P = 10^((dBm - 30) / 10)
    float power_watts = std::pow(10.0f, (dbm - 30.0f) / 10.0f);
    float voltage_volts = std::sqrt(power_watts * impedance_ohms);
    return voltage_volts * 1e6f;  // Convert to microvolts
}

float microvoltsToDbm(float microvolts, float impedance_ohms) {
    // Convert microvolts to dBm across specified impedance
    float voltage_volts = microvolts / 1e6f;
    float power_watts = (voltage_volts * voltage_volts) / impedance_ohms;
    return 10.0f * std::log10(power_watts) + 30.0f;  // Convert to dBm
}

std::string getSMeterDescription(int s_meter) {
    switch (s_meter) {
        case 0: return "S0 - Very weak signal";
        case 1: return "S1 - Weak signal";
        case 2: return "S2 - Weak signal";
        case 3: return "S3 - Fair signal";
        case 4: return "S4 - Fair signal";
        case 5: return "S5 - Good signal";
        case 6: return "S6 - Good signal";
        case 7: return "S7 - Strong signal";
        case 8: return "S8 - Strong signal";
        case 9: return "S9 - Very strong signal";
        default: 
            if (s_meter > 9) {
                return "S9+ - Extremely strong signal";
            }
            return "S0 - Very weak signal";
    }
}

float getSMeterRange(int s_meter) {
    // Return typical dBm range for S-meter reading
    switch (s_meter) {
        case 0: return -127.0f;  // S0
        case 1: return -121.0f;  // S1
        case 2: return -115.0f;  // S2
        case 3: return -109.0f;  // S3
        case 4: return -103.0f;  // S4
        case 5: return -97.0f;   // S5
        case 6: return -91.0f;   // S6
        case 7: return -85.0f;   // S7
        case 8: return -79.0f;   // S8
        case 9: return -73.0f;   // S9
        default:
            if (s_meter > 9) {
                return -73.0f + ((s_meter - 9) * 6.0f);  // S9+
            }
            return -127.0f;  // S0
    }
}

std::string assessNoiseFloorQuality(float dbm) {
    if (dbm < -140.0f) {
        return "Excellent - Very low noise floor, ideal for weak signal work";
    } else if (dbm < -125.0f) {
        return "Good - Low noise floor, good for most operations";
    } else if (dbm < -115.0f) {
        return "Fair - Moderate noise floor, acceptable for strong signals";
    } else if (dbm < -100.0f) {
        return "Poor - High noise floor, may affect weak signal reception";
    } else {
        return "Very Poor - Very high noise floor, significant impact on reception";
    }
}

bool isNoiseFloorAcceptable(float dbm, EnvironmentType env_type) {
    switch (env_type) {
        case EnvironmentType::POLAR:
            return dbm < -135.0f;  // Should be S0-S1 in polar areas
        case EnvironmentType::DESERT:
            return dbm < -130.0f;  // Should be S0-S2 in desert areas
        case EnvironmentType::OCEAN:
            return dbm < -130.0f;  // Should be S0-S2 in ocean areas
        case EnvironmentType::REMOTE:
            return dbm < -125.0f;  // Should be S1-S3 in remote areas
        case EnvironmentType::SUBURBAN:
            return dbm < -115.0f;  // Should be S3-S5 in suburban areas
        case EnvironmentType::URBAN:
            return dbm < -100.0f;  // Should be S5-S7 in urban areas
        case EnvironmentType::INDUSTRIAL:
            return dbm < -85.0f;   // Should be S7-S9+ in industrial areas
        default:
            return dbm < -115.0f;  // Default to suburban standard
    }
}

float predictUrbanNoise(float time_of_day_factor, float weather_factor) {
    // Urban noise prediction based on time and weather
    float base_urban_noise = -107.5f;  // S5-S7 baseline
    
    // Time of day effects (higher during business hours)
    float time_effect = time_of_day_factor * 5.0f;
    
    // Weather effects (thunderstorms increase noise)
    float weather_effect = weather_factor * 3.0f;
    
    return base_urban_noise + time_effect + weather_effect;
}

float predictIndustrialNoise(float activity_level, float time_of_day_factor) {
    // Industrial noise prediction based on activity and time
    float base_industrial_noise = -95.0f;  // S7-S9+ baseline
    
    // Activity level (0.0 = no activity, 1.0 = full activity)
    float activity_effect = activity_level * 10.0f;
    
    // Time of day effects (higher during work hours)
    float time_effect = time_of_day_factor * 8.0f;
    
    return base_industrial_noise + activity_effect + time_effect;
}

float predictRemoteNoise(float atmospheric_activity, float solar_activity) {
    // Remote area noise prediction based on atmospheric and solar activity
    float base_remote_noise = -132.5f;  // S1-S3 baseline
    
    // Atmospheric activity (thunderstorms, precipitation)
    float atmospheric_effect = atmospheric_activity * 5.0f;
    
    // Solar activity (higher solar flux = more atmospheric noise)
    float solar_effect = (solar_activity - 100.0f) / 50.0f * 2.0f;
    
    return base_remote_noise + atmospheric_effect + solar_effect;
}

float predictOceanNoise(float atmospheric_activity, float solar_activity, float laptop_noise_factor) {
    // Ocean noise prediction - very quiet RF environment
    float base_ocean_noise = -137.5f;  // S0-S2 baseline
    
    // Atmospheric activity (distant thunderstorms)
    float atmospheric_effect = atmospheric_activity * 3.0f;  // Less effect than land
    
    // Solar activity (higher solar flux = more atmospheric noise)
    float solar_effect = (solar_activity - 100.0f) / 50.0f * 1.5f;  // Less effect than land
    
    // Laptop power supply noise (main local noise source on sailboats)
    float laptop_effect = laptop_noise_factor * 2.0f;  // 0.0 = no laptop, 1.0 = laptop with switching supply
    
    return base_ocean_noise + atmospheric_effect + solar_effect + laptop_effect;
}

float predictDesertNoise(float atmospheric_activity, float solar_activity, float temperature_factor) {
    // Desert noise prediction - very quiet RF environment
    float base_desert_noise = -137.5f;  // S0-S2 baseline
    
    // Low atmospheric activity - deserts have less thunderstorm activity
    float atmospheric_effect = atmospheric_activity * 2.0f;  // Less effect than other land areas
    
    // Solar activity (higher solar flux = more atmospheric noise)
    float solar_effect = (solar_activity - 100.0f) / 50.0f * 1.0f;  // Less effect than other areas
    
    // Dry air reduces atmospheric absorption and noise
    float dry_air_effect = -2.0f;  // Dry air benefit
    
    // Clear ionospheric conditions
    float clear_conditions_effect = -1.0f;  // Clear conditions benefit
    
    // Temperature extremes don't affect noise floor significantly
    // but can affect equipment performance
    float temperature_effect = temperature_factor * 0.5f;  // Minimal effect
    
    return base_desert_noise + atmospheric_effect + solar_effect + dry_air_effect + 
           clear_conditions_effect + temperature_effect;
}

float predictPolarNoise(float atmospheric_activity, float solar_activity, float auroral_activity, float seasonal_factor) {
    // Polar noise prediction - quietest possible RF environment
    float base_polar_noise = -140.0f;  // S0-S1 baseline
    
    // Extremely low atmospheric activity - minimal thunderstorm activity globally
    float atmospheric_effect = atmospheric_activity * 1.0f;  // Minimal effect
    
    // Solar activity (higher solar flux = more atmospheric noise)
    float solar_effect = (solar_activity - 100.0f) / 50.0f * 0.5f;  // Minimal effect
    
    // Very dry air reduces atmospheric absorption and noise
    float dry_air_effect = -3.0f;  // Very dry air benefit
    
    // Minimal human activity = virtually no man-made noise
    float human_activity_effect = -2.0f;  // Minimal man-made interference
    
    // Seasonal variation - even quieter during polar winter
    float seasonal_effect = seasonal_factor * -2.0f;  // -1.0 = summer, 1.0 = winter
    
    // Auroral activity can add noise during geomagnetic storms
    // but also creates unique propagation opportunities
    float auroral_effect = auroral_activity * 1.0f;  // 0.0 = no aurora, 1.0 = strong aurora
    
    return base_polar_noise + atmospheric_effect + solar_effect + dry_air_effect + 
           human_activity_effect + seasonal_effect + auroral_effect;
}

float predictEVChargingNoise(float charging_activity, float time_of_day_factor, float weather_factor) {
    // EV Charging Station noise prediction based on charging activity and environmental factors
    float base_ev_noise = -120.0f;  // S3-S5 baseline for EV charging areas
    
    // Charging activity level (0.0 = no charging, 1.0 = full charging activity)
    float activity_effect = charging_activity * 8.0f;  // Up to 8 dB from high charging activity
    
    // Time of day effects (more charging during day and evening)
    float time_effect = time_of_day_factor * 4.0f;  // Up to 4 dB variation by time of day
    
    // Weather effects (wet conditions can increase noise)
    float weather_effect = (weather_factor - 1.0f) * 2.0f;  // Weather-related noise variation
    
    return base_ev_noise + activity_effect + time_effect + weather_effect;
}

float predictSubstationNoise(float voltage_level, float capacity_mva, float time_of_day_factor, float weather_factor) {
    // Substation noise prediction based on voltage level, capacity, and environmental factors
    float base_substation_noise = -110.0f;  // S4-S6 baseline for substations
    
    // Voltage level effect (higher voltage = more noise)
    float voltage_effect = (voltage_level / 100.0f) * 3.0f;  // Up to 3 dB from high voltage
    
    // Capacity effect (larger substations = more noise)
    float capacity_effect = (capacity_mva / 100.0f) * 2.0f;  // Up to 2 dB from large capacity
    
    // Time of day effects (more activity during day)
    float time_effect = (time_of_day_factor - 1.0f) * 2.0f;  // Time-related noise variation
    
    // Weather effects (wet conditions increase noise)
    float weather_effect = (weather_factor - 1.0f) * 1.5f;  // Weather-related noise variation
    
    return base_substation_noise + voltage_effect + capacity_effect + time_effect + weather_effect;
}

float predictPowerStationNoise(float capacity_mw, float output_mw, float time_of_day_factor, float weather_factor) {
    // Power station noise prediction based on capacity, output, and environmental factors
    float base_power_noise = -105.0f;  // S5-S7 baseline for power stations
    
    // Capacity effect (larger power stations = more noise)
    float capacity_effect = (capacity_mw / 100.0f) * 4.0f;  // Up to 4 dB from large capacity
    
    // Output effect (higher output = more noise)
    float output_factor = output_mw / capacity_mw;
    float output_effect = output_factor * 2.0f;  // Up to 2 dB from high output
    
    // Time of day effects (more activity during day)
    float time_effect = (time_of_day_factor - 1.0f) * 1.5f;  // Time-related noise variation
    
    // Weather effects (wet conditions increase noise)
    float weather_effect = (weather_factor - 1.0f) * 2.0f;  // Weather-related noise variation
    
    return base_power_noise + capacity_effect + output_effect + time_effect + weather_effect;
}

} // namespace NoiseFloorUtils
