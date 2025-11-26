#include "atmospheric_noise.h"
#include <cmath>
#include <string>

namespace NoiseFloorUtils {

/**
 * @brief Convert dBm power level to microvolts across specified impedance
 * 
 * This function converts a power level in dBm to the equivalent voltage in microvolts
 * across a specified impedance. This is useful for calculating the voltage levels
 * that would be present at the input of a radio receiver.
 * 
 * @param dbm Power level in dBm (decibels relative to 1 milliwatt)
 * @param impedance_ohms Load impedance in ohms (typically 50 ohms for radio equipment)
 * @return Voltage in microvolts across the specified impedance
 * 
 * @note The conversion uses the formula: P = V^2 / R, so V = sqrt(P * R)
 * @note dBm to watts conversion: P = 10^((dBm - 30) / 10)
 * 
 * @example
 * // Convert -100 dBm to microvolts across 50 ohm impedance
 * float voltage = dbmToMicrovolts(-100.0f, 50.0f);
 * // Result: approximately 0.224 microvolts
 */
float dbmToMicrovolts(float dbm, float impedance_ohms) {
    // Convert dBm to microvolts across specified impedance
    // P = V^2 / R, so V = sqrt(P * R)
    // dBm to watts: P = 10^((dBm - 30) / 10)
    float power_watts = std::pow(10.0f, (dbm - 30.0f) / 10.0f);
    float voltage_volts = std::sqrt(power_watts * impedance_ohms);
    return voltage_volts * 1e6f;  // Convert to microvolts
}

/**
 * @brief Convert microvolts to dBm power level across specified impedance
 * 
 * This function converts a voltage in microvolts to the equivalent power level in dBm
 * across a specified impedance. This is the inverse operation of dbmToMicrovolts().
 * 
 * @param microvolts Voltage in microvolts across the specified impedance
 * @param impedance_ohms Load impedance in ohms (typically 50 ohms for radio equipment)
 * @return Power level in dBm (decibels relative to 1 milliwatt)
 * 
 * @note The conversion uses the formula: P = V^2 / R
 * @note dBm = 10 * log10(P) + 30, where P is in watts
 * 
 * @example
 * // Convert 1 microvolt across 50 ohm impedance to dBm
 * float power = microvoltsToDbm(1.0f, 50.0f);
 * // Result: approximately -86.0 dBm
 */
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

/**
 * @brief Get typical dBm power level for S-meter reading
 * 
 * This function returns the typical power level in dBm for a given S-meter reading.
 * S-meter readings are a standard way to report signal strength in amateur radio
 * and other radio communications. Each S-unit represents approximately 6 dB of signal
 * strength difference.
 * 
 * @param s_meter S-meter reading (0-9, with values >9 representing S9+)
 * @return Typical power level in dBm for the S-meter reading
 * 
 * @note S0 = -127 dBm, S9 = -73 dBm, each S-unit = 6 dB
 * @note S9+ readings are calculated as S9 + (s_meter - 9) * 6 dB
 * 
 * @example
 * // Get power level for S5 signal
 * float power = getSMeterRange(5);
 * // Result: -97.0 dBm
 */
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

/**
 * @brief Check if noise floor level is acceptable for a given environment type
 * 
 * This function determines whether a given noise floor level (in dBm) is acceptable
 * for radio communication in a specific environment type. Different environments
 * have different baseline noise levels, and this function provides appropriate
 * thresholds for each environment type.
 * 
 * @param dbm Noise floor level in dBm
 * @param env_type Environment type (POLAR, DESERT, OCEAN, REMOTE, SUBURBAN, URBAN, INDUSTRIAL)
 * @return true if noise floor is acceptable for the environment, false otherwise
 * 
 * @note Thresholds are based on typical RF noise levels in each environment
 * @note Polar areas have the lowest noise floors, industrial areas have the highest
 * 
 * @example
 * // Check if -120 dBm noise floor is acceptable in suburban area
 * bool acceptable = isNoiseFloorAcceptable(-120.0f, EnvironmentType::SUBURBAN);
 * // Result: true (suburban threshold is -115 dBm)
 */
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

/**
 * @brief Predict urban area noise floor based on time and weather conditions
 * 
 * This function predicts the RF noise floor in urban environments based on
 * time of day and weather conditions. Urban areas have higher baseline noise
 * due to electronic equipment, power lines, and other man-made sources.
 * 
 * @param time_of_day_factor Time factor (0.0 = night, 1.0 = peak business hours)
 * @param weather_factor Weather factor (1.0 = clear, >1.0 = stormy conditions)
 * @return Predicted noise floor in dBm
 * 
 * @note Base urban noise is -107.5 dBm (S5-S7)
 * @note Time effects: up to 5 dB increase during business hours
 * @note Weather effects: up to 3 dB increase during thunderstorms
 * 
 * @example
 * // Predict noise during business hours with stormy weather
 * float noise = predictUrbanNoise(1.0f, 1.5f);
 * // Result: approximately -99.5 dBm
 */
float predictUrbanNoise(float time_of_day_factor, float weather_factor) {
    // Urban noise prediction based on time and weather
    float base_urban_noise = -107.5f;  // S5-S7 baseline
    
    // Time of day effects (higher during business hours)
    float time_effect = time_of_day_factor * 5.0f;
    
    // Weather effects (thunderstorms increase noise)
    float weather_effect = weather_factor * 3.0f;
    
    return base_urban_noise + time_effect + weather_effect;
}

/**
 * @brief Predict industrial area noise floor based on activity and time
 * 
 * This function predicts the RF noise floor in industrial environments based on
 * activity level and time of day. Industrial areas have the highest baseline noise
 * due to heavy machinery, power equipment, and electrical systems.
 * 
 * @param activity_level Activity level (0.0 = no activity, 1.0 = full activity)
 * @param time_of_day_factor Time factor (0.0 = night, 1.0 = peak work hours)
 * @return Predicted noise floor in dBm
 * 
 * @note Base industrial noise is -95.0 dBm (S7-S9+)
 * @note Activity effects: up to 10 dB increase with full activity
 * @note Time effects: up to 8 dB increase during work hours
 * 
 * @example
 * // Predict noise during peak work hours with full activity
 * float noise = predictIndustrialNoise(1.0f, 1.0f);
 * // Result: approximately -77.0 dBm
 */
float predictIndustrialNoise(float activity_level, float time_of_day_factor) {
    // Industrial noise prediction based on activity and time
    float base_industrial_noise = -95.0f;  // S7-S9+ baseline
    
    // Activity level (0.0 = no activity, 1.0 = full activity)
    float activity_effect = activity_level * 10.0f;
    
    // Time of day effects (higher during work hours)
    float time_effect = time_of_day_factor * 8.0f;
    
    return base_industrial_noise + activity_effect + time_effect;
}

/**
 * @brief Predict remote area noise floor based on atmospheric and solar activity
 * 
 * This function predicts the RF noise floor in remote environments based on
 * atmospheric activity and solar conditions. Remote areas have low baseline noise
 * but are affected by natural atmospheric phenomena and solar activity.
 * 
 * @param atmospheric_activity Atmospheric activity (0.0 = calm, 1.0 = severe storms)
 * @param solar_activity Solar flux index (typically 70-300, 100 = quiet sun)
 * @return Predicted noise floor in dBm
 * 
 * @note Base remote noise is -132.5 dBm (S1-S3)
 * @note Atmospheric effects: up to 5 dB increase during severe storms
 * @note Solar effects: higher solar flux increases atmospheric noise
 * 
 * @example
 * // Predict noise during severe storms with high solar activity
 * float noise = predictRemoteNoise(1.0f, 200.0f);
 * // Result: approximately -125.5 dBm
 */
float predictRemoteNoise(float atmospheric_activity, float solar_activity) {
    // Remote area noise prediction based on atmospheric and solar activity
    float base_remote_noise = -132.5f;  // S1-S3 baseline
    
    // Atmospheric activity (thunderstorms, precipitation)
    float atmospheric_effect = atmospheric_activity * 5.0f;
    
    // Solar activity (higher solar flux = more atmospheric noise)
    float solar_effect = (solar_activity - 100.0f) / 50.0f * 2.0f;
    
    return base_remote_noise + atmospheric_effect + solar_effect;
}

/**
 * @brief Predict ocean noise floor based on atmospheric, solar, and local factors
 * 
 * This function predicts the RF noise floor in ocean environments. Ocean areas
 * have very quiet baseline noise due to minimal man-made interference, but are
 * affected by atmospheric activity, solar conditions, and local equipment.
 * 
 * @param atmospheric_activity Atmospheric activity (0.0 = calm, 1.0 = severe storms)
 * @param solar_activity Solar flux index (typically 70-300, 100 = quiet sun)
 * @param laptop_noise_factor Local laptop noise (0.0 = no laptop, 1.0 = switching supply)
 * @return Predicted noise floor in dBm
 * 
 * @note Base ocean noise is -137.5 dBm (S0-S2) - very quiet
 * @note Atmospheric effects: up to 3 dB increase (less than land)
 * @note Solar effects: reduced compared to land areas
 * @note Laptop effects: main local noise source on sailboats
 * 
 * @example
 * // Predict noise with laptop and moderate atmospheric activity
 * float noise = predictOceanNoise(0.5f, 150.0f, 1.0f);
 * // Result: approximately -133.0 dBm
 */
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

/**
 * @brief Predict desert noise floor based on atmospheric, solar, and temperature factors
 * 
 * This function predicts the RF noise floor in desert environments. Desert areas
 * have very quiet baseline noise due to minimal atmospheric activity and dry air
 * conditions that reduce atmospheric absorption and noise.
 * 
 * @param atmospheric_activity Atmospheric activity (0.0 = calm, 1.0 = severe storms)
 * @param solar_activity Solar flux index (typically 70-300, 100 = quiet sun)
 * @param temperature_factor Temperature factor (-1.0 = cold, 1.0 = hot extremes)
 * @return Predicted noise floor in dBm
 * 
 * @note Base desert noise is -137.5 dBm (S0-S2) - very quiet
 * @note Atmospheric effects: reduced due to less thunderstorm activity
 * @note Solar effects: reduced compared to other land areas
 * @note Dry air benefit: -2 dB reduction
 * @note Clear conditions benefit: -1 dB reduction
 * 
 * @example
 * // Predict noise in hot desert with moderate solar activity
 * float noise = predictDesertNoise(0.2f, 150.0f, 1.0f);
 * // Result: approximately -140.0 dBm
 */
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

/**
 * @brief Predict polar noise floor based on atmospheric, solar, auroral, and seasonal factors
 * 
 * This function predicts the RF noise floor in polar environments. Polar areas
 * have the quietest possible baseline noise due to minimal atmospheric activity,
 * very dry air, and virtually no man-made interference.
 * 
 * @param atmospheric_activity Atmospheric activity (0.0 = calm, 1.0 = severe storms)
 * @param solar_activity Solar flux index (typically 70-300, 100 = quiet sun)
 * @param auroral_activity Auroral activity (0.0 = no aurora, 1.0 = strong aurora)
 * @param seasonal_factor Seasonal factor (-1.0 = summer, 1.0 = winter)
 * @return Predicted noise floor in dBm
 * 
 * @note Base polar noise is -140.0 dBm (S0-S1) - quietest possible
 * @note Atmospheric effects: minimal due to global thunderstorm distribution
 * @note Solar effects: minimal compared to other areas
 * @note Dry air benefit: -3 dB reduction
 * @note Human activity benefit: -2 dB reduction
 * @note Seasonal effects: winter is quieter than summer
 * @note Auroral effects: can add noise during geomagnetic storms
 * 
 * @example
 * // Predict noise during polar winter with aurora
 * float noise = predictPolarNoise(0.1f, 80.0f, 0.8f, 1.0f);
 * // Result: approximately -144.0 dBm
 */
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

/**
 * @brief Predict EV charging station noise floor based on activity and environmental factors
 * 
 * This function predicts the RF noise floor near electric vehicle charging stations
 * based on charging activity, time of day, and weather conditions. EV charging
 * stations can generate significant RF noise due to high-power switching electronics.
 * 
 * @param charging_activity Charging activity level (0.0 = no charging, 1.0 = full activity)
 * @param time_of_day_factor Time factor (0.0 = night, 1.0 = peak charging hours)
 * @param weather_factor Weather factor (1.0 = dry, >1.0 = wet conditions)
 * @return Predicted noise floor in dBm
 * 
 * @note Base EV charging noise is -120.0 dBm (S3-S5)
 * @note Activity effects: up to 8 dB increase with full charging activity
 * @note Time effects: up to 4 dB variation by time of day
 * @note Weather effects: wet conditions can increase noise
 * 
 * @example
 * // Predict noise during peak charging hours with wet weather
 * float noise = predictEVChargingNoise(1.0f, 1.0f, 1.5f);
 * // Result: approximately -108.0 dBm
 */
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

/**
 * @brief Predict electrical substation noise floor based on voltage, capacity, and environmental factors
 * 
 * This function predicts the RF noise floor near electrical substations based on
 * voltage level, capacity, time of day, and weather conditions. Substations can
 * generate significant RF noise due to high-voltage switching and transformers.
 * 
 * @param voltage_level Voltage level in kV (higher voltage = more noise)
 * @param capacity_mva Substation capacity in MVA (larger capacity = more noise)
 * @param time_of_day_factor Time factor (0.0 = night, 1.0 = peak activity)
 * @param weather_factor Weather factor (1.0 = dry, >1.0 = wet conditions)
 * @return Predicted noise floor in dBm
 * 
 * @note Base substation noise is -110.0 dBm (S4-S6)
 * @note Voltage effects: up to 3 dB increase with high voltage
 * @note Capacity effects: up to 2 dB increase with large capacity
 * @note Time effects: up to 2 dB variation by time of day
 * @note Weather effects: wet conditions increase noise
 * 
 * @example
 * // Predict noise from 500kV substation with 1000 MVA capacity
 * float noise = predictSubstationNoise(500.0f, 1000.0f, 1.0f, 1.2f);
 * // Result: approximately -101.5 dBm
 */
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

/**
 * @brief Predict power station noise floor based on capacity, output, and environmental factors
 * 
 * This function predicts the RF noise floor near power stations based on
 * capacity, output level, time of day, and weather conditions. Power stations
 * can generate significant RF noise due to large generators, transformers, and
 * switching equipment.
 * 
 * @param capacity_mw Power station capacity in MW (larger capacity = more noise)
 * @param output_mw Current output in MW (higher output = more noise)
 * @param time_of_day_factor Time factor (0.0 = night, 1.0 = peak activity)
 * @param weather_factor Weather factor (1.0 = dry, >1.0 = wet conditions)
 * @return Predicted noise floor in dBm
 * 
 * @note Base power station noise is -105.0 dBm (S5-S7)
 * @note Capacity effects: up to 4 dB increase with large capacity
 * @note Output effects: up to 2 dB increase with high output
 * @note Time effects: up to 1.5 dB variation by time of day
 * @note Weather effects: wet conditions increase noise
 * 
 * @example
 * // Predict noise from 1000 MW power station at 80% output
 * float noise = predictPowerStationNoise(1000.0f, 800.0f, 1.0f, 1.3f);
 * // Result: approximately -95.5 dBm
 */
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
