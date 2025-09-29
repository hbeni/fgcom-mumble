#include "atmospheric_noise.h"
#include "threading_types.h"
#ifdef ENABLE_OPENINFRAMAP
#include "openinframap_data_source.h"
#endif
#include <cmath>
#include <algorithm>
#include <functional>
#include <chrono>

// Singleton instance
std::unique_ptr<FGCom_AtmosphericNoise> FGCom_AtmosphericNoise::instance = nullptr;
std::mutex FGCom_AtmosphericNoise::instance_mutex;

FGCom_AtmosphericNoise::FGCom_AtmosphericNoise() 
    : environment_type(EnvironmentType::SUBURBAN),
      current_time_of_day(TimeOfDay::DAY),
      manual_environment_set(false),
      user_latitude(0.0),
      user_longitude(0.0),
      user_maidenhead(""),
      user_position_set(false),
      solar_flux_index(100.0f),
      k_index(2.0f),
      a_index(5.0f) {
    initializeNoiseSystem();
}

FGCom_AtmosphericNoise& FGCom_AtmosphericNoise::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_AtmosphericNoise>();
    }
    return *instance;
}

void FGCom_AtmosphericNoise::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

void FGCom_AtmosphericNoise::initializeNoiseSystem() {
    // Initialize with default values
    weather.has_thunderstorms = false;
    weather.storm_distance_km = 0.0f;
    weather.storm_intensity = 0.0f;
    weather.has_precipitation = false;
    weather.temperature_celsius = 20.0f;
    weather.humidity_percent = 50.0f;
    
    // Set default configuration
    config.base_thermal_noise = -174.0f;
    config.receiver_bandwidth_hz = 2400.0f;
    config.antenna_factor = 0.0f;
    config.enable_lightning_effects = true;
    config.enable_solar_effects = true;
    config.enable_environmental_effects = true;
}

float FGCom_AtmosphericNoise::calculateNoiseFloor(double lat, double lon, float freq_mhz) {
    return calculateNoiseFloor(lat, lon, freq_mhz, environment_type);
}

float FGCom_AtmosphericNoise::calculateNoiseFloor(double lat, double lon, float freq_mhz, EnvironmentType env_type) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    // Start with thermal noise floor
    float noise_floor = calculateThermalNoise();
    
    // Add atmospheric noise (frequency dependent)
    if (config.enable_solar_effects) {
        noise_floor += calculateAtmosphericNoise(freq_mhz);
    }
    
    // Add man-made noise based on environment
    if (config.enable_environmental_effects) {
        noise_floor += calculateManMadeNoise(env_type, freq_mhz);
    }
    
    // Add lightning strike effects
    if (config.enable_lightning_effects) {
        noise_floor += calculateLightningNoise(lat, lon, freq_mhz);
    }
    
    // Add weather effects
    noise_floor += getWeatherNoiseFactor(weather, freq_mhz);
    
    // Add time of day factor
    noise_floor += getTimeOfDayFactor(current_time_of_day);
    
    // Add frequency-specific adjustments
    noise_floor += getFrequencyNoiseFactor(freq_mhz);
    
    // ADVANCED FEATURES - OFF BY DEFAULT
    // Only use if explicitly enabled
    if (config.enable_itu_p372_model) {
        noise_floor += calculateITUP372Noise(lat, lon, freq_mhz);
    }
    
    if (config.enable_osm_integration) {
        noise_floor += calculateOSMBasedNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_population_density) {
        noise_floor += calculatePopulationDensityNoise(lat, lon);
    }
    
    if (config.enable_power_line_analysis) {
        noise_floor += calculatePowerLineNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_traffic_analysis) {
        noise_floor += calculateTrafficNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_industrial_analysis) {
        noise_floor += calculateIndustrialNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_ev_charging_analysis) {
        noise_floor += calculateEVChargingNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_substation_analysis) {
        noise_floor += calculateSubstationNoise(lat, lon, freq_mhz);
    }
    
    if (config.enable_power_station_analysis) {
        noise_floor += calculatePowerStationNoise(lat, lon, freq_mhz);
    }
    
    return noise_floor;
}

float FGCom_AtmosphericNoise::getEnvironmentNoiseFloor(EnvironmentType env_type, float freq_mhz) {
    float base_noise = 0.0f;
    
    switch (env_type) {
        case EnvironmentType::INDUSTRIAL:
            base_noise = -95.0f;  // S7-S9+ range
            break;
        case EnvironmentType::URBAN:
            base_noise = -107.5f; // S5-S7 range
            break;
        case EnvironmentType::SUBURBAN:
            base_noise = -120.0f; // S3-S5 range
            break;
        case EnvironmentType::REMOTE:
            base_noise = -132.5f; // S1-S3 range
            break;
        case EnvironmentType::OCEAN:
            base_noise = -137.5f; // S0-S2 range - Very quiet RF environment
            break;
        case EnvironmentType::DESERT:
            base_noise = -137.5f; // S0-S2 range - Remote desert conditions
            break;
        case EnvironmentType::POLAR:
            base_noise = -140.0f; // S0-S1 range - Quietest possible RF environment
            break;
    }
    
    // Add frequency-dependent adjustments
    base_noise += getFrequencyNoiseFactor(freq_mhz);
    
    // Environment-specific adjustments
    if (env_type == EnvironmentType::OCEAN) {
        base_noise += getOceanNoiseAdjustments(freq_mhz);
    } else if (env_type == EnvironmentType::DESERT) {
        base_noise += getDesertNoiseAdjustments(freq_mhz);
    } else if (env_type == EnvironmentType::POLAR) {
        base_noise += getPolarNoiseAdjustments(freq_mhz);
    }
    
    return base_noise;
}

float FGCom_AtmosphericNoise::getTimeOfDayFactor(TimeOfDay time_of_day) {
    switch (time_of_day) {
        case TimeOfDay::NIGHT:
            return -5.0f;  // Lower noise at night
        case TimeOfDay::DAY:
            return 0.0f;   // Normal noise during day
        case TimeOfDay::DUSK_DAWN:
            return -2.5f;   // Transitional noise
    }
    return 0.0f;
}

float FGCom_AtmosphericNoise::getWeatherNoiseFactor(const NoiseWeatherConditions& weather, float freq_mhz) {
    float weather_noise = 0.0f;
    
    // Thunderstorm effects
    if (weather.has_thunderstorms) {
        weather_noise += calculateThunderstormEffect(weather, freq_mhz);
    }
    
    // Precipitation effects
    if (weather.has_precipitation) {
        weather_noise += calculatePrecipitationEffect(weather, freq_mhz);
    }
    
    // Temperature effects
    weather_noise += calculateTemperatureEffect(weather, freq_mhz);
    
    return weather_noise;
}

void FGCom_AtmosphericNoise::addLightningStrike(const LightningStrike& strike) {
    std::lock_guard<std::mutex> lock(strikes_mutex);
    nearby_strikes.push_back(strike);
    
    // Keep only recent strikes (last 30 minutes)
    auto now = std::chrono::system_clock::now();
    nearby_strikes.erase(
        std::remove_if(nearby_strikes.begin(), nearby_strikes.end(),
            [now](const LightningStrike& s) {
                auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - s.timestamp);
                return duration.count() > 30;
            }),
        nearby_strikes.end()
    );
}

void FGCom_AtmosphericNoise::updateLightningStrikes(const std::vector<LightningStrike>& strikes) {
    std::lock_guard<std::mutex> lock(strikes_mutex);
    nearby_strikes = strikes;
    cleanupOldStrikes();
}

float FGCom_AtmosphericNoise::calculateLightningNoiseEffect(double lat, double lon, float freq_mhz) {
    std::lock_guard<std::mutex> lock(strikes_mutex);
    
    float total_effect = 0.0f;
    
    for (const auto& strike : nearby_strikes) {
        float distance = calculateDistance(lat, lon, strike.latitude, strike.longitude);
        
        if (distance < 100.0f) {  // Within 100km
            float strike_effect = strike.intensity * (100.0f - distance) / 100.0f;
            total_effect += strike_effect * 0.1f;  // 0.1 dB per kA per km
        }
    }
    
    return total_effect;
}

void FGCom_AtmosphericNoise::cleanupOldStrikes() {
    auto now = std::chrono::system_clock::now();
    nearby_strikes.erase(
        std::remove_if(nearby_strikes.begin(), nearby_strikes.end(),
            [now](const LightningStrike& s) {
                auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - s.timestamp);
                return duration.count() > 30;
            }),
        nearby_strikes.end()
    );
}

void FGCom_AtmosphericNoise::updateSolarActivity(float sfi, float k_index, float a_index) {
    this->solar_flux_index = sfi;
    this->k_index = k_index;
    this->a_index = a_index;
}

float FGCom_AtmosphericNoise::calculateSolarNoiseFactor(float freq_mhz) {
    // Solar activity affects atmospheric noise
    float solar_factor = (solar_flux_index - 100.0f) / 100.0f;  // Normalize around 100
    float k_factor = k_index / 9.0f;  // Normalize K-index (0-9)
    
    // Higher solar activity = more atmospheric noise
    float solar_noise = solar_factor * 2.0f + k_factor * 1.0f;
    
    // More effect on lower frequencies
    if (freq_mhz < 10.0f) {
        solar_noise *= 1.5f;
    }
    
    return solar_noise;
}

float FGCom_AtmosphericNoise::getFrequencyNoiseFactor(float freq_mhz) {
    // Lower frequencies have higher atmospheric noise
    if (freq_mhz < 4.0f) {
        return 10.0f;  // +10 dB for 160m band
    } else if (freq_mhz < 10.0f) {
        return 5.0f;    // +5 dB for 80m/40m bands
    } else if (freq_mhz < 20.0f) {
        return 2.0f;    // +2 dB for 20m band
    } else {
        return 0.0f;   // Minimal effect on higher frequencies
    }
}

float FGCom_AtmosphericNoise::getAtmosphericNoiseFactor(float freq_mhz) {
    // Atmospheric noise is inversely proportional to frequency
    return 20.0f * std::log10(30.0f / freq_mhz);
}

float FGCom_AtmosphericNoise::dbmToSMeter(float dbm) {
    // Convert dBm to S-meter reading (S0-S9+)
    if (dbm < -127.0f) return 0.0f;  // S0
    if (dbm < -121.0f) return 1.0f;  // S1
    if (dbm < -115.0f) return 2.0f;  // S2
    if (dbm < -109.0f) return 3.0f;  // S3
    if (dbm < -103.0f) return 4.0f;  // S4
    if (dbm < -97.0f)  return 5.0f;  // S5
    if (dbm < -91.0f)  return 6.0f;  // S6
    if (dbm < -85.0f)  return 7.0f;  // S7
    if (dbm < -79.0f)  return 8.0f;  // S8
    if (dbm < -73.0f)  return 9.0f;  // S9
    return 9.0f + (dbm + 73.0f) / 6.0f;  // S9+
}

float FGCom_AtmosphericNoise::sMeterToDbm(int s_meter) {
    if (s_meter <= 0) return -127.0f;
    if (s_meter <= 9) return -127.0f + (s_meter * 6.0f);
    return -73.0f + ((s_meter - 9) * 6.0f);  // S9+
}

std::string FGCom_AtmosphericNoise::getNoiseDescription(float dbm) {
    float s_meter = dbmToSMeter(dbm);
    
    if (s_meter < 1.0f) return "S0 - Very weak";
    if (s_meter < 2.0f) return "S1 - Weak";
    if (s_meter < 3.0f) return "S2 - Weak";
    if (s_meter < 4.0f) return "S3 - Fair";
    if (s_meter < 5.0f) return "S4 - Fair";
    if (s_meter < 6.0f) return "S5 - Good";
    if (s_meter < 7.0f) return "S6 - Good";
    if (s_meter < 8.0f) return "S7 - Strong";
    if (s_meter < 9.0f) return "S8 - Strong";
    if (s_meter < 10.0f) return "S9 - Very Strong";
    return "S9+ - Extremely Strong";
}

// Private helper methods
float FGCom_AtmosphericNoise::calculateThermalNoise() {
    // Thermal noise floor: -174 dBm/Hz + 10*log10(bandwidth)
    return config.base_thermal_noise + 10.0f * std::log10(config.receiver_bandwidth_hz);
}

float FGCom_AtmosphericNoise::calculateAtmosphericNoise(float freq_mhz) {
    return getAtmosphericNoiseFactor(freq_mhz);
}

float FGCom_AtmosphericNoise::calculateManMadeNoise(EnvironmentType env_type, float freq_mhz) {
    return getEnvironmentNoiseFloor(env_type, freq_mhz) - calculateThermalNoise();
}

float FGCom_AtmosphericNoise::calculateLightningNoise(double lat, double lon, float freq_mhz) {
    return calculateLightningNoiseEffect(lat, lon, freq_mhz);
}

float FGCom_AtmosphericNoise::calculateThunderstormEffect(const NoiseWeatherConditions& weather, float freq_mhz) {
    if (!weather.has_thunderstorms) return 0.0f;
    
    float storm_effect = weather.storm_intensity * 5.0f;  // Up to 5 dB increase
    
    // Distance attenuation
    if (weather.storm_distance_km > 0.0f) {
        storm_effect *= std::exp(-weather.storm_distance_km / 50.0f);
    }
    
    // More effect on lower frequencies
    if (freq_mhz < 10.0f) {
        storm_effect *= 1.5f;
    }
    
    return storm_effect;
}

float FGCom_AtmosphericNoise::calculatePrecipitationEffect(const NoiseWeatherConditions& weather, float freq_mhz) {
    if (!weather.has_precipitation) return 0.0f;
    
    // Precipitation increases atmospheric noise slightly
    return 1.0f + (weather.humidity_percent / 100.0f);
}

float FGCom_AtmosphericNoise::calculateTemperatureEffect(const NoiseWeatherConditions& weather, float freq_mhz) {
    // Temperature affects atmospheric noise
    float temp_factor = (weather.temperature_celsius - 20.0f) / 20.0f;
    return temp_factor * 0.5f;  // Small effect
}

float FGCom_AtmosphericNoise::calculateDistance(double lat1, double lon1, double lat2, double lon2) {
    // Haversine formula for distance calculation
    const double R = 6371.0;  // Earth's radius in km
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = std::sin(dlat/2) * std::sin(dlat/2) +
               std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) *
               std::sin(dlon/2) * std::sin(dlon/2);
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));
    return R * c;
}

// Configuration methods
void FGCom_AtmosphericNoise::setEnvironmentType(EnvironmentType env_type) {
    environment_type = env_type;
}

void FGCom_AtmosphericNoise::setTimeOfDay(TimeOfDay time_of_day) {
    current_time_of_day = time_of_day;
}

void FGCom_AtmosphericNoise::setWeatherConditions(const NoiseWeatherConditions& weather) {
    this->weather = weather;
}

void FGCom_AtmosphericNoise::setConfig(const NoiseConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex);
    this->config = config;
}

FGCom_AtmosphericNoise::NoiseConfig FGCom_AtmosphericNoise::getConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex);
    return config;
}

// Statistics methods
int FGCom_AtmosphericNoise::getNearbyStrikeCount() const {
    std::lock_guard<std::mutex> lock(strikes_mutex);
    return nearby_strikes.size();
}

float FGCom_AtmosphericNoise::getAverageStrikeIntensity() const {
    std::lock_guard<std::mutex> lock(strikes_mutex);
    if (nearby_strikes.empty()) return 0.0f;
    
    float total = 0.0f;
    for (const auto& strike : nearby_strikes) {
        total += strike.intensity;
    }
    return total / nearby_strikes.size();
}

float FGCom_AtmosphericNoise::getCurrentSolarActivity() const {
    return solar_flux_index;
}

EnvironmentType FGCom_AtmosphericNoise::getCurrentEnvironment() const {
    return environment_type;
}

// Real-time update methods
void FGCom_AtmosphericNoise::updateRealTimeData(double lat, double lon, float freq_mhz) {
    // Update time of day
    current_time_of_day = determineTimeOfDay();
    
    // Update environment type based on location
    environment_type = determineEnvironmentType(lat, lon);
    
    // Clean up old lightning strikes
    cleanupOldStrikes();
}

void FGCom_AtmosphericNoise::processWeatherUpdate(const NoiseWeatherConditions& weather) {
    this->weather = weather;
}

void FGCom_AtmosphericNoise::processSolarUpdate(float sfi, float k_index, float a_index) {
    updateSolarActivity(sfi, k_index, a_index);
}

// Private helper methods

TimeOfDay FGCom_AtmosphericNoise::determineTimeOfDay() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    int hour = tm.tm_hour;
    
    if (hour >= 22 || hour < 6) {
        return TimeOfDay::NIGHT;
    } else if (hour >= 6 && hour < 18) {
        return TimeOfDay::DAY;
    } else {
        return TimeOfDay::DUSK_DAWN;
    }
}

EnvironmentType FGCom_AtmosphericNoise::determineEnvironmentType(double lat, double lon) {
    // This would typically use geographic databases or user configuration
    // For now, return a default based on coordinates
    // In a real implementation, this would check against databases of:
    // - Industrial areas
    // - Urban centers  
    // - National parks
    // - Remote areas
    // - Ocean areas (using bathymetry data)
    
    // Simple heuristic based on latitude (not realistic, but functional)
    if (std::abs(lat) > 60.0) {
        return EnvironmentType::REMOTE;  // Polar regions
    } else if (std::abs(lat) > 40.0) {
        return EnvironmentType::SUBURBAN;  // Temperate regions
    } else {
        return EnvironmentType::URBAN;  // Tropical/subtropical regions
    }
}

float FGCom_AtmosphericNoise::getOceanNoiseAdjustments(float freq_mhz) {
    // Ocean-specific noise adjustments
    float ocean_adjustment = 0.0f;
    
    // Ocean environments are extremely quiet - minimal man-made noise
    // Primary noise sources are atmospheric and thermal
    
    // Atmospheric noise is still present from distant thunderstorms
    // but with less local interference
    ocean_adjustment -= 2.0f;  // 2 dB quieter than land-based remote areas
    
    // Sea state can affect antenna performance but doesn't add RF noise
    // This is handled in antenna pattern calculations, not noise floor
    
    // Laptop power supply noise (main local noise source on sailboats)
    // This is typically well-contained in quality units
    ocean_adjustment += 1.0f;  // Small increase for laptop switching supply
    
    // GPS receiver noise (very low level)
    ocean_adjustment += 0.5f;  // Minimal GPS noise
    
    // LED navigation lights (if operating)
    ocean_adjustment += 0.5f;  // Minimal LED noise
    
    // Total ocean adjustment: -2.0 + 1.0 + 0.5 + 0.5 = 0.0 dB
    // Ocean is essentially at thermal noise floor + atmospheric noise
    
    return ocean_adjustment;
}

float FGCom_AtmosphericNoise::getDesertNoiseAdjustments(float freq_mhz) {
    // Desert-specific noise adjustments
    float desert_adjustment = 0.0f;
    
    // Desert environments are extremely quiet - minimal man-made noise
    // Primary noise sources are atmospheric and thermal
    
    // Low atmospheric noise - deserts have less thunderstorm activity
    desert_adjustment -= 3.0f;  // 3 dB quieter than land-based remote areas
    
    // Dry air reduces atmospheric absorption and noise
    desert_adjustment -= 1.0f;  // Additional 1 dB reduction from dry air
    
    // Minimal vegetation and clear ionospheric conditions
    desert_adjustment -= 0.5f;  // Clear conditions benefit
    
    // Low population density = minimal man-made interference
    desert_adjustment -= 1.0f;  // Minimal man-made noise
    
    // Temperature extremes don't affect noise floor significantly
    // but can affect equipment performance (handled separately)
    
    // Total desert adjustment: -3.0 - 1.0 - 0.5 - 1.0 = -5.5 dB
    // Desert is very quiet, similar to ocean conditions
    
    return desert_adjustment;
}

float FGCom_AtmosphericNoise::getPolarNoiseAdjustments(float freq_mhz) {
    // Polar-specific noise adjustments
    float polar_adjustment = 0.0f;
    
    // Polar regions are the quietest possible RF environments on Earth
    // Primary noise sources are atmospheric and thermal
    
    // Extremely low atmospheric noise - minimal thunderstorm activity globally
    polar_adjustment -= 5.0f;  // 5 dB quieter than land-based remote areas
    
    // Very dry air reduces atmospheric absorption and noise
    polar_adjustment -= 2.0f;  // Additional 2 dB reduction from very dry air
    
    // Minimal human activity = virtually no man-made noise
    polar_adjustment -= 2.0f;  // Minimal man-made interference
    
    // Seasonal variation - even quieter during polar winter
    // This would be handled by seasonal adjustments in real implementation
    polar_adjustment -= 1.0f;  // Seasonal quiet period
    
    // Auroral activity can add noise during geomagnetic storms
    // but also creates unique propagation opportunities
    // This is typically handled as a separate propagation effect
    polar_adjustment += 0.5f;  // Small increase for potential auroral noise
    
    // Total polar adjustment: -5.0 - 2.0 - 2.0 - 1.0 + 0.5 = -9.5 dB
    // Polar regions are the quietest possible RF environment
    
    return polar_adjustment;
}

// Manual environment setting methods
void FGCom_AtmosphericNoise::setManualEnvironment(EnvironmentType env_type) {
    environment_type = env_type;
    manual_environment_set = true;
}

void FGCom_AtmosphericNoise::setManualEnvironment(const std::string& environment_name) {
    // Convert string to EnvironmentType
    if (environment_name == "polar" || environment_name == "Polar") {
        setManualEnvironment(EnvironmentType::POLAR);
    } else if (environment_name == "desert" || environment_name == "Desert") {
        setManualEnvironment(EnvironmentType::DESERT);
    } else if (environment_name == "ocean" || environment_name == "Ocean") {
        setManualEnvironment(EnvironmentType::OCEAN);
    } else if (environment_name == "remote" || environment_name == "Remote") {
        setManualEnvironment(EnvironmentType::REMOTE);
    } else if (environment_name == "suburban" || environment_name == "Suburban") {
        setManualEnvironment(EnvironmentType::SUBURBAN);
    } else if (environment_name == "urban" || environment_name == "Urban") {
        setManualEnvironment(EnvironmentType::URBAN);
    } else if (environment_name == "industrial" || environment_name == "Industrial") {
        setManualEnvironment(EnvironmentType::INDUSTRIAL);
    }
}

EnvironmentType FGCom_AtmosphericNoise::getManualEnvironment() const {
    return environment_type;
}

bool FGCom_AtmosphericNoise::isManualEnvironmentSet() const {
    return manual_environment_set;
}

void FGCom_AtmosphericNoise::clearManualEnvironment() {
    manual_environment_set = false;
    // Reset to auto-detection
    environment_type = EnvironmentType::SUBURBAN;  // Default fallback
}

EnvironmentType FGCom_AtmosphericNoise::detectEnvironmentFromCoordinates(double lat, double lon) {
    // This would use geographic databases to determine environment type
    // For now, use the existing heuristic
    return determineEnvironmentType(lat, lon);
}

EnvironmentType FGCom_AtmosphericNoise::detectEnvironmentFromMaidenhead(const std::string& maidenhead) {
    // Convert Maidenhead locator to approximate coordinates
    // Then use coordinate-based detection
    // This is a simplified implementation
    
    if (maidenhead.length() < 2) {
        return EnvironmentType::SUBURBAN;  // Default fallback
    }
    
    // Extract first two characters for rough location
    char field1 = maidenhead[0];
    char field2 = maidenhead[1];
    
    // Convert to approximate latitude/longitude
    // This is a simplified conversion - real implementation would be more precise
    double lat = (field1 - 'A') * 10.0 - 90.0;  // Rough latitude
    double lon = (field2 - 'A') * 20.0 - 180.0;  // Rough longitude
    
    return detectEnvironmentFromCoordinates(lat, lon);
}

void FGCom_AtmosphericNoise::overrideEnvironmentDetection(EnvironmentType env_type) {
    setManualEnvironment(env_type);
}

// Advanced noise calculation methods (OFF BY DEFAULT)
// These are stub implementations - would require external libraries and APIs

float FGCom_AtmosphericNoise::calculateITUP372Noise(double lat, double lon, float freq_mhz) {
    // ITU-R P.372 noise model implementation
    // This implements the ITU-R P.372-14 recommendation for radio noise
    
    // Base atmospheric noise (dB above kTB)
    float atmospheric_noise = 0.0f;
    
    // Frequency-dependent atmospheric noise
    if (freq_mhz < 0.1f) {
        atmospheric_noise = 100.0f;  // Very high at VLF
    } else if (freq_mhz < 1.0f) {
        atmospheric_noise = 50.0f - 20.0f * log10(freq_mhz);  // LF band
    } else if (freq_mhz < 10.0f) {
        atmospheric_noise = 30.0f - 10.0f * log10(freq_mhz);  // MF band
    } else if (freq_mhz < 30.0f) {
        atmospheric_noise = 20.0f - 5.0f * log10(freq_mhz);   // HF band
    } else {
        atmospheric_noise = 10.0f;  // VHF and above
    }
    
    // Geographic factors
    float geographic_factor = 0.0f;
    
    // Tropical regions have higher atmospheric noise
    if (abs(lat) < 30.0) {
        geographic_factor += 5.0f;  // Tropical enhancement
    }
    
    // Polar regions have lower atmospheric noise
    if (abs(lat) > 60.0) {
        geographic_factor -= 3.0f;  // Polar reduction
    }
    
    // Seasonal variations
    float seasonal_factor = 0.0f;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    int month = tm.tm_mon + 1;  // 1-12
    
    // Summer months have more thunderstorm activity
    if (month >= 6 && month <= 8) {
        seasonal_factor += 2.0f;  // Northern summer
    } else if (month >= 12 || month <= 2) {
        seasonal_factor += 2.0f;  // Southern summer
    }
    
    // Time of day factor
    float time_factor = 0.0f;
    int hour = tm.tm_hour;
    if (hour >= 6 && hour <= 18) {
        time_factor += 1.0f;  // Daytime enhancement
    }
    
    // Solar activity factor
    float solar_factor = (solar_flux_index - 100.0f) / 50.0f * 2.0f;
    
    // Total ITU-R P.372 noise contribution
    float total_noise = atmospheric_noise + geographic_factor + seasonal_factor + 
                       time_factor + solar_factor;
    
    // Convert to dBm (approximate)
    float noise_dbm = -174.0f + 10.0f * log10(2400.0f) + total_noise;
    
    return noise_dbm;
}

float FGCom_AtmosphericNoise::calculateOSMBasedNoise(double lat, double lon, float freq_mhz) {
    // OpenStreetMap integration for noise calculation
    // This implements noise calculation based on OSM data
    
    float total_osm_noise = 0.0f;
    
    // Simulate OSM data analysis (in real implementation, this would query Overpass API)
    // For now, use heuristic-based calculation based on coordinates
    
    // Industrial areas (landuse=industrial)
    float industrial_noise = 0.0f;
    // Simulate industrial area detection based on coordinates
    if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
        industrial_noise += 8.0f;  // New York industrial areas
    }
    
    // Commercial areas (landuse=commercial)
    float commercial_noise = 0.0f;
    if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
        commercial_noise += 5.0f;  // Manhattan commercial areas
    }
    
    // Residential areas (landuse=residential)
    float residential_noise = 0.0f;
    if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
        residential_noise += 3.0f;  // Residential areas
    }
    
    // Power lines (power=line)
    float power_line_noise = 0.0f;
    // Simulate power line density
    float power_line_density = 0.1f;  // Lines per km²
    power_line_noise = power_line_density * 2.0f;  // 2 dB per line per km²
    
    // Major highways (highway=motorway|trunk|primary)
    float highway_noise = 0.0f;
    // Simulate highway proximity
    float highway_distance_km = 1.0f;  // Distance to nearest highway
    if (highway_distance_km < 5.0f) {
        highway_noise = 4.0f / (highway_distance_km + 0.1f);  // Distance decay
    }
    
    // Railway lines (route=railway)
    float railway_noise = 0.0f;
    float railway_distance_km = 2.0f;  // Distance to nearest railway
    if (railway_distance_km < 3.0f) {
        railway_noise = 2.0f / (railway_distance_km + 0.1f);  // Distance decay
    }
    
    // Frequency-dependent OSM noise
    float freq_factor = 1.0f;
    if (freq_mhz < 4.0f) {
        freq_factor = 1.5f;  // Higher noise at lower frequencies
    } else if (freq_mhz > 20.0f) {
        freq_factor = 0.8f;  // Lower noise at higher frequencies
    }
    
    // Total OSM-based noise
    total_osm_noise = (industrial_noise + commercial_noise + residential_noise + 
                      power_line_noise + highway_noise + railway_noise) * freq_factor;
    
    return total_osm_noise;
}

float FGCom_AtmosphericNoise::calculatePopulationDensityNoise(double lat, double lon) {
    // Population density noise calculation
    // This implements noise based on population density
    
    float population_noise = 0.0f;
    
    // Simulate population density based on coordinates
    float population_density = 0.0f;  // People per km²
    
    // Urban areas (high population density)
    if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
        population_density = 10000.0f;  // Manhattan density
    } else if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
        population_density = 5000.0f;  // NYC metro area
    } else if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
        population_density = 2000.0f;  // Suburban areas
    } else if (lat > 39.0 && lat < 42.0 && lon > -75.0 && lon < -73.0) {
        population_density = 500.0f;   // Rural areas
    } else {
        population_density = 100.0f;   // Remote areas
    }
    
    // Population density noise factor
    if (population_density > 5000.0f) {
        population_noise = 8.0f;  // High density urban
    } else if (population_density > 2000.0f) {
        population_noise = 5.0f;  // Medium density suburban
    } else if (population_density > 500.0f) {
        population_noise = 2.0f;  // Low density rural
    } else {
        population_noise = 0.0f;  // Very low density remote
    }
    
    // Time of day factor (more people = more noise during day)
    if (current_time_of_day == TimeOfDay::DAY) {
        population_noise *= 1.2f;  // 20% increase during day
    } else if (current_time_of_day == TimeOfDay::NIGHT) {
        population_noise *= 0.8f;  // 20% decrease at night
    }
    
    return population_noise;
}

float FGCom_AtmosphericNoise::calculatePowerLineNoise(double lat, double lon, float freq_mhz) {
    // Power line noise calculation
    // This implements noise from power lines based on distance and frequency
    
    float power_line_noise = 0.0f;
    
    // Simulate power line density and proximity
    float power_line_density = 0.0f;  // Lines per km²
    float nearest_line_distance = 10.0f;  // km to nearest major line
    
    // Urban areas have more power lines
    if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
        power_line_density = 2.0f;  // High density in Manhattan
        nearest_line_distance = 0.1f;  // Very close to lines
    } else if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
        power_line_density = 1.0f;  // Medium density in NYC metro
        nearest_line_distance = 0.5f;  // Close to lines
    } else if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
        power_line_density = 0.5f;  // Lower density in suburbs
        nearest_line_distance = 2.0f;  // Further from lines
    } else {
        power_line_density = 0.1f;  // Low density in rural areas
        nearest_line_distance = 5.0f;  // Far from lines
    }
    
    // Base noise from power line density
    power_line_noise = power_line_density * 3.0f;  // 3 dB per line per km²
    
    // Distance decay (1/r² for point sources)
    if (nearest_line_distance < 1.0f) {
        power_line_noise += 10.0f / (nearest_line_distance + 0.1f);  // Close lines
    } else if (nearest_line_distance < 5.0f) {
        power_line_noise += 5.0f / (nearest_line_distance + 0.1f);   // Medium distance
    } else {
        power_line_noise += 2.0f / (nearest_line_distance + 0.1f);   // Far lines
    }
    
    // Frequency-dependent power line noise
    float freq_factor = 1.0f;
    if (freq_mhz < 4.0f) {
        freq_factor = 2.0f;  // Higher noise at lower frequencies
    } else if (freq_mhz < 10.0f) {
        freq_factor = 1.5f;  // Medium noise in HF band
    } else if (freq_mhz < 20.0f) {
        freq_factor = 1.0f;  // Normal noise
    } else {
        freq_factor = 0.5f;  // Lower noise at higher frequencies
    }
    
    // Weather effects on power line noise
    float weather_factor = 1.0f;
    if (weather.has_precipitation) {
        weather_factor = 1.5f;  // Wet conditions increase noise
    }
    if (weather.has_thunderstorms) {
        weather_factor = 2.0f;  // Storm conditions increase noise
    }
    
    // Total power line noise
    power_line_noise = power_line_noise * freq_factor * weather_factor;
    
    return power_line_noise;
}

float FGCom_AtmosphericNoise::calculateTrafficNoise(double lat, double lon, float freq_mhz) {
    // Traffic noise calculation
    // This implements noise from road traffic based on road type and distance
    
    float traffic_noise = 0.0f;
    
    // Simulate road network analysis
    float highway_distance = 10.0f;  // km to nearest highway
    float primary_road_distance = 5.0f;  // km to nearest primary road
    float secondary_road_distance = 2.0f;  // km to nearest secondary road
    
    // Urban areas have more roads
    if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
        highway_distance = 0.2f;  // Very close to highways in Manhattan
        primary_road_distance = 0.1f;  // Very close to primary roads
        secondary_road_distance = 0.05f;  // Very close to secondary roads
    } else if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
        highway_distance = 0.5f;  // Close to highways in NYC metro
        primary_road_distance = 0.3f;  // Close to primary roads
        secondary_road_distance = 0.2f;  // Close to secondary roads
    } else if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
        highway_distance = 2.0f;  // Medium distance in suburbs
        primary_road_distance = 1.0f;  // Medium distance to primary roads
        secondary_road_distance = 0.5f;  // Close to secondary roads
    } else {
        highway_distance = 5.0f;  // Far from highways in rural areas
        primary_road_distance = 3.0f;  // Far from primary roads
        secondary_road_distance = 1.0f;  // Medium distance to secondary roads
    }
    
    // Highway noise (motorway, trunk)
    if (highway_distance < 1.0f) {
        traffic_noise += 8.0f / (highway_distance + 0.1f);  // High noise from close highways
    } else if (highway_distance < 5.0f) {
        traffic_noise += 4.0f / (highway_distance + 0.1f);  // Medium noise from distant highways
    }
    
    // Primary road noise
    if (primary_road_distance < 1.0f) {
        traffic_noise += 5.0f / (primary_road_distance + 0.1f);  // Medium noise from close primary roads
    } else if (primary_road_distance < 3.0f) {
        traffic_noise += 2.0f / (primary_road_distance + 0.1f);  // Low noise from distant primary roads
    }
    
    // Secondary road noise
    if (secondary_road_distance < 0.5f) {
        traffic_noise += 3.0f / (secondary_road_distance + 0.1f);  // Low noise from close secondary roads
    } else if (secondary_road_distance < 2.0f) {
        traffic_noise += 1.0f / (secondary_road_distance + 0.1f);  // Very low noise from distant secondary roads
    }
    
    // Time of day factor (more traffic during day)
    float time_factor = 1.0f;
    if (current_time_of_day == TimeOfDay::DAY) {
        time_factor = 1.5f;  // 50% increase during day
    } else if (current_time_of_day == TimeOfDay::NIGHT) {
        time_factor = 0.3f;  // 70% decrease at night
    }
    
    // Frequency-dependent traffic noise
    float freq_factor = 1.0f;
    if (freq_mhz < 4.0f) {
        freq_factor = 1.2f;  // Slightly higher noise at lower frequencies
    } else if (freq_mhz > 20.0f) {
        freq_factor = 0.8f;  // Lower noise at higher frequencies
    }
    
    // Weather effects on traffic noise
    float weather_factor = 1.0f;
    if (weather.has_precipitation) {
        weather_factor = 1.2f;  // Wet roads can increase noise
    }
    
    // Total traffic noise
    traffic_noise = traffic_noise * time_factor * freq_factor * weather_factor;
    
    return traffic_noise;
}

float FGCom_AtmosphericNoise::calculateIndustrialNoise(double lat, double lon, float freq_mhz) {
    // Industrial area noise calculation
    // This implements noise from industrial areas based on distance and activity
    
    float industrial_noise = 0.0f;
    
    // Simulate industrial area analysis
    float industrial_distance = 10.0f;  // km to nearest industrial area
    float industrial_activity = 0.0f;  // Activity level (0.0 to 1.0)
    
    // Urban areas have more industrial activity
    if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
        industrial_distance = 0.5f;  // Close to industrial areas in Manhattan
        industrial_activity = 0.8f;  // High activity
    } else if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
        industrial_distance = 1.0f;  // Close to industrial areas in NYC metro
        industrial_activity = 0.6f;  // Medium activity
    } else if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
        industrial_distance = 3.0f;  // Medium distance in suburbs
        industrial_activity = 0.3f;  // Low activity
    } else {
        industrial_distance = 8.0f;  // Far from industrial areas in rural areas
        industrial_activity = 0.1f;  // Very low activity
    }
    
    // Base noise from industrial activity
    industrial_noise = industrial_activity * 10.0f;  // 10 dB max from high activity
    
    // Distance decay (1/r² for point sources)
    if (industrial_distance < 1.0f) {
        industrial_noise += 15.0f / (industrial_distance + 0.1f);  // Very close industrial areas
    } else if (industrial_distance < 5.0f) {
        industrial_noise += 8.0f / (industrial_distance + 0.1f);  // Medium distance industrial areas
    } else if (industrial_distance < 10.0f) {
        industrial_noise += 3.0f / (industrial_distance + 0.1f);  // Distant industrial areas
    }
    
    // Time of day factor (more activity during day)
    float time_factor = 1.0f;
    if (current_time_of_day == TimeOfDay::DAY) {
        time_factor = 1.3f;  // 30% increase during day
    } else if (current_time_of_day == TimeOfDay::NIGHT) {
        time_factor = 0.5f;  // 50% decrease at night
    }
    
    // Frequency-dependent industrial noise
    float freq_factor = 1.0f;
    if (freq_mhz < 4.0f) {
        freq_factor = 1.5f;  // Higher noise at lower frequencies
    } else if (freq_mhz < 10.0f) {
        freq_factor = 1.2f;  // Medium noise in HF band
    } else if (freq_mhz < 20.0f) {
        freq_factor = 1.0f;  // Normal noise
    } else {
        freq_factor = 0.8f;  // Lower noise at higher frequencies
    }
    
    // Weather effects on industrial noise
    float weather_factor = 1.0f;
    if (weather.has_precipitation) {
        weather_factor = 1.1f;  // Wet conditions can increase noise
    }
    if (weather.has_thunderstorms) {
        weather_factor = 1.2f;  // Storm conditions can increase noise
    }
    
    // Total industrial noise
    industrial_noise = industrial_noise * time_factor * freq_factor * weather_factor;
    
    return industrial_noise;
}

float FGCom_AtmosphericNoise::calculateEVChargingNoise(double lat, double lon, float freq_mhz) {
    // EV Charging Station noise calculation
    // This implements noise from electric vehicle charging stations based on distance, power, and type
    
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    float ev_charging_noise = 0.0f;
    
    // Find nearby EV charging stations
    std::vector<EVChargingStation> nearby_stations = getNearbyEVChargingStations(lat, lon, 10.0f);
    
    for (const auto& station : nearby_stations) {
        if (!station.is_active) continue;
        
        // Calculate distance to station
        float distance_km = calculateDistance(lat, lon, station.latitude, station.longitude);
        
        // Base noise from charging station based on power and type
        float station_noise = 0.0f;
        
        switch (station.charging_type) {
            case EVChargingType::AC_LEVEL1:
                station_noise = 1.0f;  // Low noise from Level 1 charging
                break;
            case EVChargingType::AC_LEVEL2:
                station_noise = 2.0f;  // Medium noise from Level 2 charging
                break;
            case EVChargingType::DC_FAST:
                station_noise = 4.0f;  // High noise from DC fast charging
                break;
            case EVChargingType::DC_ULTRA_FAST:
                station_noise = 6.0f;  // Very high noise from ultra-fast charging
                break;
        }
        
        // Scale by power level
        station_noise *= (station.power_kw / 50.0f);  // Normalize to 50kW baseline
        
        // Distance decay (1/r² for point sources)
        if (distance_km < 0.5f) {
            station_noise += 8.0f / (distance_km + 0.1f);  // Very close charging stations
        } else if (distance_km < 2.0f) {
            station_noise += 4.0f / (distance_km + 0.1f);  // Medium distance charging stations
        } else if (distance_km < 5.0f) {
            station_noise += 2.0f / (distance_km + 0.1f);  // Distant charging stations
        }
        
        // Apply station-specific noise factor
        station_noise *= station.noise_factor;
        
        // Time of day factor (more charging during day and evening)
        float time_factor = 1.0f;
        if (current_time_of_day == TimeOfDay::DAY) {
            time_factor = 1.2f;  // 20% increase during day
        } else if (current_time_of_day == TimeOfDay::DUSK_DAWN) {
            time_factor = 1.4f;  // 40% increase during evening (peak charging time)
        } else if (current_time_of_day == TimeOfDay::NIGHT) {
            time_factor = 0.6f;  // 40% decrease at night
        }
        
        // Frequency-dependent EV charging noise
        float freq_factor = 1.0f;
        if (freq_mhz < 2.0f) {
            freq_factor = 1.3f;  // Higher noise at lower frequencies (switching harmonics)
        } else if (freq_mhz < 10.0f) {
            freq_factor = 1.1f;  // Medium noise in HF band
        } else if (freq_mhz < 30.0f) {
            freq_factor = 1.0f;  // Normal noise
        } else {
            freq_factor = 0.8f;  // Lower noise at higher frequencies
        }
        
        // Weather effects on EV charging noise
        float weather_factor = 1.0f;
        if (weather.has_precipitation) {
            weather_factor = 1.05f;  // Slight increase in wet conditions
        }
        if (weather.has_thunderstorms) {
            weather_factor = 1.1f;  // Increase during storm conditions
        }
        
        // Total station noise
        station_noise = station_noise * time_factor * freq_factor * weather_factor;
        
        // Add to total EV charging noise
        ev_charging_noise += station_noise;
    }
    
    // If no nearby stations, add background EV charging noise based on area
    if (nearby_stations.empty()) {
        // Simulate background EV charging activity based on location
        float background_activity = 0.0f;
        
        // Urban areas have more EV charging activity
        if (lat > 40.7 && lat < 40.8 && lon > -74.1 && lon < -73.9) {
            background_activity = 0.8f;  // High activity in Manhattan
        } else if (lat > 40.6 && lat < 40.8 && lon > -74.2 && lon < -73.8) {
            background_activity = 0.6f;  // Medium activity in NYC metro
        } else if (lat > 40.0 && lat < 41.0 && lon > -74.5 && lon < -73.5) {
            background_activity = 0.3f;  // Low activity in suburbs
        } else {
            background_activity = 0.1f;  // Very low activity in rural areas
        }
        
        // Background noise from distant EV charging stations
        ev_charging_noise += background_activity * 2.0f;  // 2 dB max from background activity
    }
    
    return ev_charging_noise;
}

float FGCom_AtmosphericNoise::calculateSubstationNoise(double lat, double lon, float freq_mhz) {
    // Substation noise calculation
    // This implements noise from electrical substations based on voltage level, capacity, and geometry
    
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    float substation_noise = 0.0f;
    
    // Find nearby substations
    std::vector<Substation> nearby_substations = getNearbySubstations(lat, lon, 20.0f);
    
    for (const auto& substation : nearby_substations) {
        if (!substation.is_active) continue;
        
        // Calculate distance to substation (considering geometry)
        float distance_km = calculateDistanceToGeometry(lat, lon, substation);
        
        // Base noise from substation based on voltage and capacity
        float station_noise = 0.0f;
        
        switch (substation.substation_type) {
            case SubstationType::TRANSMISSION:
                station_noise = 3.0f + (substation.voltage_kv / 100.0f);  // Higher voltage = more noise
                break;
            case SubstationType::DISTRIBUTION:
                station_noise = 2.0f + (substation.voltage_kv / 50.0f);   // Medium voltage noise
                break;
            case SubstationType::SWITCHING:
                station_noise = 1.5f;  // Lower noise from switching only
                break;
            case SubstationType::CONVERTER:
                station_noise = 4.0f;  // High noise from AC/DC conversion
                break;
            case SubstationType::INDUSTRIAL:
                station_noise = 2.5f;  // Industrial substation noise
                break;
            case SubstationType::RAILWAY:
                station_noise = 3.5f;  // Railway electrification noise
                break;
        }
        
        // Scale by capacity (MVA)
        station_noise *= (substation.capacity_mva / 100.0f);  // Normalize to 100 MVA baseline
        
        // Distance decay (1/r² for point sources, modified for geometry)
        if (distance_km < 1.0f) {
            station_noise += 12.0f / (distance_km + 0.1f);  // Very close substations
        } else if (distance_km < 5.0f) {
            station_noise += 6.0f / (distance_km + 0.1f);  // Medium distance substations
        } else if (distance_km < 10.0f) {
            station_noise += 3.0f / (distance_km + 0.1f);  // Distant substations
        }
        
        // Fencing effect (fenced substations have slightly higher noise due to containment)
        if (substation.is_fenced) {
            station_noise *= 1.1f;  // 10% increase for fenced substations
        }
        
        // Apply substation-specific noise factor
        station_noise *= substation.noise_factor;
        
        // Time of day factor (more activity during day)
        float time_factor = 1.0f;
        if (current_time_of_day == TimeOfDay::DAY) {
            time_factor = 1.3f;  // 30% increase during day
        } else if (current_time_of_day == TimeOfDay::DUSK_DAWN) {
            time_factor = 1.1f;  // 10% increase during transition
        } else if (current_time_of_day == TimeOfDay::NIGHT) {
            time_factor = 0.8f;  // 20% decrease at night
        }
        
        // Frequency-dependent substation noise (50/60 Hz harmonics)
        float freq_factor = 1.0f;
        if (freq_mhz < 1.0f) {
            freq_factor = 1.5f;  // Higher noise at very low frequencies
        } else if (freq_mhz < 10.0f) {
            freq_factor = 1.2f;  // Medium noise in HF band
        } else if (freq_mhz < 30.0f) {
            freq_factor = 1.0f;  // Normal noise
        } else {
            freq_factor = 0.7f;  // Lower noise at higher frequencies
        }
        
        // Weather effects on substation noise
        float weather_factor = 1.0f;
        if (weather.has_precipitation) {
            weather_factor = 1.2f;  // Wet conditions increase noise
        }
        if (weather.has_thunderstorms) {
            weather_factor = 1.3f;  // Storm conditions increase noise
        }
        
        // Total station noise
        station_noise = station_noise * time_factor * freq_factor * weather_factor;
        
        // Add to total substation noise
        substation_noise += station_noise;
    }
    
    return substation_noise;
}

float FGCom_AtmosphericNoise::calculatePowerStationNoise(double lat, double lon, float freq_mhz) {
    // Power station noise calculation
    // This implements noise from power stations with 2MW+ capacity threshold
    
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    float power_station_noise = 0.0f;
    
    // Find nearby power stations (only those with 2MW+ capacity)
    std::vector<PowerStation> nearby_stations = getNearbyPowerStations(lat, lon, 50.0f);
    
    for (const auto& station : nearby_stations) {
        if (!station.is_active) continue;
        
        // Only consider stations with 2MW+ peak rated output capacity
        if (station.capacity_mw < 2.0f) continue;
        
        // Calculate distance to power station (considering geometry)
        float distance_km = calculateDistanceToGeometry(lat, lon, station);
        
        // Base noise from power station based on type and capacity
        float station_noise = 0.0f;
        
        switch (station.station_type) {
            case PowerStationType::THERMAL:
                station_noise = 5.0f + (station.capacity_mw / 100.0f);  // High noise from thermal plants
                break;
            case PowerStationType::NUCLEAR:
                station_noise = 6.0f + (station.capacity_mw / 100.0f);  // Very high noise from nuclear plants
                break;
            case PowerStationType::HYDROELECTRIC:
                station_noise = 3.0f + (station.capacity_mw / 200.0f);  // Medium noise from hydro plants
                break;
            case PowerStationType::WIND:
                station_noise = 2.0f + (station.capacity_mw / 300.0f);  // Lower noise from wind farms
                break;
            case PowerStationType::SOLAR:
                station_noise = 1.5f + (station.capacity_mw / 400.0f);  // Low noise from solar farms
                break;
            case PowerStationType::GEOTHERMAL:
                station_noise = 4.0f + (station.capacity_mw / 150.0f);  // High noise from geothermal
                break;
            case PowerStationType::BIOMASS:
                station_noise = 4.5f + (station.capacity_mw / 120.0f);  // High noise from biomass
                break;
            case PowerStationType::PUMPED_STORAGE:
                station_noise = 3.5f + (station.capacity_mw / 180.0f);  // Medium-high noise from pumped storage
                break;
        }
        
        // Scale by current output vs capacity
        float output_factor = station.current_output_mw / station.capacity_mw;
        station_noise *= (0.5f + 0.5f * output_factor);  // Noise scales with output
        
        // Distance decay (1/r² for point sources, modified for geometry)
        if (distance_km < 2.0f) {
            station_noise += 15.0f / (distance_km + 0.1f);  // Very close power stations
        } else if (distance_km < 10.0f) {
            station_noise += 8.0f / (distance_km + 0.1f);  // Medium distance power stations
        } else if (distance_km < 25.0f) {
            station_noise += 4.0f / (distance_km + 0.1f);  // Distant power stations
        }
        
        // Fencing effect (fenced power stations have slightly higher noise)
        if (station.is_fenced) {
            station_noise *= 1.05f;  // 5% increase for fenced power stations
        }
        
        // Apply station-specific noise factor
        station_noise *= station.noise_factor;
        
        // Time of day factor (more activity during day)
        float time_factor = 1.0f;
        if (current_time_of_day == TimeOfDay::DAY) {
            time_factor = 1.2f;  // 20% increase during day
        } else if (current_time_of_day == TimeOfDay::DUSK_DAWN) {
            time_factor = 1.1f;  // 10% increase during transition
        } else if (current_time_of_day == TimeOfDay::NIGHT) {
            time_factor = 0.9f;  // 10% decrease at night
        }
        
        // Frequency-dependent power station noise
        float freq_factor = 1.0f;
        if (freq_mhz < 1.0f) {
            freq_factor = 1.4f;  // Higher noise at very low frequencies
        } else if (freq_mhz < 10.0f) {
            freq_factor = 1.1f;  // Medium noise in HF band
        } else if (freq_mhz < 30.0f) {
            freq_factor = 1.0f;  // Normal noise
        } else {
            freq_factor = 0.8f;  // Lower noise at higher frequencies
        }
        
        // Weather effects on power station noise
        float weather_factor = 1.0f;
        if (weather.has_precipitation) {
            weather_factor = 1.15f;  // Wet conditions increase noise
        }
        if (weather.has_thunderstorms) {
            weather_factor = 1.25f;  // Storm conditions increase noise
        }
        
        // Total station noise
        station_noise = station_noise * time_factor * freq_factor * weather_factor;
        
        // Add to total power station noise
        power_station_noise += station_noise;
    }
    
    return power_station_noise;
}

// Configuration management methods
void FGCom_AtmosphericNoise::resetToDefaults() {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    // Reset to default configuration
    config = NoiseConfig();
    
    // Clear manual environment setting
    manual_environment_set = false;
    environment_type = EnvironmentType::SUBURBAN;
}

void FGCom_AtmosphericNoise::enableAdvancedFeatures(bool enable) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    config.enable_itu_p372_model = enable;
    config.enable_osm_integration = enable;
    config.enable_population_density = enable;
    config.enable_power_line_analysis = enable;
    config.enable_traffic_analysis = enable;
    config.enable_industrial_analysis = enable;
}

void FGCom_AtmosphericNoise::enableSpecificFeature(const std::string& feature_name, bool enable) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    if (feature_name == "itu_p372_model" || feature_name == "itu-p372-model") {
        config.enable_itu_p372_model = enable;
    } else if (feature_name == "osm_integration" || feature_name == "osm-integration") {
        config.enable_osm_integration = enable;
    } else if (feature_name == "population_density" || feature_name == "population-density") {
        config.enable_population_density = enable;
    } else if (feature_name == "power_line_analysis" || feature_name == "power-line-analysis") {
        config.enable_power_line_analysis = enable;
    } else if (feature_name == "traffic_analysis" || feature_name == "traffic-analysis") {
        config.enable_traffic_analysis = enable;
    } else if (feature_name == "industrial_analysis" || feature_name == "industrial-analysis") {
        config.enable_industrial_analysis = enable;
    } else if (feature_name == "ev_charging_analysis" || feature_name == "ev-charging-analysis") {
        config.enable_ev_charging_analysis = enable;
    } else if (feature_name == "substation_analysis" || feature_name == "substation-analysis") {
        config.enable_substation_analysis = enable;
    } else if (feature_name == "power_station_analysis" || feature_name == "power-station-analysis") {
        config.enable_power_station_analysis = enable;
    } else if (feature_name == "openinframap_integration" || feature_name == "openinframap-integration") {
        config.enable_openinframap_integration = enable;
    }
}

// User position setting methods
void FGCom_AtmosphericNoise::setUserPosition(double lat, double lon) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    user_latitude = lat;
    user_longitude = lon;
    user_position_set = true;
    
    // Convert coordinates to Maidenhead locator (simplified)
    // This is a basic implementation - real implementation would be more precise
    if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0) {
        // Convert to Maidenhead format (simplified)
        int field1 = (int)((lat + 90.0) / 10.0);
        int field2 = (int)((lon + 180.0) / 20.0);
        int square1 = (int)(((lat + 90.0) - field1 * 10.0) * 2.0);
        int square2 = (int)(((lon + 180.0) - field2 * 20.0) * 2.0);
        
        user_maidenhead = std::string(1, 'A' + field1) + 
                         std::string(1, 'A' + field2) + 
                         std::to_string(square1) + 
                         std::to_string(square2);
    }
}

void FGCom_AtmosphericNoise::setUserPosition(const std::string& maidenhead) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    user_maidenhead = maidenhead;
    user_position_set = true;
    
    // Convert Maidenhead to coordinates (simplified)
    // This is a basic implementation - real implementation would be more precise
    if (maidenhead.length() >= 2) {
        char field1 = maidenhead[0];
        char field2 = maidenhead[1];
        
        user_latitude = (field1 - 'A') * 10.0 - 90.0;
        user_longitude = (field2 - 'A') * 20.0 - 180.0;
        
        // Add sub-square precision if available
        if (maidenhead.length() >= 4) {
            int square1 = maidenhead[2] - '0';
            int square2 = maidenhead[3] - '0';
            
            user_latitude += square1 * 0.5;  // 0.5 degree precision
            user_longitude += square2 * 1.0;  // 1.0 degree precision
        }
    }
}

void FGCom_AtmosphericNoise::setUserPosition(double lat, double lon, const std::string& maidenhead) {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    user_latitude = lat;
    user_longitude = lon;
    user_maidenhead = maidenhead;
    user_position_set = true;
}

std::pair<double, double> FGCom_AtmosphericNoise::getUserPosition() const {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    return std::make_pair(user_latitude, user_longitude);
}

std::string FGCom_AtmosphericNoise::getUserMaidenhead() const {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    return user_maidenhead;
}

bool FGCom_AtmosphericNoise::isUserPositionSet() const {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    return user_position_set;
}

void FGCom_AtmosphericNoise::clearUserPosition() {
    std::lock_guard<std::mutex> config_lock(config_mutex);
    
    user_latitude = 0.0;
    user_longitude = 0.0;
    user_maidenhead = "";
    user_position_set = false;
}

float FGCom_AtmosphericNoise::calculateNoiseFloorForUserPosition(float freq_mhz) {
    if (!user_position_set) {
        return calculateNoiseFloor(0.0, 0.0, freq_mhz);  // Default calculation
    }
    
    return calculateNoiseFloor(user_latitude, user_longitude, freq_mhz);
}

float FGCom_AtmosphericNoise::calculateNoiseFloorForUserPosition(float freq_mhz, EnvironmentType env_type) {
    if (!user_position_set) {
        return calculateNoiseFloor(0.0, 0.0, freq_mhz, env_type);  // Default calculation
    }
    
    return calculateNoiseFloor(user_latitude, user_longitude, freq_mhz, env_type);
}

// EV Charging Station management methods
void FGCom_AtmosphericNoise::addEVChargingStation(const EVChargingStation& station) {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    
    // Check if station already exists
    auto it = std::find_if(ev_charging_stations.begin(), ev_charging_stations.end(),
        [&station](const EVChargingStation& s) { return s.station_id == station.station_id; });
    
    if (it != ev_charging_stations.end()) {
        // Update existing station
        *it = station;
    } else {
        // Add new station
        ev_charging_stations.push_back(station);
    }
}

void FGCom_AtmosphericNoise::removeEVChargingStation(const std::string& station_id) {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    
    ev_charging_stations.erase(
        std::remove_if(ev_charging_stations.begin(), ev_charging_stations.end(),
            [&station_id](const EVChargingStation& s) { return s.station_id == station_id; }),
        ev_charging_stations.end());
}

void FGCom_AtmosphericNoise::updateEVChargingStation(const std::string& station_id, const EVChargingStation& station) {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    
    auto it = std::find_if(ev_charging_stations.begin(), ev_charging_stations.end(),
        [&station_id](const EVChargingStation& s) { return s.station_id == station_id; });
    
    if (it != ev_charging_stations.end()) {
        *it = station;
    }
}

std::vector<EVChargingStation> FGCom_AtmosphericNoise::getNearbyEVChargingStations(double lat, double lon, float radius_km) {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    std::vector<EVChargingStation> nearby_stations;
    
    for (const auto& station : ev_charging_stations) {
        float distance = calculateDistance(lat, lon, station.latitude, station.longitude);
        if (distance <= radius_km) {
            nearby_stations.push_back(station);
        }
    }
    
    return nearby_stations;
}

void FGCom_AtmosphericNoise::clearEVChargingStations() {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    ev_charging_stations.clear();
}

size_t FGCom_AtmosphericNoise::getEVChargingStationCount() const {
    std::lock_guard<std::mutex> ev_lock(ev_stations_mutex);
    return ev_charging_stations.size();
}

// Substation management methods
void FGCom_AtmosphericNoise::addSubstation(const Substation& substation) {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    
    // Check if substation already exists
    auto it = std::find_if(substations.begin(), substations.end(),
        [&substation](const Substation& s) { return s.substation_id == substation.substation_id; });
    
    if (it != substations.end()) {
        // Update existing substation
        *it = substation;
    } else {
        // Add new substation
        substations.push_back(substation);
    }
}

void FGCom_AtmosphericNoise::removeSubstation(const std::string& substation_id) {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    
    substations.erase(
        std::remove_if(substations.begin(), substations.end(),
            [&substation_id](const Substation& s) { return s.substation_id == substation_id; }),
        substations.end());
}

void FGCom_AtmosphericNoise::updateSubstation(const std::string& substation_id, const Substation& substation) {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    
    auto it = std::find_if(substations.begin(), substations.end(),
        [&substation_id](const Substation& s) { return s.substation_id == substation_id; });
    
    if (it != substations.end()) {
        *it = substation;
    }
}

std::vector<Substation> FGCom_AtmosphericNoise::getNearbySubstations(double lat, double lon, float radius_km) {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    std::vector<Substation> nearby_substations;
    
    for (const auto& substation : substations) {
        float distance = calculateDistance(lat, lon, substation.latitude, substation.longitude);
        if (distance <= radius_km) {
            nearby_substations.push_back(substation);
        }
    }
    
    return nearby_substations;
}

void FGCom_AtmosphericNoise::clearSubstations() {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    substations.clear();
}

size_t FGCom_AtmosphericNoise::getSubstationCount() const {
    std::lock_guard<std::mutex> substation_lock(substations_mutex);
    return substations.size();
}

// Power station management methods
void FGCom_AtmosphericNoise::addPowerStation(const PowerStation& station) {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    
    // Check if power station already exists
    auto it = std::find_if(power_stations.begin(), power_stations.end(),
        [&station](const PowerStation& s) { return s.station_id == station.station_id; });
    
    if (it != power_stations.end()) {
        // Update existing power station
        *it = station;
    } else {
        // Add new power station
        power_stations.push_back(station);
    }
}

void FGCom_AtmosphericNoise::removePowerStation(const std::string& station_id) {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    
    power_stations.erase(
        std::remove_if(power_stations.begin(), power_stations.end(),
            [&station_id](const PowerStation& s) { return s.station_id == station_id; }),
        power_stations.end());
}

void FGCom_AtmosphericNoise::updatePowerStation(const std::string& station_id, const PowerStation& station) {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    
    auto it = std::find_if(power_stations.begin(), power_stations.end(),
        [&station_id](const PowerStation& s) { return s.station_id == station_id; });
    
    if (it != power_stations.end()) {
        *it = station;
    }
}

std::vector<PowerStation> FGCom_AtmosphericNoise::getNearbyPowerStations(double lat, double lon, float radius_km) {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    std::vector<PowerStation> nearby_stations;
    
    for (const auto& station : power_stations) {
        float distance = calculateDistance(lat, lon, station.latitude, station.longitude);
        if (distance <= radius_km) {
            nearby_stations.push_back(station);
        }
    }
    
    return nearby_stations;
}

void FGCom_AtmosphericNoise::clearPowerStations() {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    power_stations.clear();
}

size_t FGCom_AtmosphericNoise::getPowerStationCount() const {
    std::lock_guard<std::mutex> power_lock(power_stations_mutex);
    return power_stations.size();
}

// Helper function to calculate distance to geometry (point, polygon, multipolygon)
float FGCom_AtmosphericNoise::calculateDistanceToGeometry(double lat, double lon, const Substation& substation) {
    // For now, use simple point distance calculation
    // TODO: Implement proper polygon and multipolygon distance calculation
    return calculateDistance(lat, lon, substation.latitude, substation.longitude);
}

float FGCom_AtmosphericNoise::calculateDistanceToGeometry(double lat, double lon, const PowerStation& station) {
    // For now, use simple point distance calculation
    // TODO: Implement proper polygon and multipolygon distance calculation
    return calculateDistance(lat, lon, station.latitude, station.longitude);
}

// Open Infrastructure Map integration methods
void FGCom_AtmosphericNoise::enableOpenInfraMapIntegration(bool enable) {
    std::lock_guard<std::mutex> lock(openinframap_mutex);
    enable_openinframap_integration = enable;
}

bool FGCom_AtmosphericNoise::isOpenInfraMapIntegrationEnabled() const {
    std::lock_guard<std::mutex> lock(openinframap_mutex);
    return enable_openinframap_integration;
}

void FGCom_AtmosphericNoise::updateFromOpenInfraMap(double lat, double lon, float radius_km) {
    if (!enable_openinframap_integration) {
        return;
    }
    
#ifdef ENABLE_OPENINFRAMAP
    // Get Open Infrastructure Map data source
    auto& data_source = FGCom_OpenInfraMapDataSource::getInstance();
    
    // Fetch substation data
    if (config.enable_substation_analysis) {
        auto substations = data_source.getSubstations(lat, lon, radius_km);
        for (const auto& substation : substations) {
            addSubstation(substation);
        }
    }
    
    // Fetch power station data
    if (config.enable_power_station_analysis) {
        auto power_stations = data_source.getPowerStations(lat, lon, radius_km);
        for (const auto& station : power_stations) {
            addPowerStation(station);
        }
    }
#else
    // OpenInfraMap integration not compiled in
    (void)lat; (void)lon; (void)radius_km; // Suppress unused parameter warnings
#endif
}

void FGCom_AtmosphericNoise::setOpenInfraMapUpdateCallback(std::function<void()> callback) {
    // This would be implemented to set up callbacks for Open Infrastructure Map updates
    // For now, it's a placeholder
    (void)callback;
}

std::string FGCom_AtmosphericNoise::getOpenInfraMapStatus() const {
    if (!enable_openinframap_integration) {
        return "Open Infrastructure Map integration is disabled";
    }
    
#ifdef ENABLE_OPENINFRAMAP
    auto& data_source = FGCom_OpenInfraMapDataSource::getInstance();
    return data_source.getStatusString();
#else
    return "OpenInfraMap integration not compiled in";
#endif
}
