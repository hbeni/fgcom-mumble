#include "power_management.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

// Singleton instance
std::unique_ptr<FGCom_PowerManager> FGCom_PowerManager::instance = nullptr;
std::mutex FGCom_PowerManager::instance_mutex;

// Constructor
FGCom_PowerManager::FGCom_PowerManager() 
    : power_limiting_active(false)
    , thermal_protection_active(false)
    , swr_protection_active(false)
    , current_swr(1.0f)
    , current_temperature(25.0f)
    , current_antenna_type("vertical")
    , current_frequency_band("amateur")
{
    // Initialize default power levels
    current_power_levels.current_power = 100;
    current_power_levels.power_efficiency = 0.8f;
    current_power_levels.power_limiting = true;
    current_power_levels.max_safe_power = 1000.0f;
    current_power_levels.regulatory_limit = 1500.0f;
    current_power_levels.efficiency_optimization = true;
    current_power_levels.battery_level = 1.0f;
    current_power_levels.power_consumption = 100.0f;
    current_power_levels.last_power_change = std::chrono::system_clock::now();
    
    // Initialize statistics
    stats.total_power_changes = 0;
    stats.average_efficiency = 0.8f;
    stats.peak_power_used = 100.0f;
    stats.total_energy_consumed = 0.0f;
    stats.last_reset = std::chrono::system_clock::now();
    stats.efficiency_vs_power_correlation = 0.0f;
    stats.thermal_shutdowns = 0;
    stats.swr_shutdowns = 0;
    stats.regulatory_violations = 0;
    
    // Initialize default data
    initializeDefaultAntennaData();
    initializeDefaultRegulatoryLimits();
}

// Singleton access
FGCom_PowerManager& FGCom_PowerManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_PowerManager>(new FGCom_PowerManager());
    }
    return *instance;
}

void FGCom_PowerManager::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance.reset();
}

// Power level management
bool FGCom_PowerManager::setPowerLevel(int power_watts) {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    // Check if power level is available
    if (!isPowerLevelAvailable(power_watts)) {
        return false;
    }
    
    // Check all safety limits
    if (!checkAllSafetyLimits(power_watts)) {
        return false;
    }
    
    // Apply power limiting if enabled
    int actual_power = power_watts;
    if (config.enable_automatic_power_limiting) {
        if (!applyPowerLimits(power_watts, actual_power)) {
            return false;
        }
    }
    
    // Store old power for logging
    int old_power = current_power_levels.current_power;
    
    // Update power level
    current_power_levels.current_power = actual_power;
    current_power_levels.last_power_change = std::chrono::system_clock::now();
    
    // Update efficiency
    updatePowerEfficiency();
    
    // Update statistics
    stats.total_power_changes++;
    stats.peak_power_used = std::max(stats.peak_power_used, static_cast<float>(actual_power));
    stats.power_level_usage[actual_power]++;
    
    // Log power change
    if (config.log_power_changes) {
        logPowerChange(old_power, actual_power);
    }
    
    // Call callback if set
    if (power_change_callback) {
        power_change_callback(old_power, actual_power);
    }
    
    return true;
}

int FGCom_PowerManager::getCurrentPower() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.current_power;
}

std::vector<int> FGCom_PowerManager::getAvailablePowerLevels() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.available_powers;
}

bool FGCom_PowerManager::isPowerLevelAvailable(int power_watts) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return std::find(current_power_levels.available_powers.begin(), 
                     current_power_levels.available_powers.end(), 
                     power_watts) != current_power_levels.available_powers.end();
}

// Power efficiency calculations
float FGCom_PowerManager::calculatePowerEfficiency(int power_watts, const std::string& antenna_type) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = antenna_efficiency_data.find(antenna_type);
    if (it == antenna_efficiency_data.end()) {
        // Default efficiency calculation
        return std::max(0.5f, 1.0f - (power_watts - 100.0f) / 2000.0f);
    }
    
    const AntennaPowerEfficiency& efficiency_data = it->second;
    auto efficiency_it = efficiency_data.efficiency_at_power.find(power_watts);
    if (efficiency_it != efficiency_data.efficiency_at_power.end()) {
        return efficiency_it->second;
    }
    
    // Interpolate between available power levels
    int lower_power = 0, upper_power = 0;
    float lower_efficiency = 0.0f, upper_efficiency = 0.0f;
    
    for (const auto& pair : efficiency_data.efficiency_at_power) {
        if (pair.first <= power_watts && pair.first > lower_power) {
            lower_power = pair.first;
            lower_efficiency = pair.second;
        }
        if (pair.first >= power_watts && (upper_power == 0 || pair.first < upper_power)) {
            upper_power = pair.first;
            upper_efficiency = pair.second;
        }
    }
    
    if (lower_power == 0 || upper_power == 0) {
        return efficiency_data.efficiency_threshold;
    }
    
    // Linear interpolation
    float ratio = static_cast<float>(power_watts - lower_power) / (upper_power - lower_power);
    return lower_efficiency + ratio * (upper_efficiency - lower_efficiency);
}

float FGCom_PowerManager::getCurrentPowerEfficiency() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.power_efficiency;
}

int FGCom_PowerManager::getOptimalPowerLevel(const std::string& antenna_type) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = antenna_efficiency_data.find(antenna_type);
    if (it == antenna_efficiency_data.end()) {
        return 100; // Default optimal power
    }
    
    const AntennaPowerEfficiency& efficiency_data = it->second;
    return static_cast<int>(efficiency_data.max_efficient_power);
}

bool FGCom_PowerManager::optimizePowerForEfficiency() {
    if (!config.enable_efficiency_optimization) {
        return false;
    }
    
    int optimal_power = getOptimalPowerLevel(current_antenna_type);
    return setPowerLevel(optimal_power);
}

// Automatic power limiting
bool FGCom_PowerManager::enablePowerLimiting(bool enable) {
    std::lock_guard<std::mutex> lock(power_mutex);
    power_limiting_active = enable;
    current_power_levels.power_limiting = enable;
    return true;
}

bool FGCom_PowerManager::isPowerLimitingActive() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return power_limiting_active;
}

bool FGCom_PowerManager::checkPowerLimits(int power_watts) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    // Check regulatory limits
    if (config.enable_regulatory_compliance) {
        if (!checkRegulatoryCompliance(power_watts, current_frequency_band)) {
            return false;
        }
    }
    
    // Check thermal limits
    if (config.enable_thermal_protection) {
        if (!checkThermalLimits(power_watts)) {
            return false;
        }
    }
    
    // Check SWR limits
    if (config.enable_swr_protection) {
        if (!checkSWRLimits(power_watts)) {
            return false;
        }
    }
    
    // Check antenna limits
    auto it = antenna_efficiency_data.find(current_antenna_type);
    if (it != antenna_efficiency_data.end()) {
        const AntennaPowerEfficiency& efficiency_data = it->second;
        if (power_watts > efficiency_data.thermal_limit) {
            return false;
        }
    }
    
    return true;
}

bool FGCom_PowerManager::applyPowerLimits(int requested_power, int& actual_power) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    actual_power = requested_power;
    
    // Apply regulatory limit
    if (config.enable_regulatory_compliance) {
        float regulatory_limit = getRegulatoryPowerLimit(current_frequency_band);
        if (actual_power > regulatory_limit) {
            actual_power = static_cast<int>(regulatory_limit);
        }
    }
    
    // Get antenna efficiency data for thermal and SWR limits
    const AntennaPowerEfficiency* efficiency_data = nullptr;
    auto it = antenna_efficiency_data.find(current_antenna_type);
    if (it != antenna_efficiency_data.end()) {
        efficiency_data = &it->second;
    }
    
    // Apply thermal limit
    if (config.enable_thermal_protection && efficiency_data) {
        if (actual_power > efficiency_data->thermal_limit) {
            actual_power = static_cast<int>(efficiency_data->thermal_limit);
        }
    }
    
    // Apply SWR limit
    if (config.enable_swr_protection && efficiency_data && current_swr > efficiency_data->swr_limit) {
        actual_power = static_cast<int>(actual_power * (efficiency_data->swr_limit / current_swr));
    }
    
    // Apply battery limit
    if (config.enable_battery_management) {
        int max_battery_power = getMaxPowerForBattery();
        if (actual_power > max_battery_power) {
            actual_power = max_battery_power;
        }
    }
    
    return actual_power > 0;
}

// Regulatory compliance
bool FGCom_PowerManager::checkRegulatoryCompliance(int power_watts, const std::string& frequency_band) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = regulatory_limits.find(frequency_band);
    if (it == regulatory_limits.end()) {
        return true; // No specific limits defined
    }
    
    const RegulatoryPowerLimits& limits = it->second;
    return power_watts <= limits.max_power_watts;
}

float FGCom_PowerManager::getRegulatoryPowerLimit(const std::string& frequency_band) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = regulatory_limits.find(frequency_band);
    if (it == regulatory_limits.end()) {
        return 1500.0f; // Default limit
    }
    
    return it->second.max_power_watts;
}

bool FGCom_PowerManager::isRegulatoryCompliant(int power_watts, const std::string& frequency_band) const {
    return checkRegulatoryCompliance(power_watts, frequency_band);
}

// Thermal protection
bool FGCom_PowerManager::enableThermalProtection(bool enable) {
    std::lock_guard<std::mutex> lock(power_mutex);
    thermal_protection_active = enable;
    return true;
}

bool FGCom_PowerManager::isThermalProtectionActive() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return thermal_protection_active;
}

void FGCom_PowerManager::updateTemperature(float temperature_celsius) {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_temperature = temperature_celsius;
    
    // Check for thermal shutdown
    if (temperature_celsius > config.thermal_shutdown_threshold * 100.0f) {
        emergencyPowerDown();
        stats.thermal_shutdowns++;
        logSafetyEvent("Thermal shutdown triggered");
    }
}

bool FGCom_PowerManager::checkThermalLimits(int power_watts) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    // Simple thermal model: higher power = higher temperature
    float estimated_temperature = current_temperature + (power_watts - 100.0f) * 0.1f;
    return estimated_temperature < config.thermal_shutdown_threshold * 100.0f;
}

// SWR protection
bool FGCom_PowerManager::enableSWRProtection(bool enable) {
    std::lock_guard<std::mutex> lock(power_mutex);
    swr_protection_active = enable;
    return true;
}

bool FGCom_PowerManager::isSWRProtectionActive() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return swr_protection_active;
}

void FGCom_PowerManager::updateSWR(float swr_ratio) {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_swr = swr_ratio;
    
    // Check for SWR shutdown
    if (swr_ratio > config.swr_shutdown_threshold) {
        emergencyPowerDown();
        stats.swr_shutdowns++;
        logSafetyEvent("SWR shutdown triggered");
    }
}

bool FGCom_PowerManager::checkSWRLimits(int power_watts) const {
    (void)power_watts; // Suppress unused parameter warning
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = antenna_efficiency_data.find(current_antenna_type);
    if (it == antenna_efficiency_data.end()) {
        return current_swr < config.swr_shutdown_threshold;
    }
    
    const AntennaPowerEfficiency& efficiency_data = it->second;
    return current_swr < efficiency_data.swr_limit;
}

// Battery management
void FGCom_PowerManager::updateBatteryLevel(float battery_level) {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_power_levels.battery_level = std::max(0.0f, std::min(1.0f, battery_level));
}

float FGCom_PowerManager::getBatteryLevel() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.battery_level;
}

bool FGCom_PowerManager::isBatteryLow() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.battery_level < config.battery_low_threshold;
}

int FGCom_PowerManager::getMaxPowerForBattery() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    // Simple model: max power scales with battery level
    float max_power_ratio = current_power_levels.battery_level;
    if (isBatteryLow()) {
        max_power_ratio *= 0.5f; // Reduce power when battery is low
    }
    
    return static_cast<int>(1000.0f * max_power_ratio);
}

// Antenna management
void FGCom_PowerManager::setCurrentAntenna(const std::string& antenna_type) {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_antenna_type = antenna_type;
    updatePowerEfficiency();
}

std::string FGCom_PowerManager::getCurrentAntenna() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_antenna_type;
}

bool FGCom_PowerManager::loadAntennaEfficiencyData(const std::string& antenna_type, const AntennaPowerEfficiency& data) {
    std::lock_guard<std::mutex> lock(power_mutex);
    antenna_efficiency_data[antenna_type] = data;
    return true;
}

AntennaPowerEfficiency FGCom_PowerManager::getAntennaEfficiencyData(const std::string& antenna_type) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = antenna_efficiency_data.find(antenna_type);
    if (it == antenna_efficiency_data.end()) {
        return AntennaPowerEfficiency(); // Return default
    }
    
    return it->second;
}

// Frequency band management
void FGCom_PowerManager::setCurrentFrequencyBand(const std::string& frequency_band) {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_frequency_band = frequency_band;
}

std::string FGCom_PowerManager::getCurrentFrequencyBand() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_frequency_band;
}

bool FGCom_PowerManager::loadRegulatoryLimits(const std::string& frequency_band, const RegulatoryPowerLimits& limits) {
    std::lock_guard<std::mutex> lock(power_mutex);
    regulatory_limits[frequency_band] = limits;
    return true;
}

RegulatoryPowerLimits FGCom_PowerManager::getRegulatoryLimits(const std::string& frequency_band) const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto it = regulatory_limits.find(frequency_band);
    if (it == regulatory_limits.end()) {
        return RegulatoryPowerLimits(); // Return default
    }
    
    return it->second;
}

// Configuration management
void FGCom_PowerManager::setConfig(const PowerManagementConfig& new_config) {
    std::lock_guard<std::mutex> lock(power_mutex);
    config = new_config;
}

PowerManagementConfig FGCom_PowerManager::getConfig() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return config;
}

bool FGCom_PowerManager::loadConfigFromFile(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section = "";
    
    while (std::getline(file, line)) {
        // Simple INI file parsing
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        size_t equal_pos = line.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = line.substr(0, equal_pos);
            std::string value = line.substr(equal_pos + 1);
            
            // Parse configuration values
            if (current_section == "power_management") {
                if (key == "enable_automatic_power_limiting") {
                    config.enable_automatic_power_limiting = (value == "true");
                } else if (key == "enable_efficiency_optimization") {
                    config.enable_efficiency_optimization = (value == "true");
                } else if (key == "default_efficiency_threshold") {
                    config.default_efficiency_threshold = std::stof(value);
                }
                // Add more configuration parsing as needed
            }
        }
    }
    
    return true;
}

bool FGCom_PowerManager::saveConfigToFile(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "[power_management]" << std::endl;
    file << "enable_automatic_power_limiting=" << (config.enable_automatic_power_limiting ? "true" : "false") << std::endl;
    file << "enable_efficiency_optimization=" << (config.enable_efficiency_optimization ? "true" : "false") << std::endl;
    file << "default_efficiency_threshold=" << config.default_efficiency_threshold << std::endl;
    file << "thermal_shutdown_threshold=" << config.thermal_shutdown_threshold << std::endl;
    file << "swr_shutdown_threshold=" << config.swr_shutdown_threshold << std::endl;
    file << "battery_low_threshold=" << config.battery_low_threshold << std::endl;
    
    return true;
}

// Statistics and monitoring
PowerManagementStats FGCom_PowerManager::getStats() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return stats;
}

void FGCom_PowerManager::resetStats() {
    std::lock_guard<std::mutex> lock(power_mutex);
    stats = PowerManagementStats();
    stats.last_reset = std::chrono::system_clock::now();
}

void FGCom_PowerManager::updateStats() {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    // Update average efficiency
    if (stats.total_power_changes > 0) {
        stats.average_efficiency = (stats.average_efficiency * (stats.total_power_changes - 1) + 
                                   current_power_levels.power_efficiency) / stats.total_power_changes;
    }
    
    // Update energy consumption
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.last_reset);
    stats.total_energy_consumed += current_power_levels.power_consumption * duration.count() / 3600.0f; // kWh
}

bool FGCom_PowerManager::isPowerAnalyticsEnabled() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return config.enable_power_analytics;
}

// Power change management
bool FGCom_PowerManager::canChangePower() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - current_power_levels.last_power_change);
    
    return duration.count() >= config.power_change_delay_ms;
}

void FGCom_PowerManager::setPowerChangeDelay(int delay_ms) {
    std::lock_guard<std::mutex> lock(power_mutex);
    config.power_change_delay_ms = delay_ms;
}

int FGCom_PowerManager::getPowerChangeDelay() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return config.power_change_delay_ms;
}

// Safety and protection
bool FGCom_PowerManager::isSafeToTransmit(int power_watts) const {
    return checkAllSafetyLimits(power_watts);
}

bool FGCom_PowerManager::checkAllSafetyLimits(int power_watts) const {
    return checkPowerLimits(power_watts) && 
           checkThermalLimits(power_watts) && 
           checkSWRLimits(power_watts) &&
           checkRegulatoryCompliance(power_watts, current_frequency_band);
}

void FGCom_PowerManager::emergencyPowerDown() {
    std::lock_guard<std::mutex> lock(power_mutex);
    current_power_levels.current_power = 0;
    current_power_levels.last_power_change = std::chrono::system_clock::now();
    logSafetyEvent("Emergency power down");
}

bool FGCom_PowerManager::isEmergencyPowerDown() const {
    std::lock_guard<std::mutex> lock(power_mutex);
    return current_power_levels.current_power == 0;
}

// Power optimization
int FGCom_PowerManager::calculateOptimalPowerForRange(double distance_km, const std::string& antenna_type) const {
    // Simple model: power needed scales with distance squared
    float base_power = 100.0f;
    float distance_factor = static_cast<float>(distance_km / 100.0); // 100km reference
    int optimal_power = static_cast<int>(base_power * distance_factor * distance_factor);
    
    // Apply efficiency optimization
    float efficiency = calculatePowerEfficiency(optimal_power, antenna_type);
    if (efficiency < config.default_efficiency_threshold) {
        optimal_power = static_cast<int>(optimal_power * efficiency);
    }
    
    // Clamp to available power levels
    auto available_powers = getAvailablePowerLevels();
    auto it = std::lower_bound(available_powers.begin(), available_powers.end(), optimal_power);
    if (it != available_powers.end()) {
        optimal_power = *it;
    } else {
        optimal_power = available_powers.back();
    }
    
    return optimal_power;
}

int FGCom_PowerManager::calculateOptimalPowerForSignalQuality(float target_quality, double distance_km, const std::string& antenna_type) const {
    // Inverse of the power/distance model from radio_model_hf.cpp
    float required_power = static_cast<float>(distance_km * distance_km / (1000.0 * (1.0 - target_quality)));
    
    // Apply efficiency optimization
    float efficiency = calculatePowerEfficiency(static_cast<int>(required_power), antenna_type);
    required_power /= efficiency;
    
    return static_cast<int>(required_power);
}

float FGCom_PowerManager::calculatePowerConsumption(int power_watts, const std::string& antenna_type) const {
    // Power consumption includes transmitter efficiency and antenna losses
    float efficiency = calculatePowerEfficiency(power_watts, antenna_type);
    return power_watts / efficiency;
}

// Integration with existing radio models
float FGCom_PowerManager::getEffectiveRadiatedPower(int tx_power_watts, const std::string& antenna_type, float azimuth_deg, float elevation_deg, float frequency_mhz) const {
    (void)azimuth_deg; // Suppress unused parameter warning
    (void)elevation_deg; // Suppress unused parameter warning
    (void)frequency_mhz; // Suppress unused parameter warning
    // This would integrate with the existing antenna_ground_system.cpp
    // For now, return a simplified calculation
    float efficiency = calculatePowerEfficiency(tx_power_watts, antenna_type);
    return tx_power_watts * efficiency;
}

float FGCom_PowerManager::getPowerEfficiencyAtFrequency(int power_watts, const std::string& antenna_type, float frequency_mhz) const {
    // Frequency-dependent efficiency calculation
    float base_efficiency = calculatePowerEfficiency(power_watts, antenna_type);
    
    // Simple frequency response model
    float frequency_factor = 1.0f;
    if (frequency_mhz < 10.0f) {
        frequency_factor = 0.8f; // Lower efficiency at low frequencies
    } else if (frequency_mhz > 30.0f) {
        frequency_factor = 0.9f; // Slightly lower efficiency at high frequencies
    }
    
    return base_efficiency * frequency_factor;
}

// Event callbacks
void FGCom_PowerManager::setPowerChangeCallback(std::function<void(int, int)> callback) {
    std::lock_guard<std::mutex> lock(power_mutex);
    power_change_callback = callback;
}

void FGCom_PowerManager::setEfficiencyChangeCallback(std::function<void(float)> callback) {
    std::lock_guard<std::mutex> lock(power_mutex);
    efficiency_change_callback = callback;
}

void FGCom_PowerManager::setSafetyEventCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(power_mutex);
    safety_event_callback = callback;
}

// Private helper methods
void FGCom_PowerManager::initializeDefaultAntennaData() {
    // Vertical antenna efficiency data
    AntennaPowerEfficiency vertical_data;
    vertical_data.antenna_type = "vertical";
    vertical_data.efficiency_at_power = {
        {50, 0.85f}, {100, 0.80f}, {200, 0.75f}, {400, 0.70f}, 
        {600, 0.65f}, {800, 0.60f}, {1000, 0.55f}
    };
    vertical_data.max_efficient_power = 100.0f;
    vertical_data.efficiency_threshold = 0.7f;
    vertical_data.has_power_limiting = true;
    vertical_data.thermal_limit = 800.0f;
    vertical_data.swr_limit = 2.0f;
    antenna_efficiency_data["vertical"] = vertical_data;
    
    // Yagi antenna efficiency data
    AntennaPowerEfficiency yagi_data;
    yagi_data.antenna_type = "yagi";
    yagi_data.efficiency_at_power = {
        {50, 0.90f}, {100, 0.85f}, {200, 0.80f}, {400, 0.75f}, 
        {600, 0.70f}, {800, 0.65f}, {1000, 0.60f}
    };
    yagi_data.max_efficient_power = 200.0f;
    yagi_data.efficiency_threshold = 0.75f;
    yagi_data.has_power_limiting = true;
    yagi_data.thermal_limit = 1000.0f;
    yagi_data.swr_limit = 1.5f;
    antenna_efficiency_data["yagi"] = yagi_data;
    
    // Loop antenna efficiency data
    AntennaPowerEfficiency loop_data;
    loop_data.antenna_type = "loop";
    loop_data.efficiency_at_power = {
        {50, 0.80f}, {100, 0.75f}, {200, 0.70f}, {400, 0.65f}, 
        {600, 0.60f}, {800, 0.55f}, {1000, 0.50f}
    };
    loop_data.max_efficient_power = 150.0f;
    loop_data.efficiency_threshold = 0.65f;
    loop_data.has_power_limiting = true;
    loop_data.thermal_limit = 600.0f;
    loop_data.swr_limit = 2.5f;
    antenna_efficiency_data["loop"] = loop_data;
}

void FGCom_PowerManager::initializeDefaultRegulatoryLimits() {
    // Amateur radio limits
    RegulatoryPowerLimits amateur_limits;
    amateur_limits.band_name = "amateur";
    amateur_limits.min_freq_mhz = 1.8f;
    amateur_limits.max_freq_mhz = 54.0f;
    amateur_limits.max_power_watts = 1500.0f;
    amateur_limits.regulatory_body = "FCC";
    amateur_limits.license_type = "Amateur";
    amateur_limits.requires_license = true;
    amateur_limits.power_density_limit = 100.0f;
    regulatory_limits["amateur"] = amateur_limits;
    
    // Commercial limits
    RegulatoryPowerLimits commercial_limits;
    commercial_limits.band_name = "commercial";
    commercial_limits.min_freq_mhz = 2.0f;
    commercial_limits.max_freq_mhz = 30.0f;
    commercial_limits.max_power_watts = 1000.0f;
    commercial_limits.regulatory_body = "FCC";
    commercial_limits.license_type = "Commercial";
    commercial_limits.requires_license = true;
    commercial_limits.power_density_limit = 50.0f;
    regulatory_limits["commercial"] = commercial_limits;
    
    // Military limits
    RegulatoryPowerLimits military_limits;
    military_limits.band_name = "military";
    military_limits.min_freq_mhz = 2.0f;
    military_limits.max_freq_mhz = 30.0f;
    military_limits.max_power_watts = 2000.0f;
    military_limits.regulatory_body = "ITU";
    military_limits.license_type = "Military";
    military_limits.requires_license = true;
    military_limits.power_density_limit = 200.0f;
    regulatory_limits["military"] = military_limits;
}

void FGCom_PowerManager::updatePowerEfficiency() {
    current_power_levels.power_efficiency = calculatePowerEfficiency(current_power_levels.current_power, current_antenna_type);
    
    // Call efficiency change callback if set
    if (efficiency_change_callback) {
        efficiency_change_callback(current_power_levels.power_efficiency);
    }
}

void FGCom_PowerManager::checkSafetyLimits() {
    if (!checkAllSafetyLimits(current_power_levels.current_power)) {
        emergencyPowerDown();
    }
}

void FGCom_PowerManager::logPowerChange(int old_power, int new_power) {
    if (config.log_power_changes) {
        std::cout << "[PowerManager] Power changed from " << old_power << "W to " << new_power << "W" << std::endl;
    }
}

void FGCom_PowerManager::logSafetyEvent(const std::string& event) {
    std::cout << "[PowerManager] Safety event: " << event << std::endl;
    
    if (safety_event_callback) {
        safety_event_callback(event);
    }
}

// Utility functions implementation
namespace PowerManagementUtils {
    float wattsToDBm(float watts) {
        return 10.0f * log10(watts * 1000.0f);
    }
    
    float dbmToWatts(float dbm) {
        return pow(10.0f, dbm / 10.0f) / 1000.0f;
    }
    
    float wattsToDBW(float watts) {
        return 10.0f * log10(watts);
    }
    
    float dbwToWatts(float dbw) {
        return pow(10.0f, dbw / 10.0f);
    }
    
    float calculatePowerDensity(float power_watts, float distance_meters) {
        // Assuming isotropic radiation
        float area = 4.0f * M_PI * distance_meters * distance_meters;
        return power_watts / area;
    }
    
    bool checkPowerDensityLimit(float power_watts, float distance_meters, float limit_w_per_m2) {
        float power_density = calculatePowerDensity(power_watts, distance_meters);
        return power_density <= limit_w_per_m2;
    }
    
    float calculateERP(float tx_power_watts, float antenna_gain_db, float system_loss_db) {
        float net_gain_db = antenna_gain_db - system_loss_db;
        return tx_power_watts * pow(10.0f, net_gain_db / 10.0f);
    }
    
    float calculateEIRP(float tx_power_watts, float antenna_gain_db, float system_loss_db) {
        return calculateERP(tx_power_watts, antenna_gain_db, system_loss_db);
    }
    
    float calculateAntennaEfficiency(float power_watts, float swr, float temperature_celsius) {
        (void)power_watts; // Suppress unused parameter warning
        // Simple efficiency model based on SWR and temperature
        float swr_efficiency = 1.0f / (1.0f + (swr - 1.0f) * 0.1f);
        float temp_efficiency = 1.0f - (temperature_celsius - 25.0f) * 0.001f;
        return std::max(0.1f, swr_efficiency * temp_efficiency);
    }
    
    float calculateSystemEfficiency(float tx_power_watts, float antenna_efficiency, float feedline_loss_db, float connector_loss_db) {
        (void)tx_power_watts; // Suppress unused parameter warning
        float total_loss_db = feedline_loss_db + connector_loss_db;
        float loss_factor = pow(10.0f, -total_loss_db / 10.0f);
        return antenna_efficiency * loss_factor;
    }
    
    bool isAmateurRadioFrequency(float frequency_mhz) {
        return (frequency_mhz >= 1.8f && frequency_mhz <= 54.0f);
    }
    
    bool isCommercialFrequency(float frequency_mhz) {
        return (frequency_mhz >= 2.0f && frequency_mhz <= 30.0f);
    }
    
    bool isMilitaryFrequency(float frequency_mhz) {
        return (frequency_mhz >= 2.0f && frequency_mhz <= 30.0f);
    }
    
    std::string getRegulatoryBody(float frequency_mhz) {
        if (isAmateurRadioFrequency(frequency_mhz)) {
            return "FCC";
        } else if (isCommercialFrequency(frequency_mhz)) {
            return "FCC";
        } else if (isMilitaryFrequency(frequency_mhz)) {
            return "ITU";
        }
        return "Unknown";
    }
    
    std::string getLicenseType(float frequency_mhz) {
        if (isAmateurRadioFrequency(frequency_mhz)) {
            return "Amateur";
        } else if (isCommercialFrequency(frequency_mhz)) {
            return "Commercial";
        } else if (isMilitaryFrequency(frequency_mhz)) {
            return "Military";
        }
        return "Unknown";
    }
}
