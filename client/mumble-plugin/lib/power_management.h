#ifndef FGCOM_POWER_MANAGEMENT_H
#define FGCOM_POWER_MANAGEMENT_H

#include <vector>
#include <string>
#include <map>
#include <memory>
#include <chrono>
#include <mutex>
#include <functional>

// Power level management structure
struct PowerLevels {
    std::vector<int> available_powers = {50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000};
    int current_power;
    float power_efficiency;         // Antenna efficiency at current power
    bool power_limiting;            // Automatic power limiting for safety
    float max_safe_power;           // Maximum safe power for current antenna
    float regulatory_limit;         // Regulatory power limit for current band
    bool efficiency_optimization;   // Enable power efficiency optimization
    float battery_level;            // Current battery level (0.0-1.0)
    float power_consumption;        // Current power consumption in watts
    std::chrono::system_clock::time_point last_power_change;
};

// Power efficiency data for different antenna types
struct AntennaPowerEfficiency {
    std::string antenna_type;
    std::map<int, float> efficiency_at_power;  // Power level -> efficiency (0.0-1.0)
    float max_efficient_power;                 // Power level with best efficiency
    float efficiency_threshold;                // Minimum efficiency threshold
    bool has_power_limiting;                   // Whether this antenna has power limiting
    float thermal_limit;                       // Thermal power limit in watts
    float swr_limit;                          // SWR limit for power limiting
};

// Regulatory power limits by frequency band
struct RegulatoryPowerLimits {
    std::string band_name;
    float min_freq_mhz;
    float max_freq_mhz;
    float max_power_watts;
    std::string regulatory_body;  // FCC, ITU, etc.
    std::string license_type;     // Amateur, Commercial, Military, etc.
    bool requires_license;
    float power_density_limit;    // Power density limit in W/m²
};

// Power management configuration
struct PowerManagementConfig {
    bool enable_automatic_power_limiting = true;
    bool enable_efficiency_optimization = true;
    bool enable_regulatory_compliance = true;
    bool enable_thermal_protection = true;
    bool enable_swr_protection = true;
    bool enable_battery_management = true;
    float default_efficiency_threshold = 0.7f;
    float thermal_shutdown_threshold = 0.9f;
    float swr_shutdown_threshold = 3.0f;
    float battery_low_threshold = 0.2f;
    int power_change_delay_ms = 100;  // Delay between power changes
    bool log_power_changes = true;
    bool enable_power_analytics = true;
};

// Power management statistics
struct PowerManagementStats {
    int total_power_changes;
    float average_efficiency;
    float peak_power_used;
    float total_energy_consumed;
    std::chrono::system_clock::time_point last_reset;
    std::map<int, int> power_level_usage;  // Power level -> usage count
    float efficiency_vs_power_correlation;
    int thermal_shutdowns;
    int swr_shutdowns;
    int regulatory_violations;
};

// Main power management class
class FGCom_PowerManager {
private:
    static std::unique_ptr<FGCom_PowerManager> instance;
    static std::mutex instance_mutex;
    
    PowerLevels current_power_levels;
    PowerManagementConfig config;
    PowerManagementStats stats;
    std::map<std::string, AntennaPowerEfficiency> antenna_efficiency_data;
    std::map<std::string, RegulatoryPowerLimits> regulatory_limits;
    
    // Internal state
    std::mutex power_mutex;
    bool power_limiting_active;
    bool thermal_protection_active;
    bool swr_protection_active;
    float current_swr;
    float current_temperature;
    std::string current_antenna_type;
    std::string current_frequency_band;
    
    // Private constructor for singleton
    FGCom_PowerManager();
    
public:
    // Singleton access
    static FGCom_PowerManager& getInstance();
    static void destroyInstance();
    
    // Power level management
    bool setPowerLevel(int power_watts);
    int getCurrentPower() const;
    std::vector<int> getAvailablePowerLevels() const;
    bool isPowerLevelAvailable(int power_watts) const;
    
    // Power efficiency calculations
    float calculatePowerEfficiency(int power_watts, const std::string& antenna_type) const;
    float getCurrentPowerEfficiency() const;
    int getOptimalPowerLevel(const std::string& antenna_type) const;
    bool optimizePowerForEfficiency();
    
    // Automatic power limiting
    bool enablePowerLimiting(bool enable);
    bool isPowerLimitingActive() const;
    bool checkPowerLimits(int power_watts) const;
    bool applyPowerLimits(int requested_power, int& actual_power) const;
    
    // Regulatory compliance
    bool checkRegulatoryCompliance(int power_watts, const std::string& frequency_band) const;
    float getRegulatoryPowerLimit(const std::string& frequency_band) const;
    bool isRegulatoryCompliant(int power_watts, const std::string& frequency_band) const;
    
    // Thermal protection
    bool enableThermalProtection(bool enable);
    bool isThermalProtectionActive() const;
    void updateTemperature(float temperature_celsius);
    bool checkThermalLimits(int power_watts) const;
    
    // SWR protection
    bool enableSWRProtection(bool enable);
    bool isSWRProtectionActive() const;
    void updateSWR(float swr_ratio);
    bool checkSWRLimits(int power_watts) const;
    
    // Battery management
    void updateBatteryLevel(float battery_level);
    float getBatteryLevel() const;
    bool isBatteryLow() const;
    int getMaxPowerForBattery() const;
    
    // Antenna management
    void setCurrentAntenna(const std::string& antenna_type);
    std::string getCurrentAntenna() const;
    bool loadAntennaEfficiencyData(const std::string& antenna_type, const AntennaPowerEfficiency& data);
    AntennaPowerEfficiency getAntennaEfficiencyData(const std::string& antenna_type) const;
    
    // Frequency band management
    void setCurrentFrequencyBand(const std::string& frequency_band);
    std::string getCurrentFrequencyBand() const;
    bool loadRegulatoryLimits(const std::string& frequency_band, const RegulatoryPowerLimits& limits);
    RegulatoryPowerLimits getRegulatoryLimits(const std::string& frequency_band) const;
    
    // Configuration management
    void setConfig(const PowerManagementConfig& new_config);
    PowerManagementConfig getConfig() const;
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    
    // Statistics and monitoring
    PowerManagementStats getStats() const;
    void resetStats();
    void updateStats();
    bool isPowerAnalyticsEnabled() const;
    
    // Power change management
    bool canChangePower() const;
    void setPowerChangeDelay(int delay_ms);
    int getPowerChangeDelay() const;
    
    // Safety and protection
    bool isSafeToTransmit(int power_watts) const;
    bool checkAllSafetyLimits(int power_watts) const;
    void emergencyPowerDown();
    bool isEmergencyPowerDown() const;
    
    // Power optimization
    int calculateOptimalPowerForRange(double distance_km, const std::string& antenna_type) const;
    int calculateOptimalPowerForSignalQuality(float target_quality, double distance_km, const std::string& antenna_type) const;
    float calculatePowerConsumption(int power_watts, const std::string& antenna_type) const;
    
    // Integration with existing radio models
    float getEffectiveRadiatedPower(int tx_power_watts, const std::string& antenna_type, float azimuth_deg, float elevation_deg, float frequency_mhz) const;
    float getPowerEfficiencyAtFrequency(int power_watts, const std::string& antenna_type, float frequency_mhz) const;
    
    // Event callbacks
    void setPowerChangeCallback(std::function<void(int, int)> callback);
    void setEfficiencyChangeCallback(std::function<void(float)> callback);
    void setSafetyEventCallback(std::function<void(const std::string&)> callback);
    
private:
    // Internal helper methods
    void initializeDefaultAntennaData();
    void initializeDefaultRegulatoryLimits();
    void updatePowerEfficiency();
    void checkSafetyLimits();
    void logPowerChange(int old_power, int new_power);
    void logSafetyEvent(const std::string& event);
    
    // Callbacks
    std::function<void(int, int)> power_change_callback;
    std::function<void(float)> efficiency_change_callback;
    std::function<void(const std::string&)> safety_event_callback;
};

// Utility functions for power management
namespace PowerManagementUtils {
    // Convert power levels between different units
    float wattsToDBm(float watts);
    float dbmToWatts(float dbm);
    float wattsToDBW(float watts);
    float dbwToWatts(float dbw);
    
    // Calculate power density
    float calculatePowerDensity(float power_watts, float distance_meters);
    bool checkPowerDensityLimit(float power_watts, float distance_meters, float limit_w_per_m2);
    
    // Calculate effective radiated power
    float calculateERP(float tx_power_watts, float antenna_gain_db, float system_loss_db);
    float calculateEIRP(float tx_power_watts, float antenna_gain_db, float system_loss_db);
    
    // Power efficiency calculations
    float calculateAntennaEfficiency(float power_watts, float swr, float temperature_celsius);
    float calculateSystemEfficiency(float tx_power_watts, float antenna_efficiency, float feedline_loss_db, float connector_loss_db);
    
    // Regulatory compliance helpers
    bool isAmateurRadioFrequency(float frequency_mhz);
    bool isCommercialFrequency(float frequency_mhz);
    bool isMilitaryFrequency(float frequency_mhz);
    std::string getRegulatoryBody(float frequency_mhz);
    std::string getLicenseType(float frequency_mhz);
}

#endif // FGCOM_POWER_MANAGEMENT_H
