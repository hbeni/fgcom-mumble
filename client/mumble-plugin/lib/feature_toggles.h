#ifndef FGCOM_FEATURE_TOGGLES_H
#define FGCOM_FEATURE_TOGGLES_H

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cassert>

// =============================================================================
// FEATURE TOGGLE SYSTEM
// =============================================================================
// This system provides runtime control over all major features in FGCom-mumble
// allowing users to enable/disable functionality as needed for performance
// optimization, debugging, or specific use cases.

// Feature categories
enum class FeatureCategory {
    THREADING = 0,
    GPU_ACCELERATION = 1,
    SOLAR_DATA = 2,
    PROPAGATION = 3,
    ANTENNA_PATTERNS = 4,
    AUDIO_PROCESSING = 5,
    API_SERVER = 6,
    LIGHTNING_DATA = 7,
    WEATHER_DATA = 8,
    POWER_MANAGEMENT = 9,
    FREQUENCY_OFFSET = 10,
    BFO_SIMULATION = 11,
    FILTER_APPLICATION = 12,
    FUZZY_LOGIC = 13,
    VEHICLE_DYNAMICS = 14,
    DEBUGGING = 15,
    PERFORMANCE_MONITORING = 16
};

// Individual feature toggles
enum class FeatureToggle {
    // Threading features
    THREADING_SOLAR_DATA = 0,
    THREADING_PROPAGATION = 1,
    THREADING_API_SERVER = 2,
    THREADING_GPU_COMPUTE = 3,
    THREADING_LIGHTNING_DATA = 4,
    THREADING_WEATHER_DATA = 5,
    THREADING_ANTENNA_PATTERN = 6,
    THREADING_MONITORING = 7,
    
    // GPU acceleration features
    GPU_ANTENNA_PATTERNS = 8,
    GPU_PROPAGATION_CALCULATIONS = 9,
    GPU_AUDIO_PROCESSING = 10,
    GPU_FREQUENCY_OFFSET = 11,
    GPU_FILTER_APPLICATION = 12,
    GPU_BATCH_QSO_CALCULATION = 13,
    GPU_SOLAR_DATA_PROCESSING = 14,
    GPU_LIGHTNING_DATA_PROCESSING = 15,
    
    // Solar data features
    SOLAR_DATA_FETCHING = 16,
    SOLAR_DATA_CACHING = 17,
    SOLAR_DATA_HISTORICAL = 18,
    SOLAR_DATA_VALIDATION = 19,
    SOLAR_DATA_RETRY = 20,
    
    // Propagation features
    PROPAGATION_MUF_LUF = 21,
    PROPAGATION_PATH_LOSS = 22,
    PROPAGATION_SKIP_DISTANCE = 23,
    PROPAGATION_MULTI_HOP = 24,
    PROPAGATION_IONOSPHERIC_ABSORPTION = 25,
    PROPAGATION_GROUND_REFLECTION = 26,
    PROPAGATION_SOLAR_ZENITH = 27,
    PROPAGATION_REALISTIC_FADING = 28,
    
    // Antenna pattern features
    ANTENNA_PATTERN_LOADING = 29,
    ANTENNA_PATTERN_CACHING = 30,
    ANTENNA_PATTERN_INTERPOLATION = 31,
    ANTENNA_PATTERN_ALTITUDE_DEPENDENT = 32,
    ANTENNA_PATTERN_GROUND_EFFECTS = 33,
    ANTENNA_PATTERN_GPU_ACCELERATION = 34,
    
    // Audio processing features
    AUDIO_FREQUENCY_OFFSET = 35,
    AUDIO_DONALD_DUCK_EFFECT = 36,
    AUDIO_DOPPLER_SHIFT = 37,
    AUDIO_BFO_SIMULATION = 38,
    AUDIO_FILTER_APPLICATION = 39,
    AUDIO_ATMOSPHERIC_NOISE = 40,
    AUDIO_REALISTIC_FADING = 41,
    
    // API server features
    API_REST_ENDPOINTS = 42,
    API_WEBSOCKET_UPDATES = 43,
    API_VEHICLE_DYNAMICS = 44,
    API_ANTENNA_ROTATION = 45,
    API_POWER_MANAGEMENT = 46,
    API_PROPAGATION_DATA = 47,
    API_SOLAR_DATA = 48,
    API_BAND_STATUS = 49,
    API_ANTENNA_PATTERNS = 50,
    API_GPU_STATUS = 51,
    
    // Lightning data features
    LIGHTNING_DATA_FETCHING = 52,
    LIGHTNING_DATA_CACHING = 53,
    LIGHTNING_DATA_FILTERING = 54,
    LIGHTNING_DATA_ATMOSPHERIC_NOISE = 55,
    
    // Weather data features
    WEATHER_DATA_FETCHING = 56,
    WEATHER_DATA_CACHING = 57,
    WEATHER_DATA_VALIDATION = 58,
    WEATHER_DATA_ATMOSPHERIC_EFFECTS = 59,
    
    // Power management features
    POWER_EFFICIENCY_CALCULATION = 60,
    POWER_LIMITING = 61,
    POWER_OPTIMIZATION = 62,
    POWER_THERMAL_PROTECTION = 63,
    POWER_BATTERY_MANAGEMENT = 64,
    
    // Frequency offset features
    FREQUENCY_OFFSET_COMPLEX_EXPONENTIAL = 65,
    FREQUENCY_OFFSET_HILBERT_TRANSFORM = 66,
    FREQUENCY_OFFSET_SMOOTHING = 67,
    FREQUENCY_OFFSET_REAL_TIME = 68,
    FREQUENCY_OFFSET_SIMD = 69,
    FREQUENCY_OFFSET_MULTI_THREADING = 70,
    
    // BFO simulation features
    BFO_CW_DEMODULATION = 71,
    BFO_SSB_DEMODULATION = 72,
    BFO_FREQUENCY_MIXING = 73,
    BFO_PHASE_ACCUMULATION = 74,
    
    // Filter application features
    FILTER_SSB = 75,
    FILTER_AM = 76,
    FILTER_CW = 77,
    FILTER_AVIATION = 78,
    FILTER_MARITIME = 79,
    FILTER_NOTCH = 80,
    FILTER_DYNAMIC_SELECTION = 81,
    
    // Fuzzy logic features
    FUZZY_PROPAGATION_MODELING = 82,
    FUZZY_ANOMALY_DETECTION = 83,
    FUZZY_SPORADIC_E_SKIP = 84,
    FUZZY_SOLAR_FLARE_EFFECTS = 85,
    
    // Vehicle dynamics features
    VEHICLE_HEADING_TRACKING = 86,
    VEHICLE_SPEED_TRACKING = 87,
    VEHICLE_ATTITUDE_TRACKING = 88,
    VEHICLE_ALTITUDE_TRACKING = 89,
    VEHICLE_ANTENNA_ROTATION = 90,
    VEHICLE_DYNAMICS_CACHING = 91,
    
    // Debugging features
    DEBUG_THREAD_OPERATIONS = 92,
    DEBUG_CACHE_OPERATIONS = 93,
    DEBUG_GPU_OPERATIONS = 94,
    DEBUG_PROPAGATION_CALCULATIONS = 95,
    DEBUG_AUDIO_PROCESSING = 96,
    DEBUG_API_REQUESTS = 97,
    DEBUG_ERROR_LOGGING = 98,
    DEBUG_PERFORMANCE_LOGGING = 99,
    
    // Performance monitoring features
    PERFORMANCE_THREAD_STATS = 100,
    PERFORMANCE_CACHE_STATS = 101,
    PERFORMANCE_GPU_STATS = 102,
    PERFORMANCE_MEMORY_STATS = 103,
    PERFORMANCE_NETWORK_STATS = 104,
    PERFORMANCE_ALERTS = 105,
    PERFORMANCE_REPORTING = 106
};

// Feature toggle configuration
struct FeatureToggleConfig {
    bool enabled = true;
    std::string description;
    FeatureCategory category;
    std::string config_key;
    bool requires_restart = false;
    std::map<std::string, std::string> dependencies;
    std::map<std::string, std::string> conflicts;
    std::string performance_impact; // "low", "medium", "high"
    std::string memory_impact; // "low", "medium", "high"
    std::string cpu_impact; // "low", "medium", "high"
};

// Main feature toggle manager
class FGCom_FeatureToggleManager {
private:
    static std::unique_ptr<FGCom_FeatureToggleManager> instance;
    static std::mutex instance_mutex;
    
    std::map<FeatureToggle, FeatureToggleConfig> feature_configs;
    std::map<FeatureToggle, std::atomic<bool>> feature_states;
    std::mutex config_mutex;
    
    // Performance tracking
    std::map<FeatureToggle, std::atomic<uint64_t>> feature_usage_counts;
    std::map<FeatureToggle, std::atomic<double>> feature_performance_impact;
    
    // Private constructor for singleton
    FGCom_FeatureToggleManager();
    
public:
    // Singleton access
    static FGCom_FeatureToggleManager& getInstance();
    static void destroyInstance();
    
    // Feature control
    bool isFeatureEnabled(FeatureToggle feature) const;
    bool enableFeature(FeatureToggle feature);
    bool disableFeature(FeatureToggle feature);
    bool toggleFeature(FeatureToggle feature);
    
    // Configuration management
    void setFeatureConfig(FeatureToggle feature, const FeatureToggleConfig& config);
    FeatureToggleConfig getFeatureConfig(FeatureToggle feature) const;
    void initializeDefaultConfigs();
    
    // Bulk operations
    void enableAllFeatures();
    void disableAllFeatures();
    void enableCategory(FeatureCategory category);
    void disableCategory(FeatureCategory category);
    void enableFeaturesByImpact(const std::string& impact_level); // "low", "medium", "high"
    
    // Configuration persistence
    bool loadConfigFromFile(const std::string& config_file);
    bool saveConfigToFile(const std::string& config_file) const;
    bool loadConfigFromString(const std::string& config_string);
    std::string saveConfigToString() const;
    
    // Dependency management
    bool checkDependencies(FeatureToggle feature) const;
    bool checkConflicts(FeatureToggle feature) const;
    std::vector<FeatureToggle> getDependentFeatures(FeatureToggle feature) const;
    std::vector<FeatureToggle> getConflictingFeatures(FeatureToggle feature) const;
    
    // Performance monitoring
    void recordFeatureUsage(FeatureToggle feature, double performance_impact_ms = 0.0);
    uint64_t getFeatureUsageCount(FeatureToggle feature) const;
    double getFeaturePerformanceImpact(FeatureToggle feature) const;
    std::map<FeatureToggle, uint64_t> getAllFeatureUsageCounts() const;
    std::map<FeatureToggle, double> getAllFeaturePerformanceImpacts() const;
    
    // Information and reporting
    std::vector<FeatureToggle> getEnabledFeatures() const;
    std::vector<FeatureToggle> getDisabledFeatures() const;
    std::vector<FeatureToggle> getFeaturesByCategory(FeatureCategory category) const;
    std::vector<FeatureToggle> getFeaturesByImpact(const std::string& impact_level) const;
    
    // Validation and diagnostics
    bool validateConfiguration() const;
    std::vector<std::string> getConfigurationErrors() const;
    std::vector<std::string> getConfigurationWarnings() const;
    void generateFeatureReport() const;
    
    // Runtime control
    bool canToggleFeature(FeatureToggle feature) const;
    bool requiresRestart(FeatureToggle feature) const;
    std::vector<FeatureToggle> getFeaturesRequiringRestart() const;
    
    // Debugging and diagnostics
    void enableDebugMode(bool enable);
    bool isDebugModeEnabled() const;
    void logFeatureToggle(FeatureToggle feature, bool enabled, const std::string& reason = "");
    std::vector<std::string> getFeatureToggleHistory() const;
    
private:
    // Internal helper methods
    void initializeFeatureConfigs();
    bool validateFeatureToggle(FeatureToggle feature, bool enabled) const;
    void updateDependentFeatures(FeatureToggle feature, bool enabled);
    void logFeatureChange(FeatureToggle feature, bool enabled, const std::string& reason);
    
    // Internal state
    std::atomic<bool> debug_mode_enabled;
    std::vector<std::string> toggle_history;
    std::mutex history_mutex;
};

// Utility functions for feature toggles
namespace FeatureToggleUtils {
    // Feature toggle to string conversion
    std::string featureToggleToString(FeatureToggle feature);
    FeatureToggle stringToFeatureToggle(const std::string& str);
    
    // Category to string conversion
    std::string featureCategoryToString(FeatureCategory category);
    FeatureCategory stringToFeatureCategory(const std::string& str);
    
    // Impact level validation
    bool isValidImpactLevel(const std::string& impact_level);
    std::vector<std::string> getValidImpactLevels();
    
    // Feature dependency analysis
    std::vector<FeatureToggle> analyzeFeatureDependencies(FeatureToggle feature);
    std::vector<FeatureToggle> analyzeFeatureConflicts(FeatureToggle feature);
    
    // Performance impact estimation
    double estimateFeaturePerformanceImpact(FeatureToggle feature);
    std::string estimateFeatureResourceUsage(FeatureToggle feature);
    
    // Configuration validation
    bool validateFeatureConfig(const FeatureToggleConfig& config);
    std::vector<std::string> getFeatureConfigErrors(const FeatureToggleConfig& config);
}

// Macro for easy feature checking
#define FGCOM_FEATURE_ENABLED(feature) \
    FGCom_FeatureToggleManager::getInstance().isFeatureEnabled(feature)

#define FGCOM_FEATURE_DISABLED(feature) \
    (!FGCom_FeatureToggleManager::getInstance().isFeatureEnabled(feature))

#define FGCOM_FEATURE_USAGE(feature, performance_impact) \
    FGCom_FeatureToggleManager::getInstance().recordFeatureUsage(feature, performance_impact)

// Conditional compilation macros
#define FGCOM_IF_FEATURE_ENABLED(feature, code) \
    if (FGCOM_FEATURE_ENABLED(feature)) { \
        code \
    }

#define FGCOM_IF_FEATURE_DISABLED(feature, code) \
    if (FGCOM_FEATURE_DISABLED(feature)) { \
        code \
    }

#endif // FGCOM_FEATURE_TOGGLES_H
