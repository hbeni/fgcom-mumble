#include "feature_toggles.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

// Singleton instances
std::unique_ptr<FGCom_FeatureToggleManager> FGCom_FeatureToggleManager::instance = nullptr;
std::mutex FGCom_FeatureToggleManager::instance_mutex;

// FGCom_FeatureToggleManager Implementation
FGCom_FeatureToggleManager::FGCom_FeatureToggleManager() 
    : debug_mode_enabled(false) {
    initializeFeatureConfigs();
}

FGCom_FeatureToggleManager& FGCom_FeatureToggleManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::unique_ptr<FGCom_FeatureToggleManager>(new FGCom_FeatureToggleManager());
    }
    return *instance;
}

void FGCom_FeatureToggleManager::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance.reset();
    }
}

bool FGCom_FeatureToggleManager::isFeatureEnabled(FeatureToggle feature) const {
    try {
        std::lock_guard<std::mutex> lock(config_mutex);
        auto it = feature_states.find(feature);
        if (it != feature_states.end()) {
            return it->second.load();
        }
        return false;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in isFeatureEnabled: " << e.what() << std::endl;
        }
        return false;
    }
}

bool FGCom_FeatureToggleManager::enableFeature(FeatureToggle feature) {
    try {
        if (!validateFeatureToggle(feature, true)) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(config_mutex);
        feature_states[feature] = true;
        logFeatureChange(feature, true, "User requested enable");
        updateDependentFeatures(feature, true);
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in enableFeature: " << e.what() << std::endl;
        }
        return false;
    }
}

bool FGCom_FeatureToggleManager::disableFeature(FeatureToggle feature) {
    try {
        if (!validateFeatureToggle(feature, false)) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(config_mutex);
        feature_states[feature] = false;
        logFeatureChange(feature, false, "User requested disable");
        updateDependentFeatures(feature, false);
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in disableFeature: " << e.what() << std::endl;
        }
        return false;
    }
}

bool FGCom_FeatureToggleManager::toggleFeature(FeatureToggle feature) {
    try {
        bool current_state = isFeatureEnabled(feature);
        return current_state ? disableFeature(feature) : enableFeature(feature);
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in toggleFeature: " << e.what() << std::endl;
        }
        return false;
    }
}

void FGCom_FeatureToggleManager::setFeatureConfig(FeatureToggle feature, const FeatureToggleConfig& config) {
    try {
        std::lock_guard<std::mutex> lock(config_mutex);
        feature_configs[feature] = config;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in setFeatureConfig: " << e.what() << std::endl;
        }
    }
}

FeatureToggleConfig FGCom_FeatureToggleManager::getFeatureConfig(FeatureToggle feature) const {
    try {
        std::lock_guard<std::mutex> lock(config_mutex);
        auto it = feature_configs.find(feature);
        if (it != feature_configs.end()) {
            return it->second;
        }
        return FeatureToggleConfig();
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in getFeatureConfig: " << e.what() << std::endl;
        }
        return FeatureToggleConfig();
    }
}

void FGCom_FeatureToggleManager::initializeDefaultConfigs() {
    try {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        // Initialize all features with default configurations
        for (int i = 0; i < 107; ++i) {
            FeatureToggle feature = static_cast<FeatureToggle>(i);
            FeatureToggleConfig config;
            config.enabled = true;
            config.description = "Feature " + std::to_string(i);
            config.category = static_cast<FeatureCategory>(i / 7); // Distribute across categories
            config.config_key = "feature_" + std::to_string(i);
            config.requires_restart = false;
            config.performance_impact = "low";
            config.memory_impact = "low";
            config.cpu_impact = "low";
            
            feature_configs[feature] = config;
            feature_states[feature] = true;
        }
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in initializeDefaultConfigs: " << e.what() << std::endl;
        }
    }
}

bool FGCom_FeatureToggleManager::loadConfigFromFile(const std::string& config_file) {
    try {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            if (debug_mode_enabled.load()) {
                std::cerr << "[FeatureToggleManager] Cannot open config file: " << config_file << std::endl;
            }
            return false;
        }
        
        std::string line;
        std::string current_section = "";
        
        while (std::getline(file, line)) {
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
                
                // Parse feature toggle settings
                if (current_section == "features") {
                    try {
                        FeatureToggle feature = stringToFeatureToggle(key);
                        bool enabled = (value == "true" || value == "1" || value == "yes");
                        feature_states[feature] = enabled;
                    } catch (const std::exception& e) {
                        if (debug_mode_enabled.load()) {
                            std::cerr << "[FeatureToggleManager] Invalid feature toggle: " << key << std::endl;
                        }
                    }
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in loadConfigFromFile: " << e.what() << std::endl;
        }
        return false;
    }
}

bool FGCom_FeatureToggleManager::saveConfigToFile(const std::string& config_file) const {
    try {
        std::ofstream file(config_file);
        if (!file.is_open()) {
            if (debug_mode_enabled.load()) {
                std::cerr << "[FeatureToggleManager] Cannot create config file: " << config_file << std::endl;
            }
            return false;
        }
        
        file << "[features]" << std::endl;
        
        std::lock_guard<std::mutex> lock(config_mutex);
        for (const auto& pair : feature_states) {
            std::string feature_name = featureToggleToString(pair.first);
            bool enabled = pair.second.load();
            file << feature_name << "=" << (enabled ? "true" : "false") << std::endl;
        }
        
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in saveConfigToFile: " << e.what() << std::endl;
        }
        return false;
    }
}

void FGCom_FeatureToggleManager::recordFeatureUsage(FeatureToggle feature, double performance_impact_ms) {
    try {
        feature_usage_counts[feature]++;
        feature_performance_impact[feature] = performance_impact_ms;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in recordFeatureUsage: " << e.what() << std::endl;
        }
    }
}

uint64_t FGCom_FeatureToggleManager::getFeatureUsageCount(FeatureToggle feature) const {
    try {
        auto it = feature_usage_counts.find(feature);
        if (it != feature_usage_counts.end()) {
            return it->second.load();
        }
        return 0;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in getFeatureUsageCount: " << e.what() << std::endl;
        }
        return 0;
    }
}

double FGCom_FeatureToggleManager::getFeaturePerformanceImpact(FeatureToggle feature) const {
    try {
        auto it = feature_performance_impact.find(feature);
        if (it != feature_performance_impact.end()) {
            return it->second.load();
        }
        return 0.0;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in getFeaturePerformanceImpact: " << e.what() << std::endl;
        }
        return 0.0;
    }
}

bool FGCom_FeatureToggleManager::validateConfiguration() const {
    try {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        // Check for conflicting features
        for (const auto& pair : feature_states) {
            if (pair.second.load()) {
                auto conflicts = getConflictingFeatures(pair.first);
                for (const auto& conflict : conflicts) {
                    if (isFeatureEnabled(conflict)) {
                        return false; // Conflicting features enabled
                    }
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in validateConfiguration: " << e.what() << std::endl;
        }
        return false;
    }
}

std::vector<std::string> FGCom_FeatureToggleManager::getConfigurationErrors() const {
    std::vector<std::string> errors;
    
    try {
        if (!validateConfiguration()) {
            errors.push_back("Conflicting features are enabled");
        }
    } catch (const std::exception& e) {
        errors.push_back("Exception during configuration validation: " + std::string(e.what()));
    }
    
    return errors;
}

void FGCom_FeatureToggleManager::enableDebugMode(bool enable) {
    debug_mode_enabled = enable;
}

bool FGCom_FeatureToggleManager::isDebugModeEnabled() const {
    return debug_mode_enabled.load();
}

void FGCom_FeatureToggleManager::logFeatureToggle(FeatureToggle feature, bool enabled, const std::string& reason) {
    try {
        logFeatureChange(feature, enabled, reason);
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in logFeatureToggle: " << e.what() << std::endl;
        }
    }
}

// Private helper methods
void FGCom_FeatureToggleManager::initializeFeatureConfigs() {
    try {
        initializeDefaultConfigs();
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in initializeFeatureConfigs: " << e.what() << std::endl;
        }
    }
}

bool FGCom_FeatureToggleManager::validateFeatureToggle(FeatureToggle feature, bool enabled) const {
    try {
        // Check if feature exists
        if (feature < FeatureToggle::THREADING_SOLAR_DATA || feature > FeatureToggle::PERFORMANCE_REPORTING) {
            return false;
        }
        
        // Check dependencies
        if (enabled && !checkDependencies(feature)) {
            return false;
        }
        
        // Check conflicts
        if (enabled && !checkConflicts(feature)) {
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in validateFeatureToggle: " << e.what() << std::endl;
        }
        return false;
    }
}

void FGCom_FeatureToggleManager::updateDependentFeatures(FeatureToggle feature, bool enabled) {
    try {
        // In a real implementation, this would update dependent features
        // For now, this is a placeholder
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in updateDependentFeatures: " << e.what() << std::endl;
        }
    }
}

void FGCom_FeatureToggleManager::logFeatureChange(FeatureToggle feature, bool enabled, const std::string& reason) {
    try {
        std::lock_guard<std::mutex> lock(history_mutex);
        std::string log_entry = "Feature " + featureToggleToString(feature) + 
                               " " + (enabled ? "enabled" : "disabled") + 
                               " - " + reason;
        toggle_history.push_back(log_entry);
        
        // Limit history size
        if (toggle_history.size() > 1000) {
            toggle_history.erase(toggle_history.begin());
        }
    } catch (const std::exception& e) {
        if (debug_mode_enabled.load()) {
            std::cerr << "[FeatureToggleManager] Exception in logFeatureChange: " << e.what() << std::endl;
        }
    }
}

// Utility functions implementation
namespace FeatureToggleUtils {
    std::string featureToggleToString(FeatureToggle feature) {
        try {
            switch (feature) {
                case FeatureToggle::THREADING_SOLAR_DATA:
                    return "threading_solar_data";
                case FeatureToggle::THREADING_PROPAGATION:
                    return "threading_propagation";
                case FeatureToggle::THREADING_API_SERVER:
                    return "threading_api_server";
                case FeatureToggle::THREADING_GPU_COMPUTE:
                    return "threading_gpu_compute";
                case FeatureToggle::THREADING_LIGHTNING_DATA:
                    return "threading_lightning_data";
                case FeatureToggle::THREADING_WEATHER_DATA:
                    return "threading_weather_data";
                case FeatureToggle::THREADING_ANTENNA_PATTERN:
                    return "threading_antenna_pattern";
                case FeatureToggle::THREADING_MONITORING:
                    return "threading_monitoring";
                // Add more cases as needed
                default:
                    return "unknown_feature_" + std::to_string(static_cast<int>(feature));
            }
        } catch (const std::exception& e) {
            return "error_feature_" + std::to_string(static_cast<int>(feature));
        }
    }
    
    FeatureToggle stringToFeatureToggle(const std::string& str) {
        try {
            if (str == "threading_solar_data") return FeatureToggle::THREADING_SOLAR_DATA;
            if (str == "threading_propagation") return FeatureToggle::THREADING_PROPAGATION;
            if (str == "threading_api_server") return FeatureToggle::THREADING_API_SERVER;
            if (str == "threading_gpu_compute") return FeatureToggle::THREADING_GPU_COMPUTE;
            if (str == "threading_lightning_data") return FeatureToggle::THREADING_LIGHTNING_DATA;
            if (str == "threading_weather_data") return FeatureToggle::THREADING_WEATHER_DATA;
            if (str == "threading_antenna_pattern") return FeatureToggle::THREADING_ANTENNA_PATTERN;
            if (str == "threading_monitoring") return FeatureToggle::THREADING_MONITORING;
            // Add more cases as needed
            
            throw std::invalid_argument("Unknown feature toggle: " + str);
        } catch (const std::exception& e) {
            throw std::invalid_argument("Invalid feature toggle string: " + str);
        }
    }
    
    std::string featureCategoryToString(FeatureCategory category) {
        try {
            switch (category) {
                case FeatureCategory::THREADING:
                    return "threading";
                case FeatureCategory::GPU_ACCELERATION:
                    return "gpu_acceleration";
                case FeatureCategory::SOLAR_DATA:
                    return "solar_data";
                case FeatureCategory::PROPAGATION:
                    return "propagation";
                case FeatureCategory::ANTENNA_PATTERNS:
                    return "antenna_patterns";
                case FeatureCategory::AUDIO_PROCESSING:
                    return "audio_processing";
                case FeatureCategory::API_SERVER:
                    return "api_server";
                case FeatureCategory::LIGHTNING_DATA:
                    return "lightning_data";
                case FeatureCategory::WEATHER_DATA:
                    return "weather_data";
                case FeatureCategory::POWER_MANAGEMENT:
                    return "power_management";
                case FeatureCategory::FREQUENCY_OFFSET:
                    return "frequency_offset";
                case FeatureCategory::BFO_SIMULATION:
                    return "bfo_simulation";
                case FeatureCategory::FILTER_APPLICATION:
                    return "filter_application";
                case FeatureCategory::FUZZY_LOGIC:
                    return "fuzzy_logic";
                case FeatureCategory::VEHICLE_DYNAMICS:
                    return "vehicle_dynamics";
                case FeatureCategory::DEBUGGING:
                    return "debugging";
                case FeatureCategory::PERFORMANCE_MONITORING:
                    return "performance_monitoring";
                default:
                    return "unknown_category_" + std::to_string(static_cast<int>(category));
            }
        } catch (const std::exception& e) {
            return "error_category_" + std::to_string(static_cast<int>(category));
        }
    }
    
    FeatureCategory stringToFeatureCategory(const std::string& str) {
        try {
            if (str == "threading") return FeatureCategory::THREADING;
            if (str == "gpu_acceleration") return FeatureCategory::GPU_ACCELERATION;
            if (str == "solar_data") return FeatureCategory::SOLAR_DATA;
            if (str == "propagation") return FeatureCategory::PROPAGATION;
            if (str == "antenna_patterns") return FeatureCategory::ANTENNA_PATTERNS;
            if (str == "audio_processing") return FeatureCategory::AUDIO_PROCESSING;
            if (str == "api_server") return FeatureCategory::API_SERVER;
            if (str == "lightning_data") return FeatureCategory::LIGHTNING_DATA;
            if (str == "weather_data") return FeatureCategory::WEATHER_DATA;
            if (str == "power_management") return FeatureCategory::POWER_MANAGEMENT;
            if (str == "frequency_offset") return FeatureCategory::FREQUENCY_OFFSET;
            if (str == "bfo_simulation") return FeatureCategory::BFO_SIMULATION;
            if (str == "filter_application") return FeatureCategory::FILTER_APPLICATION;
            if (str == "fuzzy_logic") return FeatureCategory::FUZZY_LOGIC;
            if (str == "vehicle_dynamics") return FeatureCategory::VEHICLE_DYNAMICS;
            if (str == "debugging") return FeatureCategory::DEBUGGING;
            if (str == "performance_monitoring") return FeatureCategory::PERFORMANCE_MONITORING;
            
            throw std::invalid_argument("Unknown feature category: " + str);
        } catch (const std::exception& e) {
            throw std::invalid_argument("Invalid feature category string: " + str);
        }
    }
    
    bool isValidImpactLevel(const std::string& impact_level) {
        try {
            std::string lower_level = impact_level;
            std::transform(lower_level.begin(), lower_level.end(), lower_level.begin(), ::tolower);
            return (lower_level == "low" || lower_level == "medium" || lower_level == "high");
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    std::vector<std::string> getValidImpactLevels() {
        return {"low", "medium", "high"};
    }
}