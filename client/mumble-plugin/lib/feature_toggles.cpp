#include "feature_toggles.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <iomanip>

// Singleton instances
std::unique_ptr<FGCom_FeatureToggleManager> FGCom_FeatureToggleManager::instance = nullptr;
std::mutex FGCom_FeatureToggleManager::instance_mutex;

// FGCom_FeatureToggleManager Implementation
FGCom_FeatureToggleManager::FGCom_FeatureToggleManager() 
    : debug_mode_enabled(false)
{
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
    instance.reset();
}

bool FGCom_FeatureToggleManager::isFeatureEnabled(FeatureToggle feature) const {
    auto it = feature_states.find(feature);
    if (it == feature_states.end()) {
        return false;
    }
    return it->second.load();
}

bool FGCom_FeatureToggleManager::enableFeature(FeatureToggle feature) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    if (!validateFeatureToggle(feature, true)) {
        return false;
    }
    
    feature_states[feature] = true;
    updateDependentFeatures(feature, true);
    logFeatureChange(feature, true, "Manually enabled");
    
    return true;
}

bool FGCom_FeatureToggleManager::disableFeature(FeatureToggle feature) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    if (!validateFeatureToggle(feature, false)) {
        return false;
    }
    
    feature_states[feature] = false;
    updateDependentFeatures(feature, false);
    logFeatureChange(feature, false, "Manually disabled");
    
    return true;
}

bool FGCom_FeatureToggleManager::toggleFeature(FeatureToggle feature) {
    if (isFeatureEnabled(feature)) {
        return disableFeature(feature);
    } else {
        return enableFeature(feature);
    }
}

void FGCom_FeatureToggleManager::setFeatureConfig(FeatureToggle feature, const FeatureToggleConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex);
    feature_configs[feature] = config;
}

FeatureToggleConfig FGCom_FeatureToggleManager::getFeatureConfig(FeatureToggle feature) const {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    auto it = feature_configs.find(feature);
    if (it == feature_configs.end()) {
        return FeatureToggleConfig();
    }
    
    return it->second;
}

void FGCom_FeatureToggleManager::initializeDefaultConfigs() {
    initializeFeatureConfigs();
}

void FGCom_FeatureToggleManager::enableAllFeatures() {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    for (auto& pair : feature_states) {
        if (validateFeatureToggle(pair.first, true)) {
            pair.second = true;
            logFeatureChange(pair.first, true, "Bulk enabled");
        }
    }
}

void FGCom_FeatureToggleManager::disableAllFeatures() {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    for (auto& pair : feature_states) {
        if (validateFeatureToggle(pair.first, false)) {
            pair.second = false;
            logFeatureChange(pair.first, false, "Bulk disabled");
        }
    }
}

void FGCom_FeatureToggleManager::enableCategory(FeatureCategory category) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    for (auto& pair : feature_configs) {
        if (pair.second.category == category) {
            if (validateFeatureToggle(pair.first, true)) {
                feature_states[pair.first] = true;
                logFeatureChange(pair.first, true, "Category enabled");
            }
        }
    }
}

void FGCom_FeatureToggleManager::disableCategory(FeatureCategory category) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    for (auto& pair : feature_configs) {
        if (pair.second.category == category) {
            if (validateFeatureToggle(pair.first, false)) {
                feature_states[pair.first] = false;
                logFeatureChange(pair.first, false, "Category disabled");
            }
        }
    }
}

void FGCom_FeatureToggleManager::enableFeaturesByImpact(const std::string& impact_level) {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    for (auto& pair : feature_configs) {
        if (pair.second.performance_impact == impact_level ||
            pair.second.memory_impact == impact_level ||
            pair.second.cpu_impact == impact_level) {
            if (validateFeatureToggle(pair.first, true)) {
                feature_states[pair.first] = true;
                logFeatureChange(pair.first, true, "Impact-based enabled");
            }
        }
    }
}

bool FGCom_FeatureToggleManager::loadConfigFromFile(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
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
            
            if (current_section == "feature_toggles") {
                // Parse feature toggle configuration
                FeatureToggle feature = FeatureToggleUtils::stringToFeatureToggle(key);
                if (feature != static_cast<FeatureToggle>(-1)) {
                    bool enabled = (value == "true" || value == "1" || value == "yes");
                    feature_states[feature] = enabled;
                }
            }
        }
    }
    
    return true;
}

bool FGCom_FeatureToggleManager::saveConfigToFile(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "[feature_toggles]" << std::endl;
    
    for (const auto& pair : feature_states) {
        std::string feature_name = FeatureToggleUtils::featureToggleToString(pair.first);
        file << feature_name << "=" << (pair.second.load() ? "true" : "false") << std::endl;
    }
    
    return true;
}

bool FGCom_FeatureToggleManager::loadConfigFromString(const std::string& config_string) {
    std::istringstream stream(config_string);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        size_t equal_pos = line.find('=');
        if (equal_pos != std::string::npos) {
            std::string key = line.substr(0, equal_pos);
            std::string value = line.substr(equal_pos + 1);
            
            FeatureToggle feature = FeatureToggleUtils::stringToFeatureToggle(key);
            if (feature != static_cast<FeatureToggle>(-1)) {
                bool enabled = (value == "true" || value == "1" || value == "yes");
                feature_states[feature] = enabled;
            }
        }
    }
    
    return true;
}

std::string FGCom_FeatureToggleManager::saveConfigToString() const {
    std::ostringstream stream;
    
    for (const auto& pair : feature_states) {
        std::string feature_name = FeatureToggleUtils::featureToggleToString(pair.first);
        stream << feature_name << "=" << (pair.second.load() ? "true" : "false") << std::endl;
    }
    
    return stream.str();
}

bool FGCom_FeatureToggleManager::checkDependencies(FeatureToggle feature) const {
    auto it = feature_configs.find(feature);
    if (it == feature_configs.end()) {
        return true;
    }
    
    for (const auto& dep : it->second.dependencies) {
        FeatureToggle dep_feature = FeatureToggleUtils::stringToFeatureToggle(dep.first);
        if (dep_feature != static_cast<FeatureToggle>(-1)) {
            if (!isFeatureEnabled(dep_feature)) {
                return false;
            }
        }
    }
    
    return true;
}

bool FGCom_FeatureToggleManager::checkConflicts(FeatureToggle feature) const {
    auto it = feature_configs.find(feature);
    if (it == feature_configs.end()) {
        return true;
    }
    
    for (const auto& conflict : it->second.conflicts) {
        FeatureToggle conflict_feature = FeatureToggleUtils::stringToFeatureToggle(conflict.first);
        if (conflict_feature != static_cast<FeatureToggle>(-1)) {
            if (isFeatureEnabled(conflict_feature)) {
                return false;
            }
        }
    }
    
    return true;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getDependentFeatures(FeatureToggle feature) const {
    std::vector<FeatureToggle> dependent_features;
    
    for (const auto& pair : feature_configs) {
        for (const auto& dep : pair.second.dependencies) {
            FeatureToggle dep_feature = FeatureToggleUtils::stringToFeatureToggle(dep.first);
            if (dep_feature == feature) {
                dependent_features.push_back(pair.first);
            }
        }
    }
    
    return dependent_features;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getConflictingFeatures(FeatureToggle feature) const {
    std::vector<FeatureToggle> conflicting_features;
    
    auto it = feature_configs.find(feature);
    if (it != feature_configs.end()) {
        for (const auto& conflict : it->second.conflicts) {
            FeatureToggle conflict_feature = FeatureToggleUtils::stringToFeatureToggle(conflict.first);
            if (conflict_feature != static_cast<FeatureToggle>(-1)) {
                conflicting_features.push_back(conflict_feature);
            }
        }
    }
    
    return conflicting_features;
}

void FGCom_FeatureToggleManager::recordFeatureUsage(FeatureToggle feature, double performance_impact_ms) {
    feature_usage_counts[feature]++;
    if (performance_impact_ms > 0.0) {
        double current_impact = feature_performance_impact[feature].load();
        double new_impact = (current_impact + performance_impact_ms) / 2.0; // Simple average
        feature_performance_impact[feature] = new_impact;
    }
}

uint64_t FGCom_FeatureToggleManager::getFeatureUsageCount(FeatureToggle feature) const {
    auto it = feature_usage_counts.find(feature);
    if (it == feature_usage_counts.end()) {
        return 0;
    }
    return it->second.load();
}

double FGCom_FeatureToggleManager::getFeaturePerformanceImpact(FeatureToggle feature) const {
    auto it = feature_performance_impact.find(feature);
    if (it == feature_performance_impact.end()) {
        return 0.0;
    }
    return it->second.load();
}

std::map<FeatureToggle, uint64_t> FGCom_FeatureToggleManager::getAllFeatureUsageCounts() const {
    std::map<FeatureToggle, uint64_t> counts;
    for (const auto& pair : feature_usage_counts) {
        counts[pair.first] = pair.second.load();
    }
    return counts;
}

std::map<FeatureToggle, double> FGCom_FeatureToggleManager::getAllFeaturePerformanceImpacts() const {
    std::map<FeatureToggle, double> impacts;
    for (const auto& pair : feature_performance_impact) {
        impacts[pair.first] = pair.second.load();
    }
    return impacts;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getEnabledFeatures() const {
    std::vector<FeatureToggle> enabled_features;
    
    for (const auto& pair : feature_states) {
        if (pair.second.load()) {
            enabled_features.push_back(pair.first);
        }
    }
    
    return enabled_features;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getDisabledFeatures() const {
    std::vector<FeatureToggle> disabled_features;
    
    for (const auto& pair : feature_states) {
        if (!pair.second.load()) {
            disabled_features.push_back(pair.first);
        }
    }
    
    return disabled_features;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getFeaturesByCategory(FeatureCategory category) const {
    std::vector<FeatureToggle> category_features;
    
    for (const auto& pair : feature_configs) {
        if (pair.second.category == category) {
            category_features.push_back(pair.first);
        }
    }
    
    return category_features;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getFeaturesByImpact(const std::string& impact_level) const {
    std::vector<FeatureToggle> impact_features;
    
    for (const auto& pair : feature_configs) {
        if (pair.second.performance_impact == impact_level ||
            pair.second.memory_impact == impact_level ||
            pair.second.cpu_impact == impact_level) {
            impact_features.push_back(pair.first);
        }
    }
    
    return impact_features;
}

bool FGCom_FeatureToggleManager::validateConfiguration() const {
    for (const auto& pair : feature_states) {
        if (!validateFeatureToggle(pair.first, pair.second.load())) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> FGCom_FeatureToggleManager::getConfigurationErrors() const {
    std::vector<std::string> errors;
    
    for (const auto& pair : feature_states) {
        if (!validateFeatureToggle(pair.first, pair.second.load())) {
            errors.push_back("Feature " + FeatureToggleUtils::featureToggleToString(pair.first) + 
                           " has invalid configuration");
        }
    }
    
    return errors;
}

std::vector<std::string> FGCom_FeatureToggleManager::getConfigurationWarnings() const {
    std::vector<std::string> warnings;
    
    // Check for potential performance issues
    for (const auto& pair : feature_states) {
        if (pair.second.load()) {
            auto config_it = feature_configs.find(pair.first);
            if (config_it != feature_configs.end()) {
                if (config_it->second.performance_impact == "high" ||
                    config_it->second.memory_impact == "high" ||
                    config_it->second.cpu_impact == "high") {
                    warnings.push_back("High impact feature " + 
                                     FeatureToggleUtils::featureToggleToString(pair.first) + 
                                     " is enabled");
                }
            }
        }
    }
    
    return warnings;
}

void FGCom_FeatureToggleManager::generateFeatureReport() const {
    std::cout << "\n=== FGCom-mumble Feature Toggle Report ===" << std::endl;
    
    // Summary statistics
    int total_features = feature_states.size();
    int enabled_features = 0;
    int disabled_features = 0;
    
    for (const auto& pair : feature_states) {
        if (pair.second.load()) {
            enabled_features++;
        } else {
            disabled_features++;
        }
    }
    
    std::cout << "\nSummary:" << std::endl;
    std::cout << "  Total Features: " << total_features << std::endl;
    std::cout << "  Enabled Features: " << enabled_features << std::endl;
    std::cout << "  Disabled Features: " << disabled_features << std::endl;
    std::cout << "  Enable Rate: " << std::fixed << std::setprecision(1) 
              << (100.0 * enabled_features / total_features) << "%" << std::endl;
    
    // Category breakdown
    std::cout << "\nFeatures by Category:" << std::endl;
    for (int cat = 0; cat < static_cast<int>(FeatureCategory::PERFORMANCE_MONITORING) + 1; cat++) {
        FeatureCategory category = static_cast<FeatureCategory>(cat);
        std::vector<FeatureToggle> category_features = getFeaturesByCategory(category);
        
        int enabled_in_category = 0;
        for (FeatureToggle feature : category_features) {
            if (isFeatureEnabled(feature)) {
                enabled_in_category++;
            }
        }
        
        std::cout << "  " << FeatureToggleUtils::featureCategoryToString(category) 
                  << ": " << enabled_in_category << "/" << category_features.size() << " enabled" << std::endl;
    }
    
    // Performance impact analysis
    std::cout << "\nPerformance Impact Analysis:" << std::endl;
    for (const std::string& impact : {"low", "medium", "high"}) {
        std::vector<FeatureToggle> impact_features = getFeaturesByImpact(impact);
        int enabled_impact_features = 0;
        
        for (FeatureToggle feature : impact_features) {
            if (isFeatureEnabled(feature)) {
                enabled_impact_features++;
            }
        }
        
        std::cout << "  " << impact << " impact: " << enabled_impact_features 
                  << "/" << impact_features.size() << " enabled" << std::endl;
    }
    
    // Top used features
    std::cout << "\nTop 10 Most Used Features:" << std::endl;
    std::vector<std::pair<FeatureToggle, uint64_t>> usage_counts;
    for (const auto& pair : feature_usage_counts) {
        usage_counts.push_back({pair.first, pair.second.load()});
    }
    
    std::sort(usage_counts.begin(), usage_counts.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(usage_counts.size(), size_t(10)); i++) {
        std::cout << "  " << (i + 1) << ". " 
                  << FeatureToggleUtils::featureToggleToString(usage_counts[i].first)
                  << ": " << usage_counts[i].second << " uses" << std::endl;
    }
    
    // Configuration errors and warnings
    std::vector<std::string> errors = getConfigurationErrors();
    std::vector<std::string> warnings = getConfigurationWarnings();
    
    if (!errors.empty()) {
        std::cout << "\nConfiguration Errors:" << std::endl;
        for (const auto& error : errors) {
            std::cout << "  ERROR: " << error << std::endl;
        }
    }
    
    if (!warnings.empty()) {
        std::cout << "\nConfiguration Warnings:" << std::endl;
        for (const auto& warning : warnings) {
            std::cout << "  WARNING: " << warning << std::endl;
        }
    }
    
    std::cout << "\n=== End Feature Toggle Report ===" << std::endl;
}

bool FGCom_FeatureToggleManager::canToggleFeature(FeatureToggle feature) const {
    return !requiresRestart(feature);
}

bool FGCom_FeatureToggleManager::requiresRestart(FeatureToggle feature) const {
    auto it = feature_configs.find(feature);
    if (it == feature_configs.end()) {
        return false;
    }
    return it->second.requires_restart;
}

std::vector<FeatureToggle> FGCom_FeatureToggleManager::getFeaturesRequiringRestart() const {
    std::vector<FeatureToggle> restart_features;
    
    for (const auto& pair : feature_configs) {
        if (pair.second.requires_restart) {
            restart_features.push_back(pair.first);
        }
    }
    
    return restart_features;
}

void FGCom_FeatureToggleManager::enableDebugMode(bool enable) {
    debug_mode_enabled = enable;
}

bool FGCom_FeatureToggleManager::isDebugModeEnabled() const {
    return debug_mode_enabled.load();
}

void FGCom_FeatureToggleManager::logFeatureToggle(FeatureToggle feature, bool enabled, const std::string& reason) {
    logFeatureChange(feature, enabled, reason);
}

std::vector<std::string> FGCom_FeatureToggleManager::getFeatureToggleHistory() const {
    std::lock_guard<std::mutex> lock(history_mutex);
    return toggle_history;
}

// Private helper methods
void FGCom_FeatureToggleManager::initializeFeatureConfigs() {
    // Initialize all feature configurations with defaults
    // This is a simplified version - in a real implementation, this would be much more comprehensive
    
    // Threading features
    feature_configs[FeatureToggle::THREADING_SOLAR_DATA] = {
        true, "Solar data background thread", FeatureCategory::THREADING, 
        "threading.solar_data", false, {}, {}, "medium", "low", "low"
    };
    
    feature_configs[FeatureToggle::THREADING_PROPAGATION] = {
        true, "Propagation calculation thread", FeatureCategory::THREADING,
        "threading.propagation", false, {}, {}, "high", "medium", "high"
    };
    
    feature_configs[FeatureToggle::THREADING_API_SERVER] = {
        true, "API server thread", FeatureCategory::THREADING,
        "threading.api_server", false, {}, {}, "low", "low", "medium"
    };
    
    feature_configs[FeatureToggle::THREADING_GPU_COMPUTE] = {
        true, "GPU compute thread", FeatureCategory::THREADING,
        "threading.gpu_compute", false, {}, {}, "high", "high", "low"
    };
    
    // GPU acceleration features
    feature_configs[FeatureToggle::GPU_ANTENNA_PATTERNS] = {
        true, "GPU-accelerated antenna pattern calculations", FeatureCategory::GPU_ACCELERATION,
        "gpu.antenna_patterns", false, {{"THREADING_GPU_COMPUTE", "true"}}, {}, "high", "high", "low"
    };
    
    feature_configs[FeatureToggle::GPU_PROPAGATION_CALCULATIONS] = {
        true, "GPU-accelerated propagation calculations", FeatureCategory::GPU_ACCELERATION,
        "gpu.propagation", false, {{"THREADING_GPU_COMPUTE", "true"}}, {}, "high", "high", "low"
    };
    
    // Solar data features
    feature_configs[FeatureToggle::SOLAR_DATA_FETCHING] = {
        true, "Solar data fetching from APIs", FeatureCategory::SOLAR_DATA,
        "solar_data.fetching", false, {{"THREADING_SOLAR_DATA", "true"}}, {}, "low", "low", "low"
    };
    
    feature_configs[FeatureToggle::SOLAR_DATA_CACHING] = {
        true, "Solar data caching", FeatureCategory::SOLAR_DATA,
        "solar_data.caching", false, {}, {}, "low", "medium", "low"
    };
    
    // Initialize feature states
    for (const auto& pair : feature_configs) {
        feature_states[pair.first] = pair.second.enabled;
        feature_usage_counts[pair.first] = 0;
        feature_performance_impact[pair.first] = 0.0;
    }
}

bool FGCom_FeatureToggleManager::validateFeatureToggle(FeatureToggle feature, bool enabled) const {
    if (enabled) {
        // Check dependencies
        if (!checkDependencies(feature)) {
            return false;
        }
        
        // Check conflicts
        if (!checkConflicts(feature)) {
            return false;
        }
    }
    
    return true;
}

void FGCom_FeatureToggleManager::updateDependentFeatures(FeatureToggle feature, bool enabled) {
    std::vector<FeatureToggle> dependent_features = getDependentFeatures(feature);
    
    for (FeatureToggle dep_feature : dependent_features) {
        if (enabled) {
            // Enable dependent feature if possible
            if (validateFeatureToggle(dep_feature, true)) {
                feature_states[dep_feature] = true;
                logFeatureChange(dep_feature, true, "Dependency enabled");
            }
        } else {
            // Disable dependent feature
            feature_states[dep_feature] = false;
            logFeatureChange(dep_feature, false, "Dependency disabled");
        }
    }
}

void FGCom_FeatureToggleManager::logFeatureChange(FeatureToggle feature, bool enabled, const std::string& reason) {
    if (debug_mode_enabled.load()) {
        std::lock_guard<std::mutex> lock(history_mutex);
        
        std::ostringstream log_entry;
        log_entry << "[" << std::chrono::system_clock::now().time_since_epoch().count() << "] "
                  << FeatureToggleUtils::featureToggleToString(feature) << " "
                  << (enabled ? "ENABLED" : "DISABLED") << " - " << reason;
        
        toggle_history.push_back(log_entry.str());
        
        // Keep only last 1000 entries
        if (toggle_history.size() > 1000) {
            toggle_history.erase(toggle_history.begin());
        }
        
        std::cout << "[FeatureToggle] " << log_entry.str() << std::endl;
    }
}

// FeatureToggleUtils Implementation
namespace FeatureToggleUtils {
    std::string featureToggleToString(FeatureToggle feature) {
        switch (feature) {
            case FeatureToggle::THREADING_SOLAR_DATA: return "THREADING_SOLAR_DATA";
            case FeatureToggle::THREADING_PROPAGATION: return "THREADING_PROPAGATION";
            case FeatureToggle::THREADING_API_SERVER: return "THREADING_API_SERVER";
            case FeatureToggle::THREADING_GPU_COMPUTE: return "THREADING_GPU_COMPUTE";
            case FeatureToggle::THREADING_LIGHTNING_DATA: return "THREADING_LIGHTNING_DATA";
            case FeatureToggle::THREADING_WEATHER_DATA: return "THREADING_WEATHER_DATA";
            case FeatureToggle::THREADING_ANTENNA_PATTERN: return "THREADING_ANTENNA_PATTERN";
            case FeatureToggle::THREADING_MONITORING: return "THREADING_MONITORING";
            case FeatureToggle::GPU_ANTENNA_PATTERNS: return "GPU_ANTENNA_PATTERNS";
            case FeatureToggle::GPU_PROPAGATION_CALCULATIONS: return "GPU_PROPAGATION_CALCULATIONS";
            case FeatureToggle::GPU_AUDIO_PROCESSING: return "GPU_AUDIO_PROCESSING";
            case FeatureToggle::GPU_FREQUENCY_OFFSET: return "GPU_FREQUENCY_OFFSET";
            case FeatureToggle::GPU_FILTER_APPLICATION: return "GPU_FILTER_APPLICATION";
            case FeatureToggle::GPU_BATCH_QSO_CALCULATION: return "GPU_BATCH_QSO_CALCULATION";
            case FeatureToggle::GPU_SOLAR_DATA_PROCESSING: return "GPU_SOLAR_DATA_PROCESSING";
            case FeatureToggle::GPU_LIGHTNING_DATA_PROCESSING: return "GPU_LIGHTNING_DATA_PROCESSING";
            case FeatureToggle::SOLAR_DATA_FETCHING: return "SOLAR_DATA_FETCHING";
            case FeatureToggle::SOLAR_DATA_CACHING: return "SOLAR_DATA_CACHING";
            case FeatureToggle::SOLAR_DATA_HISTORICAL: return "SOLAR_DATA_HISTORICAL";
            case FeatureToggle::SOLAR_DATA_VALIDATION: return "SOLAR_DATA_VALIDATION";
            case FeatureToggle::SOLAR_DATA_RETRY: return "SOLAR_DATA_RETRY";
            default: return "UNKNOWN_FEATURE";
        }
    }
    
    FeatureToggle stringToFeatureToggle(const std::string& str) {
        if (str == "THREADING_SOLAR_DATA") return FeatureToggle::THREADING_SOLAR_DATA;
        if (str == "THREADING_PROPAGATION") return FeatureToggle::THREADING_PROPAGATION;
        if (str == "THREADING_API_SERVER") return FeatureToggle::THREADING_API_SERVER;
        if (str == "THREADING_GPU_COMPUTE") return FeatureToggle::THREADING_GPU_COMPUTE;
        if (str == "THREADING_LIGHTNING_DATA") return FeatureToggle::THREADING_LIGHTNING_DATA;
        if (str == "THREADING_WEATHER_DATA") return FeatureToggle::THREADING_WEATHER_DATA;
        if (str == "THREADING_ANTENNA_PATTERN") return FeatureToggle::THREADING_ANTENNA_PATTERN;
        if (str == "THREADING_MONITORING") return FeatureToggle::THREADING_MONITORING;
        if (str == "GPU_ANTENNA_PATTERNS") return FeatureToggle::GPU_ANTENNA_PATTERNS;
        if (str == "GPU_PROPAGATION_CALCULATIONS") return FeatureToggle::GPU_PROPAGATION_CALCULATIONS;
        if (str == "GPU_AUDIO_PROCESSING") return FeatureToggle::GPU_AUDIO_PROCESSING;
        if (str == "GPU_FREQUENCY_OFFSET") return FeatureToggle::GPU_FREQUENCY_OFFSET;
        if (str == "GPU_FILTER_APPLICATION") return FeatureToggle::GPU_FILTER_APPLICATION;
        if (str == "GPU_BATCH_QSO_CALCULATION") return FeatureToggle::GPU_BATCH_QSO_CALCULATION;
        if (str == "GPU_SOLAR_DATA_PROCESSING") return FeatureToggle::GPU_SOLAR_DATA_PROCESSING;
        if (str == "GPU_LIGHTNING_DATA_PROCESSING") return FeatureToggle::GPU_LIGHTNING_DATA_PROCESSING;
        if (str == "SOLAR_DATA_FETCHING") return FeatureToggle::SOLAR_DATA_FETCHING;
        if (str == "SOLAR_DATA_CACHING") return FeatureToggle::SOLAR_DATA_CACHING;
        if (str == "SOLAR_DATA_HISTORICAL") return FeatureToggle::SOLAR_DATA_HISTORICAL;
        if (str == "SOLAR_DATA_VALIDATION") return FeatureToggle::SOLAR_DATA_VALIDATION;
        if (str == "SOLAR_DATA_RETRY") return FeatureToggle::SOLAR_DATA_RETRY;
        return static_cast<FeatureToggle>(-1);
    }
    
    std::string featureCategoryToString(FeatureCategory category) {
        switch (category) {
            case FeatureCategory::THREADING: return "Threading";
            case FeatureCategory::GPU_ACCELERATION: return "GPU Acceleration";
            case FeatureCategory::SOLAR_DATA: return "Solar Data";
            case FeatureCategory::PROPAGATION: return "Propagation";
            case FeatureCategory::ANTENNA_PATTERNS: return "Antenna Patterns";
            case FeatureCategory::AUDIO_PROCESSING: return "Audio Processing";
            case FeatureCategory::API_SERVER: return "API Server";
            case FeatureCategory::LIGHTNING_DATA: return "Lightning Data";
            case FeatureCategory::WEATHER_DATA: return "Weather Data";
            case FeatureCategory::POWER_MANAGEMENT: return "Power Management";
            case FeatureCategory::FREQUENCY_OFFSET: return "Frequency Offset";
            case FeatureCategory::BFO_SIMULATION: return "BFO Simulation";
            case FeatureCategory::FILTER_APPLICATION: return "Filter Application";
            case FeatureCategory::FUZZY_LOGIC: return "Fuzzy Logic";
            case FeatureCategory::VEHICLE_DYNAMICS: return "Vehicle Dynamics";
            case FeatureCategory::DEBUGGING: return "Debugging";
            case FeatureCategory::PERFORMANCE_MONITORING: return "Performance Monitoring";
            default: return "Unknown Category";
        }
    }
    
    FeatureCategory stringToFeatureCategory(const std::string& str) {
        if (str == "Threading") return FeatureCategory::THREADING;
        if (str == "GPU Acceleration") return FeatureCategory::GPU_ACCELERATION;
        if (str == "Solar Data") return FeatureCategory::SOLAR_DATA;
        if (str == "Propagation") return FeatureCategory::PROPAGATION;
        if (str == "Antenna Patterns") return FeatureCategory::ANTENNA_PATTERNS;
        if (str == "Audio Processing") return FeatureCategory::AUDIO_PROCESSING;
        if (str == "API Server") return FeatureCategory::API_SERVER;
        if (str == "Lightning Data") return FeatureCategory::LIGHTNING_DATA;
        if (str == "Weather Data") return FeatureCategory::WEATHER_DATA;
        if (str == "Power Management") return FeatureCategory::POWER_MANAGEMENT;
        if (str == "Frequency Offset") return FeatureCategory::FREQUENCY_OFFSET;
        if (str == "BFO Simulation") return FeatureCategory::BFO_SIMULATION;
        if (str == "Filter Application") return FeatureCategory::FILTER_APPLICATION;
        if (str == "Fuzzy Logic") return FeatureCategory::FUZZY_LOGIC;
        if (str == "Vehicle Dynamics") return FeatureCategory::VEHICLE_DYNAMICS;
        if (str == "Debugging") return FeatureCategory::DEBUGGING;
        if (str == "Performance Monitoring") return FeatureCategory::PERFORMANCE_MONITORING;
        return static_cast<FeatureCategory>(-1);
    }
    
    bool isValidImpactLevel(const std::string& impact_level) {
        return (impact_level == "low" || impact_level == "medium" || impact_level == "high");
    }
    
    std::vector<std::string> getValidImpactLevels() {
        return {"low", "medium", "high"};
    }
    
    std::vector<FeatureToggle> analyzeFeatureDependencies(FeatureToggle feature) {
        // This would analyze the dependency graph for a feature
        // For now, return empty vector
        return {};
    }
    
    std::vector<FeatureToggle> analyzeFeatureConflicts(FeatureToggle feature) {
        // This would analyze conflicts for a feature
        // For now, return empty vector
        return {};
    }
    
    double estimateFeaturePerformanceImpact(FeatureToggle feature) {
        // This would estimate the performance impact of a feature
        // For now, return 0.0
        return 0.0;
    }
    
    std::string estimateFeatureResourceUsage(FeatureToggle feature) {
        // This would estimate resource usage for a feature
        // For now, return "unknown"
        return "unknown";
    }
    
    bool validateFeatureConfig(const FeatureToggleConfig& config) {
        return FeatureToggleUtils::isValidImpactLevel(config.performance_impact) &&
               FeatureToggleUtils::isValidImpactLevel(config.memory_impact) &&
               FeatureToggleUtils::isValidImpactLevel(config.cpu_impact);
    }
    
    std::vector<std::string> getFeatureConfigErrors(const FeatureToggleConfig& config) {
        std::vector<std::string> errors;
        
        if (!FeatureToggleUtils::isValidImpactLevel(config.performance_impact)) {
            errors.push_back("Invalid performance impact level: " + config.performance_impact);
        }
        
        if (!FeatureToggleUtils::isValidImpactLevel(config.memory_impact)) {
            errors.push_back("Invalid memory impact level: " + config.memory_impact);
        }
        
        if (!FeatureToggleUtils::isValidImpactLevel(config.cpu_impact)) {
            errors.push_back("Invalid CPU impact level: " + config.cpu_impact);
        }
        
        return errors;
    }
}
