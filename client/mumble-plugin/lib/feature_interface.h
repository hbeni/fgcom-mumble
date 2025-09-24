#ifndef FGCOM_FEATURE_INTERFACE_H
#define FGCOM_FEATURE_INTERFACE_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

// Forward declarations
enum class FeatureToggle;
enum class FeatureCategory;

// Abstract interface for feature toggle management
class IFeatureToggleManager {
public:
    virtual ~IFeatureToggleManager() = default;
    
    // Feature control
    virtual bool isFeatureEnabled(FeatureToggle feature) const = 0;
    virtual bool enableFeature(FeatureToggle feature) = 0;
    virtual bool disableFeature(FeatureToggle feature) = 0;
    virtual bool toggleFeature(FeatureToggle feature) = 0;
    
    // Bulk operations
    virtual void enableAllFeatures() = 0;
    virtual void disableAllFeatures() = 0;
    virtual void enableCategory(FeatureCategory category) = 0;
    virtual void disableCategory(FeatureCategory category) = 0;
    virtual void enableFeaturesByImpact(const std::string& impact_level) = 0;
    
    // Configuration management
    virtual bool loadConfigFromFile(const std::string& config_file) = 0;
    virtual bool saveConfigToFile(const std::string& config_file) const = 0;
    virtual bool loadConfigFromString(const std::string& config_string) = 0;
    virtual std::string saveConfigToString() const = 0;
    
    // Dependency management
    virtual bool checkDependencies(FeatureToggle feature) const = 0;
    virtual bool checkConflicts(FeatureToggle feature) const = 0;
    virtual std::vector<FeatureToggle> getDependentFeatures(FeatureToggle feature) const = 0;
    virtual std::vector<FeatureToggle> getConflictingFeatures(FeatureToggle feature) const = 0;
    
    // Performance monitoring
    virtual void recordFeatureUsage(FeatureToggle feature, double performance_impact_ms = 0.0) = 0;
    virtual uint64_t getFeatureUsageCount(FeatureToggle feature) const = 0;
    virtual double getFeaturePerformanceImpact(FeatureToggle feature) const = 0;
    virtual std::map<FeatureToggle, uint64_t> getAllFeatureUsageCounts() const = 0;
    virtual std::map<FeatureToggle, double> getAllFeaturePerformanceImpacts() const = 0;
    
    // Information and reporting
    virtual std::vector<FeatureToggle> getEnabledFeatures() const = 0;
    virtual std::vector<FeatureToggle> getDisabledFeatures() const = 0;
    virtual std::vector<FeatureToggle> getFeaturesByCategory(FeatureCategory category) const = 0;
    virtual std::vector<FeatureToggle> getFeaturesByImpact(const std::string& impact_level) const = 0;
    
    // Validation and diagnostics
    virtual bool validateConfiguration() const = 0;
    virtual std::vector<std::string> getConfigurationErrors() const = 0;
    virtual std::vector<std::string> getConfigurationWarnings() const = 0;
    virtual void generateFeatureReport() const = 0;
    
    // Runtime control
    virtual bool canToggleFeature(FeatureToggle feature) const = 0;
    virtual bool requiresRestart(FeatureToggle feature) const = 0;
    virtual std::vector<FeatureToggle> getFeaturesRequiringRestart() const = 0;
    
    // Debugging and diagnostics
    virtual void enableDebugMode(bool enable) = 0;
    virtual bool isDebugModeEnabled() const = 0;
    virtual void logFeatureToggle(FeatureToggle feature, bool enabled, const std::string& reason = "") = 0;
    virtual std::vector<std::string> getFeatureToggleHistory() const = 0;
};

// Abstract interface for feature configuration
class IFeatureConfig {
public:
    virtual ~IFeatureConfig() = default;
    
    virtual void setFeatureConfig(FeatureToggle feature, const std::string& config) = 0;
    virtual std::string getFeatureConfig(FeatureToggle feature) const = 0;
    virtual void initializeDefaultConfigs() = 0;
    
    virtual bool loadConfigFromFile(const std::string& config_file) = 0;
    virtual bool saveConfigToFile(const std::string& config_file) const = 0;
    virtual bool validateConfiguration() const = 0;
    virtual std::vector<std::string> getConfigurationErrors() const = 0;
};

// Abstract interface for feature validation
class IFeatureValidator {
public:
    virtual ~IFeatureValidator() = default;
    
    virtual bool validateFeatureToggle(FeatureToggle feature, bool enabled) const = 0;
    virtual bool validateFeatureConfig(const std::string& config) const = 0;
    virtual std::vector<std::string> getValidationErrors(FeatureToggle feature) const = 0;
    virtual std::vector<std::string> getValidationWarnings(FeatureToggle feature) const = 0;
};

// Factory interface for creating feature components
class IFeatureComponentFactory {
public:
    virtual ~IFeatureComponentFactory() = default;
    
    virtual std::unique_ptr<IFeatureToggleManager> createFeatureToggleManager() = 0;
    virtual std::unique_ptr<IFeatureConfig> createFeatureConfig() = 0;
    virtual std::unique_ptr<IFeatureValidator> createFeatureValidator() = 0;
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
    bool validateFeatureConfig(const std::string& config);
    std::vector<std::string> getFeatureConfigErrors(const std::string& config);
}

#endif // FGCOM_FEATURE_INTERFACE_H



