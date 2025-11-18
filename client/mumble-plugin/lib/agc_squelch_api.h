#ifndef FGCOM_AGC_SQUELCH_API_H
#define FGCOM_AGC_SQUELCH_API_H

#include "agc_squelch.h"
#include <string>
#include <map>
#include <functional>

// API endpoint definitions for AGC and Squelch
class FGCom_AGC_Squelch_API {
public:
    // AGC API endpoints
    static std::string getAGCStatus();
    static std::string setAGCMode(const std::string& mode);
    static std::string setAGCThreshold(float threshold_db);
    static std::string setAGCAttackTime(float attack_time_ms);
    static std::string setAGCReleaseTime(float release_time_ms);
    static std::string setAGCMaxGain(float max_gain_db);
    static std::string setAGCMinGain(float min_gain_db);
    static std::string enableAGC(bool enabled);
    static std::string setAGCPreset(const std::string& preset);
    
    // Squelch API endpoints
    static std::string getSquelchStatus();
    static std::string setSquelchEnabled(bool enabled);
    static std::string setSquelchThreshold(float threshold_db);
    static std::string setSquelchHysteresis(float hysteresis_db);
    static std::string setSquelchAttackTime(float attack_time_ms);
    static std::string setSquelchReleaseTime(float release_time_ms);
    static std::string setToneSquelch(bool enabled, float frequency_hz = 100.0f);
    static std::string setNoiseSquelch(bool enabled, float threshold_db = -70.0f);
    static std::string setSquelchPreset(const std::string& preset);
    
    // Combined API endpoints
    static std::string getCombinedStatus();
    static std::string setCombinedConfig(const std::string& json_config);
    static std::string resetToDefaults();
    
    // Audio processing API
    static std::string processAudio(const std::string& audio_data_base64, 
                                  float sample_rate_hz, size_t sample_count);
    static std::string getAudioStats();
    
    // Preset management
    static std::string getAvailablePresets();
    static std::string createCustomPreset(const std::string& name, 
                                        const std::string& agc_config, 
                                        const std::string& squelch_config);
    static std::string deleteCustomPreset(const std::string& name);
    static std::string loadPreset(const std::string& name);
    
    // Monitoring and diagnostics
    static std::string getDiagnostics();
    static std::string getPerformanceStats();
    static std::string startMonitoring();
    static std::string stopMonitoring();
    static std::string getMonitoringData();
    
    // Configuration management
    static std::string saveConfiguration(const std::string& config_name);
    static std::string loadConfiguration(const std::string& config_name);
    static std::string listConfigurations();
    static std::string deleteConfiguration(const std::string& config_name);
    
    // Export/Import
    static std::string exportConfiguration();
    static std::string importConfiguration(const std::string& config_data);
    
private:
    // Internal helper methods
    static std::string createJSONResponse(bool success, const std::string& message, 
                                        const std::string& data = "");
    static std::string createErrorResponse(const std::string& error_message);
    static std::string createSuccessResponse(const std::string& message, 
                                           const std::string& data = "");
    static bool validateAGCMode(const std::string& mode);
    static bool validateSquelchPreset(const std::string& preset);
    static bool validateThreshold(float threshold);
    static bool validateTime(float time_ms);
    static bool validateGain(float gain_db);
    static bool validateFrequency(float frequency_hz);
    
    // Configuration storage
    static std::map<std::string, std::string> custom_presets;
    static std::map<std::string, std::string> saved_configurations;
    static bool monitoring_active;
    static std::string monitoring_data;
};

// REST API endpoint definitions
namespace AGC_Squelch_Endpoints {
    // AGC endpoints
    const std::string GET_AGC_STATUS = "/api/agc/status";
    const std::string POST_AGC_MODE = "/api/agc/mode";
    const std::string POST_AGC_THRESHOLD = "/api/agc/threshold";
    const std::string POST_AGC_ATTACK_TIME = "/api/agc/attack-time";
    const std::string POST_AGC_RELEASE_TIME = "/api/agc/release-time";
    const std::string POST_AGC_MAX_GAIN = "/api/agc/max-gain";
    const std::string POST_AGC_MIN_GAIN = "/api/agc/min-gain";
    const std::string POST_AGC_ENABLE = "/api/agc/enable";
    const std::string POST_AGC_PRESET = "/api/agc/preset";
    
    // Squelch endpoints
    const std::string GET_SQUELCH_STATUS = "/api/squelch/status";
    const std::string POST_SQUELCH_ENABLE = "/api/squelch/enable";
    const std::string POST_SQUELCH_THRESHOLD = "/api/squelch/threshold";
    const std::string POST_SQUELCH_HYSTERESIS = "/api/squelch/hysteresis";
    const std::string POST_SQUELCH_ATTACK_TIME = "/api/squelch/attack-time";
    const std::string POST_SQUELCH_RELEASE_TIME = "/api/squelch/release-time";
    const std::string POST_SQUELCH_TONE = "/api/squelch/tone";
    const std::string POST_SQUELCH_NOISE = "/api/squelch/noise";
    const std::string POST_SQUELCH_PRESET = "/api/squelch/preset";
    
    // Combined endpoints
    const std::string GET_COMBINED_STATUS = "/api/agc-squelch/status";
    const std::string POST_COMBINED_CONFIG = "/api/agc-squelch/config";
    const std::string POST_RESET_DEFAULTS = "/api/agc-squelch/reset";
    
    // Audio processing endpoints
    const std::string POST_PROCESS_AUDIO = "/api/agc-squelch/process-audio";
    const std::string GET_AUDIO_STATS = "/api/agc-squelch/audio-stats";
    
    // Preset management endpoints
    const std::string GET_PRESETS = "/api/agc-squelch/presets";
    const std::string POST_CREATE_PRESET = "/api/agc-squelch/create-preset";
    const std::string DELETE_PRESET = "/api/agc-squelch/delete-preset";
    const std::string POST_LOAD_PRESET = "/api/agc-squelch/load-preset";
    
    // Monitoring endpoints
    const std::string GET_DIAGNOSTICS = "/api/agc-squelch/diagnostics";
    const std::string GET_PERFORMANCE_STATS = "/api/agc-squelch/performance";
    const std::string POST_START_MONITORING = "/api/agc-squelch/start-monitoring";
    const std::string POST_STOP_MONITORING = "/api/agc-squelch/stop-monitoring";
    const std::string GET_MONITORING_DATA = "/api/agc-squelch/monitoring-data";
    
    // Configuration management endpoints
    const std::string POST_SAVE_CONFIG = "/api/agc-squelch/save-config";
    const std::string POST_LOAD_CONFIG = "/api/agc-squelch/load-config";
    const std::string GET_LIST_CONFIGS = "/api/agc-squelch/list-configs";
    const std::string DELETE_CONFIG = "/api/agc-squelch/delete-config";
    
    // Export/Import endpoints
    const std::string GET_EXPORT_CONFIG = "/api/agc-squelch/export-config";
    const std::string POST_IMPORT_CONFIG = "/api/agc-squelch/import-config";
}

// API response structures
struct APIResponse {
    bool success;
    std::string message;
    std::string data;
    std::string timestamp;
    int error_code;
    
    APIResponse() : success(false), error_code(0) {
        timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    }
};

// API request structures
struct AGCRequest {
    std::string mode;
    float threshold_db;
    float attack_time_ms;
    float release_time_ms;
    float max_gain_db;
    float min_gain_db;
    bool enabled;
    std::string preset;
};

struct SquelchRequest {
    bool enabled;
    float threshold_db;
    float hysteresis_db;
    float attack_time_ms;
    float release_time_ms;
    bool tone_squelch;
    float tone_frequency_hz;
    bool noise_squelch;
    float noise_threshold_db;
    std::string preset;
};

struct CombinedRequest {
    AGCRequest agc;
    SquelchRequest squelch;
    std::string config_name;
    bool reset_to_defaults;
};

// API validation functions
namespace API_Validation {
    bool validateAGCMode(const std::string& mode);
    bool validateSquelchPreset(const std::string& preset);
    bool validateThreshold(float threshold);
    bool validateTime(float time_ms);
    bool validateGain(float gain_db);
    bool validateFrequency(float frequency_hz);
    bool validatePresetName(const std::string& name);
    bool validateConfigName(const std::string& name);
}

// API utility functions
namespace API_Utils {
    std::string encodeBase64(const std::string& data);
    std::string decodeBase64(const std::string& encoded_data);
    std::string createTimestamp();
    std::string formatFloat(float value, int precision = 2);
    std::string escapeJSON(const std::string& str);
    std::string unescapeJSON(const std::string& str);
}

#endif // FGCOM_AGC_SQUELCH_API_H
