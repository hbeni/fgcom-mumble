/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FGCOM_CONFIG_H
#define FGCOM_CONFIG_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include "lib/json/json.hpp"

// Configuration section definitions
struct AmateurRadioConfig {
    bool enabled = true;
    int itu_region = 1;  // 1, 2, or 3
    bool strict_band_compliance = true;
    float default_power = 100.0;  // Watts
    float antenna_height = 10.0;  // Meters
    bool enable_grid_locator = true;
    bool enable_mode_validation = true;
    bool enable_frequency_validation = true;
    std::string band_plan_file = "band_segments.csv";
    std::string custom_band_plan = "";
    bool enable_solar_effects = true;
    bool enable_propagation_modeling = true;
    bool enable_antenna_patterns = true;
    bool enable_ground_system_effects = true;
    
    // Advanced settings
    float min_signal_quality = 0.1;
    float max_propagation_distance = 10000.0;  // km
    bool enable_muf_luf_calculations = true;
    bool enable_skip_zone_modeling = true;
    bool enable_tropospheric_ducting = false;
    bool enable_sporadic_e = false;
    bool enable_aurora_propagation = false;
};

struct SolarDataConfig {
    bool enabled = true;
    std::string noaa_api_url = "https://services.swpc.noaa.gov/json/";
    int update_interval = 900;  // seconds (15 minutes)
    std::string fallback_data_path = "/usr/share/fgcom-mumble/solar_fallback.json";
    bool enable_background_updates = true;
    bool enable_offline_mode = true;
    bool enable_forecast_data = false;
    int forecast_hours = 24;
    bool enable_historical_data = true;
    int historical_days = 7;
    
    // API endpoints
    std::string sfi_endpoint = "f107cm.json";
    std::string k_index_endpoint = "k_index_1m.json";
    std::string a_index_endpoint = "a_index_1m.json";
    std::string ap_index_endpoint = "ap_index_1m.json";
    std::string solar_wind_endpoint = "solar_wind.json";
    std::string geomagnetic_endpoint = "geomagnetic_field.json";
    
    // Fallback values
    float fallback_sfi = 70.0;
    float fallback_k_index = 0.0;
    float fallback_a_index = 0.0;
};

struct PropagationConfig {
    bool enable_muf_luf = true;
    bool enable_solar_effects = true;
    bool enable_seasonal_variations = true;
    bool enable_day_night_effects = true;
    bool enable_geomagnetic_storm_effects = true;
    bool cache_propagation_results = true;
    int cache_size = 1000;
    int cache_ttl = 3600;  // seconds
    bool enable_gpu_acceleration = false;
    bool enable_parallel_processing = true;
    int max_threads = 4;
    
    // Propagation models
    bool enable_skywave_propagation = true;
    bool enable_groundwave_propagation = true;
    bool enable_line_of_sight = true;
    bool enable_tropospheric_scatter = false;
    bool enable_meteor_scatter = false;
    bool enable_moonbounce = false;
    
    // Advanced propagation
    bool enable_ray_tracing = false;
    bool enable_3d_propagation = false;
    bool enable_atmospheric_modeling = false;
    std::string atmospheric_model = "standard";
};

struct AntennaSystemConfig {
    bool enable_4nec2_patterns = true;
    bool enable_gpu_acceleration = false;
    int antenna_pattern_cache_size = 1000;
    std::string default_ground_type = "average";
    std::string pattern_directory = "/usr/share/fgcom-mumble/antenna_patterns/";
    std::string default_antenna_type = "vertical";
    float default_height = 10.0;
    float default_efficiency = 0.8;
    float default_swr = 1.5;
    float default_impedance = 50.0;
    
    // Ground system settings
    bool enable_ground_system_effects = true;
    bool enable_star_network_modeling = true;
    bool enable_copper_plate_modeling = true;
    bool enable_fuselage_modeling = true;
    bool enable_vehicle_ground_modeling = true;
    
    // Antenna types
    bool enable_dipole_antennas = true;
    bool enable_yagi_antennas = true;
    bool enable_vertical_antennas = true;
    bool enable_whip_antennas = true;
    bool enable_custom_antennas = true;
};

struct APIServerConfig {
    bool enabled = true;
    int port = 8080;
    std::string host = "0.0.0.0";
    bool enable_websocket = true;
    bool enable_cors = true;
    std::string cors_origin = "*";
    bool enable_rate_limiting = true;
    int rate_limit_requests_per_minute = 100;
    bool enable_api_key_auth = false;
    std::string api_key = "";
    bool enable_ssl = false;
    std::string ssl_cert_file = "";
    std::string ssl_key_file = "";
    
    // Logging
    bool enable_request_logging = true;
    bool enable_error_logging = true;
    std::string log_level = "info";  // debug, info, warn, error
    std::string log_file = "/var/log/fgcom-mumble/api.log";
    
    // Security
    bool enable_ip_whitelist = false;
    std::vector<std::string> allowed_ips;
    bool enable_https_redirect = false;
    int https_redirect_port = 443;
};

struct NonAmateurHFConfig {
    bool enable_aviation_hf = true;
    bool enable_maritime_hf = true;
    bool enable_mwara_frequencies = true;
    bool enable_uscg_channels = true;
    bool enable_emergency_frequencies = true;
    bool enable_volmet_broadcasts = true;
    
    // Aviation HF settings
    bool enable_aircraft_fuselage_modeling = true;
    bool enable_high_altitude_effects = true;
    bool enable_whip_antenna_modeling = true;
    bool enable_selcal_system = true;
    
    // Maritime HF settings
    bool enable_ship_hull_modeling = true;
    bool enable_sea_path_effects = true;
    bool enable_duplex_operation = true;
    bool enable_distress_frequencies = true;
    
    // Data sources
    std::string mwara_data_source = "builtin";
    std::string uscg_data_source = "builtin";
    bool enable_external_data_sources = false;
    std::string external_data_url = "";
    int external_data_update_interval = 3600;  // seconds
};

struct AudioConfig {
    bool enable_audio_processing = true;
    bool enable_noise_reduction = true;
    bool enable_audio_compression = true;
    bool enable_audio_effects = false;
    
    // Audio quality
    int sample_rate = 48000;
    int bit_depth = 16;
    int channels = 1;  // mono
    bool enable_stereo = false;
    
    // Audio effects
    bool enable_reverb = false;
    bool enable_echo = false;
    bool enable_distortion = false;
    bool enable_filtering = true;
    
    // Noise reduction
    bool enable_adaptive_noise_reduction = true;
    bool enable_spectral_subtraction = true;
    float noise_reduction_level = 0.5;  // 0.0 to 1.0
};

struct LoggingConfig {
    bool enable_file_logging = true;
    bool enable_console_logging = true;
    std::string log_level = "info";
    std::string log_file = "/var/log/fgcom-mumble/fgcom-mumble.log";
    int max_log_file_size = 10485760;  // 10MB
    int max_log_files = 5;
    bool enable_rotation = true;
    
    // Component-specific logging
    bool enable_udp_logging = true;
    bool enable_propagation_logging = true;
    bool enable_solar_logging = true;
    bool enable_antenna_logging = true;
    bool enable_api_logging = true;
    bool enable_debug_logging = false;
};

struct PerformanceConfig {
    bool enable_multithreading = true;
    int max_threads = 4;
    bool enable_thread_pool = true;
    int thread_pool_size = 8;
    bool enable_memory_pool = true;
    int memory_pool_size = 1000000;  // 1MB
    
    // Caching
    bool enable_propagation_cache = true;
    int propagation_cache_size = 1000;
    int propagation_cache_ttl = 3600;
    bool enable_antenna_cache = true;
    int antenna_cache_size = 100;
    int antenna_cache_ttl = 7200;
    bool enable_solar_cache = true;
    int solar_cache_ttl = 900;
    
    // GPU acceleration
    bool enable_gpu_acceleration = false;
    bool enable_cuda = false;
    bool enable_opencl = false;
    int gpu_memory_limit = 512;  // MB
    bool enable_gpu_propagation = false;
    bool enable_gpu_antenna_patterns = false;
};

// Main configuration class
class FGCom_Config {
private:
    static std::unique_ptr<FGCom_Config> instance;
    static std::mutex instance_mutex;
    
    std::string config_file_path;
    std::map<std::string, std::string> config_values;
    std::map<std::string, bool> feature_flags;
    std::mutex config_mutex;
    bool config_loaded;
    
    // Configuration sections
    AmateurRadioConfig amateur_radio_config;
    SolarDataConfig solar_data_config;
    PropagationConfig propagation_config;
    AntennaSystemConfig antenna_system_config;
    APIServerConfig api_server_config;
    NonAmateurHFConfig non_amateur_hf_config;
    AudioConfig audio_config;
    LoggingConfig logging_config;
    PerformanceConfig performance_config;
    
    // Configuration change callbacks
    std::map<std::string, std::function<void()>> config_change_callbacks;
    
public:
    // Singleton pattern
    static FGCom_Config& getInstance();
    static void destroyInstance();
    
    // Configuration management
    bool loadConfig(const std::string& config_file = "fgcom-mumble.conf");
    bool saveConfig(const std::string& config_file = "");
    bool reloadConfig();
    void setDefaultConfig();
    
    // Generic configuration access
    std::string getConfigValue(const std::string& key, const std::string& default_value = "") const;
    void setConfigValue(const std::string& key, const std::string& value);
    bool getConfigBool(const std::string& key, bool default_value = false) const;
    void setConfigBool(const std::string& key, bool value);
    int getConfigInt(const std::string& key, int default_value = 0) const;
    void setConfigInt(const std::string& key, int value);
    float getConfigFloat(const std::string& key, float default_value = 0.0f) const;
    void setConfigFloat(const std::string& key, float value);
    
    // Feature flags
    bool isFeatureEnabled(const std::string& feature) const;
    void setFeatureFlag(const std::string& feature, bool enabled);
    std::map<std::string, bool> getAllFeatureFlags() const;
    
    // Configuration sections
    const AmateurRadioConfig& getAmateurRadioConfig() const { return amateur_radio_config; }
    void setAmateurRadioConfig(const AmateurRadioConfig& config);
    
    const SolarDataConfig& getSolarDataConfig() const { return solar_data_config; }
    void setSolarDataConfig(const SolarDataConfig& config);
    
    const PropagationConfig& getPropagationConfig() const { return propagation_config; }
    void setPropagationConfig(const PropagationConfig& config);
    
    const AntennaSystemConfig& getAntennaSystemConfig() const { return antenna_system_config; }
    void setAntennaSystemConfig(const AntennaSystemConfig& config);
    
    const APIServerConfig& getAPIServerConfig() const { return api_server_config; }
    void setAPIServerConfig(const APIServerConfig& config);
    
    const NonAmateurHFConfig& getNonAmateurHFConfig() const { return non_amateur_hf_config; }
    void setNonAmateurHFConfig(const NonAmateurHFConfig& config);
    
    const AudioConfig& getAudioConfig() const { return audio_config; }
    void setAudioConfig(const AudioConfig& config);
    
    const LoggingConfig& getLoggingConfig() const { return logging_config; }
    void setLoggingConfig(const LoggingConfig& config);
    
    const PerformanceConfig& getPerformanceConfig() const { return performance_config; }
    void setPerformanceConfig(const PerformanceConfig& config);
    
    // Band plan management
    bool loadBandPlan(const std::string& band_plan_file);
    bool saveBandPlan(const std::string& band_plan_file);
    bool loadCustomBandPlan(const std::string& custom_plan);
    std::string getBandPlanFile() const;
    void setBandPlanFile(const std::string& file);
    
    // Configuration validation
    bool validateConfig() const;
    std::vector<std::string> getConfigErrors() const;
    std::vector<std::string> getConfigWarnings() const;
    
    // Configuration change callbacks
    void registerConfigChangeCallback(const std::string& key, std::function<void()> callback);
    void unregisterConfigChangeCallback(const std::string& key);
    
    // Utility functions
    std::string getConfigFilePath() const { return config_file_path; }
    void setConfigFilePath(const std::string& path) { config_file_path = path; }
    bool isConfigLoaded() const { return config_loaded; }
    
    // JSON export/import
    nlohmann::json toJSON() const;
    bool fromJSON(const nlohmann::json& json);
    bool exportToJSON(const std::string& file) const;
    bool importFromJSON(const std::string& file);
    
    // Configuration templates
    void createDefaultConfigFile(const std::string& file) const;
    void createExampleConfigFile(const std::string& file) const;
    void createMinimalConfigFile(const std::string& file) const;
    
private:
    FGCom_Config();
    ~FGCom_Config();
    
    // Internal helper functions
    void parseConfigFile(const std::string& file);
    void parseConfigSection(const std::string& section, const std::string& content);
    void updateConfigSections();
    void notifyConfigChange(const std::string& key);
    std::string trimString(const std::string& str) const;
    std::vector<std::string> splitString(const std::string& str, char delimiter) const;
    bool parseBoolean(const std::string& value) const;
    int parseInteger(const std::string& value) const;
    float parseFloat(const std::string& value) const;
    
    // Configuration section parsers
    void parseAmateurRadioConfig(const std::map<std::string, std::string>& values);
    void parseSolarDataConfig(const std::map<std::string, std::string>& values);
    void parsePropagationConfig(const std::map<std::string, std::string>& values);
    void parseAntennaSystemConfig(const std::map<std::string, std::string>& values);
    void parseAPIServerConfig(const std::map<std::string, std::string>& values);
    void parseNonAmateurHFConfig(const std::map<std::string, std::string>& values);
    void parseAudioConfig(const std::map<std::string, std::string>& values);
    void parseLoggingConfig(const std::map<std::string, std::string>& values);
    void parsePerformanceConfig(const std::map<std::string, std::string>& values);
    
    // Configuration section serializers
    std::map<std::string, std::string> serializeAmateurRadioConfig() const;
    std::map<std::string, std::string> serializeSolarDataConfig() const;
    std::map<std::string, std::string> serializePropagationConfig() const;
    std::map<std::string, std::string> serializeAntennaSystemConfig() const;
    std::map<std::string, std::string> serializeAPIServerConfig() const;
    std::map<std::string, std::string> serializeNonAmateurHFConfig() const;
    std::map<std::string, std::string> serializeAudioConfig() const;
    std::map<std::string, std::string> serializeLoggingConfig() const;
    std::map<std::string, std::string> serializePerformanceConfig() const;
};

// Configuration file generator
class FGCom_ConfigGenerator {
public:
    static void generateDefaultConfig(const std::string& output_file);
    static void generateExampleConfig(const std::string& output_file);
    static void generateMinimalConfig(const std::string& output_file);
    static void generateDevelopmentConfig(const std::string& output_file);
    static void generateProductionConfig(const std::string& output_file);
    static void generateTestingConfig(const std::string& output_file);
    
private:
    static std::string generateConfigHeader();
    static std::string generateConfigFooter();
    static std::string generateAmateurRadioSection();
    static std::string generateSolarDataSection();
    static std::string generatePropagationSection();
    static std::string generateAntennaSystemSection();
    static std::string generateAPIServerSection();
    static std::string generateNonAmateurHFSection();
    static std::string generateAudioSection();
    static std::string generateLoggingSection();
    static std::string generatePerformanceSection();
};

#endif // FGCOM_CONFIG_H
